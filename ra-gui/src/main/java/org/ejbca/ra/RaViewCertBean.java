/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ra.RaCertificateDetails.Callbacks;

/**
 * Backing bean for certificate details view.
 *
 * @version $Id: RaViewCertBean.java 26138 2017-07-06 14:39:48Z henriks $ TODO:
 *     Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaViewCertBean implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

  /** Param. */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;

  /**
   * @param araAuthenticationBean bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }

  /** Param. */
  @ManagedProperty(value = "#{raLocaleBean}")
  private RaLocaleBean raLocaleBean;

  /**
   * @param araLocaleBean Bean
   */
  public void setRaLocaleBean(final RaLocaleBean araLocaleBean) {
    this.raLocaleBean = araLocaleBean;
  }

  /** Param. */
  private String fingerprint = null;
  /** Param. */
  private RaCertificateDetails raCertificateDetails = null;
  /** Param. */
  private Map<Integer, String> eepIdToNameMap = null;
  /** Param. */
  private Map<Integer, String> cpIdToNameMap = null;
  /** Param. */
  private final Map<String, String> caSubjectToNameMap = new HashMap<>();

  /**
   * Callbacks.
   */
  private final Callbacks raCertificateDetailsCallbacks =
      new RaCertificateDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
          return raLocaleBean;
        }

        @Override
        public UIComponent getConfirmPasswordComponent() {
          return null;
        }

        @Override
        public boolean changeStatus(
            final RaCertificateDetails araCertificateDetails,
            final int newStatus,
            final int newRevocationReason)
            throws ApprovalException, WaitingForApprovalException {
          final boolean ret =
              raMasterApiProxyBean.changeCertificateStatus(
                  raAuthenticationBean.getAuthenticationToken(),
                  araCertificateDetails.getFingerprint(),
                  newStatus,
                  newRevocationReason);
          if (ret) {
            // Re-initialize object if status has changed
            final CertificateDataWrapper cdw =
                raMasterApiProxyBean.searchForCertificate(
                    raAuthenticationBean.getAuthenticationToken(),
                    araCertificateDetails.getFingerprint());
            araCertificateDetails.reInitialize(
                cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
          }
          return ret;
        }

        @Override
        public boolean recoverKey(
            final RaCertificateDetails araCertificateDetails)
            throws ApprovalException, CADoesntExistsException,
                AuthorizationDeniedException, WaitingForApprovalException,
                NoSuchEndEntityException, EndEntityProfileValidationException {
          final boolean ret =
              raMasterApiProxyBean.markForRecovery(
                  raAuthenticationBean.getAuthenticationToken(),
                  araCertificateDetails.getUsername(),
                  araCertificateDetails.getPassword(),
                  EJBTools.wrap(araCertificateDetails.getCertificate()),
                  false);
          return ret;
        }

        @Override
        public boolean keyRecoveryPossible(
            final RaCertificateDetails araCertificateDetails) {
          final boolean ret =
              raMasterApiProxyBean.keyRecoveryPossible(
                  raAuthenticationBean.getAuthenticationToken(),
                  araCertificateDetails.getCertificate(),
                  araCertificateDetails.getUsername());
          return ret;
        }
      };

      /**
       * Construct.
       */
  @PostConstruct
  public void postConstruct() {
    fingerprint =
        ((HttpServletRequest)
                FacesContext.getCurrentInstance()
                    .getExternalContext()
                    .getRequest())
            .getParameter("fp");
    if (fingerprint != null) {
      final CertificateDataWrapper cdw =
          raMasterApiProxyBean.searchForCertificate(
              raAuthenticationBean.getAuthenticationToken(), fingerprint);
      if (cdw != null) {
        cpIdToNameMap =
            raMasterApiProxyBean.getAuthorizedCertificateProfileIdsToNameMap(
                raAuthenticationBean.getAuthenticationToken());
        eepIdToNameMap =
            raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(
                raAuthenticationBean.getAuthenticationToken());
        final List<CAInfo> caInfos =
            new ArrayList<>(
                raMasterApiProxyBean.getAuthorizedCas(
                    raAuthenticationBean.getAuthenticationToken()));
        for (final CAInfo caInfo : caInfos) {
          caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
        }
        raCertificateDetails =
            new RaCertificateDetails(
                cdw,
                raCertificateDetailsCallbacks,
                cpIdToNameMap,
                eepIdToNameMap,
                caSubjectToNameMap);
      }
    }
  }

  /**
   * @return FP
   */
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @return Cert
   */
  public RaCertificateDetails getCertificate() {
    return raCertificateDetails;
  }
}
