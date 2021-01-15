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

package org.ejbca.ui.web.admin.cainterface;

import javax.servlet.http.HttpServletRequest;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * Contains help methods used to parse a viewcainfo jsp page requests.
 *
 * @author Philip Vendil
 * @version $Id: ViewCAInfoJSPHelper.java 25830 2017-05-10 13:36:45Z mikekushner
 *     $
 */
public class ViewCAInfoJSPHelper implements java.io.Serializable {

  private static final long serialVersionUID = 109073226626366410L;

  /** POarem. */
  public static final String CA_PARAMETER = "caid";

  /** POarem. */
  public static final String CERTSERNO_PARAMETER = "certsernoparameter";

  /** POarem. */
  public static final String PASSWORD_AUTHENTICATIONCODE =
      "passwordactivationcode";

  /** POarem. */
  public static final String CHECKBOX_VALUE = BasePublisher.TRUE;

  /** POarem. */
  public static final String BUTTON_ACTIVATE = "buttonactivate";
  /** POarem. */
  public static final String BUTTON_MAKEOFFLINE = "buttonmakeoffline";
  /** POarem. */
  public static final String BUTTON_CLOSE = "buttonclose";
  /** POarem. */
  public static final String CHECKBOX_INCLUDEINHEALTHCHECK =
      "includeinhealthcheck";
  /** POarem. */
  public static final String SUBMITHS = "submiths";

  /** POarem. */
  private CAInterfaceBean cabean;
  /** POarem. */
  private boolean initialized = false;
  /** POarem. */
  private String generalerrormessage = null;
  /** POarem. */
  private String activationerrormessage = null;
  /** POarem. */
  private String activationerrorreason = null;
  /** POarem. */
  private String activationmessage = null;
  /** POarem. */
  private CAInfoView cainfo = null;
  /** POarem. */
  private int status = 0;
  /** POarem. */
  private boolean tokenoffline = false;
  /** POarem. */
  private int caid = 0;

  /** Creates new LogInterfaceBean. */
  public ViewCAInfoJSPHelper() { }

  /**
   * Method that initialized the bean.
   *
   * @param request is a reference to the http request.
   * @param ejbcawebbean bean
   * @param acabean bean
   */
  public void initialize(
      final HttpServletRequest request,
      final EjbcaWebBean ejbcawebbean,
      final CAInterfaceBean acabean) {
    if (!initialized) {
      this.cabean = acabean;
      initialized = true;
    }
  }

  /**
   * Method that parses the request and take appropriate actions.
   *
   * @param request the http request
   * @throws Exception fail
   */
  public void parseRequest(final HttpServletRequest request) throws Exception {
    generalerrormessage = null;
    activationerrormessage = null;
    activationmessage = null;
    RequestHelper.setDefaultCharacterEncoding(request);
    if (request.getParameter(CA_PARAMETER) != null) {
      caid = Integer.parseInt(request.getParameter(CA_PARAMETER));
      // Get currentstate
      status = CAConstants.CA_OFFLINE;
      try {
        cainfo = cabean.getCAInfo(caid);
        if (cainfo == null) {
          generalerrormessage = "CADOESNTEXIST";
        } else {
          status = cainfo.getCAInfo().getStatus();
        }
      } catch (AuthorizationDeniedException e) {
        generalerrormessage = "NOTAUTHORIZEDTOVIEWCA";
        return;
      }
    } else {
      generalerrormessage = "YOUMUSTSPECIFYCAID";
    }
  }

/**
 * @return the generalerrormessage
 */
public String getGeneralerrormessage() {
    return generalerrormessage;
}

/**
 * @param ageneralerrormessage the generalerrormessage to set
 */
public void setGeneralerrormessage(final String ageneralerrormessage) {
    this.generalerrormessage = ageneralerrormessage;
}

/**
 * @return the activationerrormessage
 */
public String getActivationerrormessage() {
    return activationerrormessage;
}

/**
 * @param anactivationerrormessage the activationerrormessage to set
 */
public void setActivationerrormessage(final String anactivationerrormessage) {
    this.activationerrormessage = anactivationerrormessage;
}

/**
 * @return the activationerrorreason
 */
public String getActivationerrorreason() {
    return activationerrorreason;
}

/**
 * @param anactivationerrorreason the activationerrorreason to set
 */
public void setActivationerrorreason(final String anactivationerrorreason) {
    this.activationerrorreason = anactivationerrorreason;
}

/**
 * @return the activationmessage
 */
public String getActivationmessage() {
    return activationmessage;
}

/**
 * @param anactivationmessage the activationmessage to set
 */
public void setActivationmessage(final String anactivationmessage) {
    this.activationmessage = anactivationmessage;
}

/**
 * @return the cainfo
 */
public CAInfoView getCainfo() {
    return cainfo;
}

/**
 * @param acainfo the cainfo to set
 */
public void setCainfo(final CAInfoView acainfo) {
    this.cainfo = acainfo;
}

/**
 * @return the status
 */
public int getStatus() {
    return status;
}

/**
 * @param astatus the status to set
 */
public void setStatus(final int astatus) {
    this.status = astatus;
}

/**
 * @return the tokenoffline
 */
public boolean isTokenoffline() {
    return tokenoffline;
}

/**
 * @param atokenoffline the tokenoffline to set
 */
public void setTokenoffline(final boolean atokenoffline) {
    this.tokenoffline = atokenoffline;
}

/**
 * @return the caid
 */
public int getCaid() {
    return caid;
}

/**
 * @param acaid the caid to set
 */
public void setCaid(final int acaid) {
    this.caid = acaid;
}
}
