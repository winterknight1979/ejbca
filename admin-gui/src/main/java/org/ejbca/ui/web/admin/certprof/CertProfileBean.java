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
package org.ejbca.ui.web.admin.certprof;

import java.io.IOException;
import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.DataModelEvent;
import javax.faces.model.DataModelListener;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.cvc.AccessRightAuthTerm;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * JSF MBean backing the certificate profile pages.
 *
 * @version $Id: CertProfileBean.java 29667 2018-08-16 12:20:15Z anatom $
 */
// Declarations in faces-config.xml
// @javax.faces.bean.SessionScoped
// @javax.faces.bean.ManagedBean(name="certProfileBean")
public class CertProfileBean extends BaseManagedBean implements Serializable {
  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(CertProfileBean.class);
  /** Param. */
  private final int msPerS = 1000;
  // Declarations in faces-config.xml
  // @javax.faces.bean.ManagedProperty(value="#{certProfilesBean}")
  /** Param. */
  private CertProfilesBean certProfilesBean;

  /** Param. */
  private int currentCertProfileId = -1;
  /** Param. */
  private CertificateProfile certificateProfile = null;
  /** Param. */
  private ListDataModel<CertificatePolicy> certificatePoliciesModel = null;
  /** Param. */
  private CertificatePolicy newCertificatePolicy = null;
  /** Param. */
  private ListDataModel<String> caIssuersModel = null;
  /** Param. */
  private String newCaIssuer = "";
  /** Param. */
  private ListDataModel<String> documentTypeList = null;
  /** Param. */
  private String documentTypeListNew = "";
  /** Param. */
  private ListDataModel<PKIDisclosureStatement> pdsListModel = null;
  /** Param. */
  private List<ApprovalRequestItem> approvalRequestItems = null;

  /**
   * Since this MBean is session scoped we need to reset all the values when
   * needed.
   */
  private void reset() {
    currentCertProfileId = -1;
    certificateProfile = null;
    certificatePoliciesModel = null;
    newCertificatePolicy = null;
    caIssuersModel = null;
    newCaIssuer = "";
    documentTypeList = null;
    documentTypeListNew = "";
    pdsListModel = null;
    approvalRequestItems = null;
  }

  /**
   * @return Bean
   */
  public CertProfilesBean getCertProfilesBean() {
    return certProfilesBean;
  }

  /**
   * @param acertProfilesBean bean
   */
  public void setCertProfilesBean(final CertProfilesBean acertProfilesBean) {
    this.certProfilesBean = acertProfilesBean;
  }

  /**
   * @return ID
   */
  public Integer getSelectedCertProfileId() {
    return certProfilesBean.getSelectedCertProfileId();
  }

  /**
   * @return Name
   */
  public String getSelectedCertProfileName() {
    return getEjbcaWebBean()
        .getEjb()
        .getCertificateProfileSession()
        .getCertificateProfileName(getSelectedCertProfileId());
  }

  /**
   * @return Profile
   */
  public CertificateProfile getCertificateProfile() {
    if (currentCertProfileId != -1
        && certificateProfile != null
        && getSelectedCertProfileId().intValue() != currentCertProfileId) {
      reset();
    }
    if (certificateProfile == null) {
      currentCertProfileId = getSelectedCertProfileId().intValue();
      final CertificateProfile acertificateProfile =
          getEjbcaWebBean()
              .getEjb()
              .getCertificateProfileSession()
              .getCertificateProfile(currentCertProfileId);
      try {
        this.certificateProfile = acertificateProfile.clone();
        // Add some defaults
        final GlobalConfiguration globalConfiguration =
            getEjbcaWebBean().getGlobalConfiguration();
        if (this.certificateProfile.getCRLDistributionPointURI().length()
            == 0) {
          this.certificateProfile.setCRLDistributionPointURI(
              globalConfiguration.getStandardCRLDistributionPointURI());
          this.certificateProfile.setCRLIssuer(
              globalConfiguration.getStandardCRLIssuer());
        }
        if (this.certificateProfile.getFreshestCRLURI().length() == 0) {
          this.certificateProfile.setFreshestCRLURI(
              globalConfiguration.getStandardDeltaCRLDistributionPointURI());
        }
      } catch (CloneNotSupportedException e) {
        LOG.error(
            "Certificate Profiles should be clonable, but this one was not!",
            e);
      }
    }
    return certificateProfile;
  }

  /**
   * @return success
   */
  public String cancel() {
    reset();
    return "done"; // Outcome defined in faces-config.xml
  }

  /**
   * @return success
   */
  public String save() {
    boolean success = true;
    try {
      // Perform last minute validations before saving
      CertificateProfile prof = getCertificateProfile();
      if (prof.getAvailableKeyAlgorithmsAsList().isEmpty()) {
        addErrorMessage("ONEAVAILABLEKEYALGORITHM");
        success = false;
      }
      if (prof.getAvailableBitLengthsAsList().isEmpty()) {
        addErrorMessage("ONEAVAILABLEBITLENGTH");
        success = false;
      }
      if (isCtEnabled()) {
        final int numEnabledLabels = prof.getEnabledCtLabels().size();
        final boolean isNumOfSctsCustom = prof.isNumberOfSctByCustom();
        final boolean isMaxNumOfSctsCustom = prof.isMaxNumberOfSctByCustom();
        if (numEnabledLabels == 0) {
          addErrorMessage("NOCTLABELSSELECTED");
          success = false;
        } else if (((prof.getCtMinScts() < 0
                    && prof.isUseCertificateTransparencyInCerts())
                || (prof.getCtMinSctsOcsp() < 0
                    && prof.isUseCertificateTransparencyInOCSP()))
            && isNumOfSctsCustom) {
          addErrorMessage("INCORRECTMINSCTS");
          success = false;
        } else if ((prof.getCtMaxScts() < 0
                && prof.isUseCertificateTransparencyInCerts())
            || (prof.getCtMaxSctsOcsp() < 0
                && prof.isUseCertificateTransparencyInOCSP())) {
          addErrorMessage("INCORRECTMAXSCTS");
          success = false;

        } else if (((prof.getCtMaxScts() < prof.getCtMinScts()
                    && prof.isUseCertificateTransparencyInCerts())
                || (prof.getCtMaxSctsOcsp() < prof.getCtMinSctsOcsp()
                    && prof.isUseCertificateTransparencyInOCSP()))
            && (isNumOfSctsCustom && isMaxNumOfSctsCustom)) {
          addErrorMessage("INCORRECTMAXLESSTHANMIN");
          success = false;
        } else if (((prof.getCtMinScts() < numEnabledLabels
                    && prof.getCtMinScts() != 0
                    && prof.isUseCertificateTransparencyInCerts())
                || (prof.getCtMinSctsOcsp() < numEnabledLabels
                    && prof.getCtMinSctsOcsp() != 0
                    && prof.isUseCertificateTransparencyInOCSP()))
            && isNumOfSctsCustom) {
          addErrorMessage("INCORRECTNUMBEROFLABELS");
          success = false;
        } else if (((prof.getCtMaxScts() < numEnabledLabels
                    && prof.isUseCertificateTransparencyInCerts())
                || (prof.getCtMaxSctsOcsp() < numEnabledLabels
                    && prof.isUseCertificateTransparencyInOCSP()))
            && isMaxNumOfSctsCustom) {
          addErrorMessage("INCORRECTNUMBEROFLABELSMAX");
          success = false;
        }
      }
      if (prof.getUseExpirationRestrictionForWeekdays()) {
        boolean allDaysExcluded = true;
        for (boolean enabled : prof.getExpirationRestrictionWeekdays()) {
          if (!enabled) {
            allDaysExcluded = false;
            break;
          }
        }
        if (allDaysExcluded) {
          addErrorMessage(
              "CERT_EXPIRATION_RESTRICTION_FOR_WEEKDAYS_ALL_EXCLUDED");
          success = false;
        }
      }
      if (prof.getUseQCStatement()) {
        boolean[] statements = {
          prof.getUsePkixQCSyntaxV2(),
          prof.getUseQCEtsiQCCompliance(),
          prof.getUseQCEtsiSignatureDevice(),
          prof.getUseQCEtsiValueLimit(),
          prof.getUseQCEtsiRetentionPeriod(),
          !StringUtils.isEmpty(prof.getQCEtsiType()),
          prof.getQCEtsiPds() != null
              && prof.getQCEtsiPds().size() > 0
              && !(prof.getQCEtsiPds().size() == 1
                  && prof.getQCEtsiPds().get(0).getUrl() == null),
          prof.getUseQCCustomString()
              && !prof.getQCCustomStringOid().isEmpty()
              && !prof.getQCCustomStringText().isEmpty()
        };
        // Check that at least one QC statement is used
        boolean foundUsed = false;
        for (boolean statement : statements) {
          if (statement) {
            foundUsed = true;
          }
        }
        if (!foundUsed) {
          addErrorMessage("ONEQCSTATEMENTUSED");
          success = false;
        }
      }
      if (success) {
        // Remove the added defaults if they were never used
        final CertificateProfile acertificateProfile = getCertificateProfile();
        if (!acertificateProfile.getUseCRLDistributionPoint()
            || acertificateProfile.getUseDefaultCRLDistributionPoint()) {
          acertificateProfile.setCRLDistributionPointURI("");
          acertificateProfile.setCRLIssuer("");
        }
        if (!acertificateProfile.getUseFreshestCRL()
            || acertificateProfile.getUseCADefinedFreshestCRL()) {
          acertificateProfile.setFreshestCRLURI("");
        }

        applyExpirationRestrictionForValidityWithFixedDate(acertificateProfile);

        final List<PKIDisclosureStatement> pdsList =
            acertificateProfile.getQCEtsiPds();
        if (pdsList != null) {
          final List<PKIDisclosureStatement> pdsCleaned = new ArrayList<>();
          for (final PKIDisclosureStatement pds : pdsList) {
            if (!StringUtils.isEmpty(pds.getUrl())) {
              pdsCleaned.add(pds);
            }
          }
          acertificateProfile.setQCEtsiPds(pdsCleaned);
        }
        Map<ApprovalRequestType, Integer> approvals = new HashMap<>();
        for (ApprovalRequestItem approvalRequestItem : approvalRequestItems) {
          approvals.put(
              approvalRequestItem.getRequestType(),
              approvalRequestItem.getApprovalProfileId());
        }
        acertificateProfile.setApprovals(approvals);

        // Modify the profile
        getEjbcaWebBean()
            .getEjb()
            .getCertificateProfileSession()
            .changeCertificateProfile(
                getAdmin(), getSelectedCertProfileName(), acertificateProfile);
        addInfoMessage("CERTIFICATEPROFILESAVED");
        reset();
        return "done"; // Outcome defined in faces-config.xml
      }
    } catch (AuthorizationDeniedException e) {
      addNonTranslatedErrorMessage(
          "Not authorized to edit certificate profile.");
    }
    return "";
  }

  private void applyExpirationRestrictionForValidityWithFixedDate(
      final CertificateProfile profile) {
    final String encodedValidty = profile.getEncodedValidity();
    if (profile.getUseExpirationRestrictionForWeekdays()) {
      Date endDate = null;
      try {
        endDate = ValidityDate.parseAsIso8601(encodedValidty);
      } catch (ParseException e) {
        // NOOP
      }
      if (null != endDate) { // for fixed end dates.
        LOG.info(
            "Applying expiration restrictions for weekdays with fixed end"
                + " date: "
                + encodedValidty
                + " days "
                + Arrays.toString(profile.getExpirationRestrictionWeekdays()));
        try {
          final Date appliedDate =
              ValidityDate.applyExpirationRestrictionForWeekdays(
                  endDate,
                  profile.getExpirationRestrictionWeekdays(),
                  profile.getExpirationRestrictionForWeekdaysExpireBefore());
          if (!appliedDate.equals(endDate)) {
            final String newEncodedValidity =
                ValidityDate.formatAsISO8601ServerTZ(
                    appliedDate.getTime(), ValidityDate.TIMEZONE_SERVER);
            profile.setEncodedValidity(newEncodedValidity);
            addInfoMessage(
                "CERT_EXPIRATION_RESTRICTION_FIXED_DATE_CHANGED",
                encodedValidty,
                newEncodedValidity);
          }
        } catch (Exception e) {
          LOG.warn(
              "Expiration restriction of certificate profile could not be"
                  + " applied!");
        }
      }
    }
  }
  /**
   * @return bool
   */
  public boolean isTypeCA() {
    return isTypeRootCa() || isTypeSubCa();
  }
  /**
   * @return bool
   */
  public boolean isTypeEndEntityAvailable() {
    return true;
  }
  /**
   * @return bool
   */
  public boolean isTypeSubCaAvailable() {
    return isAuthorizedTo(StandardRules.ROLE_ROOT.resource());
  }
  /**
   * @return bool
   */
  public boolean isTypeRootCaAvailable() {
    return isAuthorizedTo(StandardRules.ROLE_ROOT.resource());
  }
  /**
   * @return bool
   */
  public boolean isTypeHardTokenAvailable() {
    return isAuthorizedTo(StandardRules.ROLE_ROOT.resource())
        && getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens();
  }

  /**
   * @return bool
   */
  public boolean isTypeEndEntity() {
    return getCertificateProfile().getType()
        == CertificateConstants.CERTTYPE_ENDENTITY;
  }
  /**
   * @return bool
   */
  public boolean isTypeSubCa() {
    return getCertificateProfile().getType()
        == CertificateConstants.CERTTYPE_SUBCA;
  }
  /**
   * @return bool
   */
  public boolean isTypeRootCa() {
    return getCertificateProfile().getType()
        == CertificateConstants.CERTTYPE_ROOTCA;
  }

  /**
   * @return bool
   */
  public boolean isTypeHardToken() {
    return getCertificateProfile().getType()
        == CertificateConstants.CERTTYPE_HARDTOKEN;
  }

  /** Set. */
  public void setTypeEndEntity() {
    getCertificateProfile().setType(CertificateConstants.CERTTYPE_ENDENTITY);
  }

  /** Set. */
  public void setTypeSubCa() {
    getCertificateProfile().setType(CertificateConstants.CERTTYPE_SUBCA);
  }

  /** Set. */
  public void setTypeRootCa() {
    getCertificateProfile().setType(CertificateConstants.CERTTYPE_ROOTCA);
  }

  /** Set. */
  public void setTypeHardToken() {
    getCertificateProfile().setType(CertificateConstants.CERTTYPE_HARDTOKEN);
  }

  /**
   * @return bool
   */
  public boolean isUniqueCertificateSerialNumberIndex() {
    return getEjbcaWebBean()
        .getEjb()
        .getCertificateCreateSession()
        .isUniqueCertificateSerialNumberIndex();
  }

  /**
   * @return Algos
   */
  public List<SelectItem /*<String,String>*/>
      getAvailableKeyAlgorithmsAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    for (final String current : AlgorithmTools.getAvailableKeyAlgorithms()) {
      ret.add(new SelectItem(current));
    }
    return ret;
  }

  /**
   * @return curves
   */
  public List<SelectItem /*<String,String>*/> getAvailableEcCurvesAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    final Map<String, List<String>> namedEcCurvesMap =
        AlgorithmTools.getNamedEcCurvesMap(false);
    final String[] keys =
        namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
    Arrays.sort(keys);
    ret.add(
        new SelectItem(
            CertificateProfile.ANY_EC_CURVE,
            getEjbcaWebBean().getText("AVAILABLEECDSABYBITS")));
    for (final String name : keys) {
      ret.add(
          new SelectItem(
              name,
              StringTools.getAsStringWithSeparator(
                  " / ", namedEcCurvesMap.get(name))));
    }
    return ret;
  }

  /**
   * @return lengths
   */
  public List<SelectItem /*<Integer,String*/>
      getAvailableBitLengthsAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    for (final int current : CertificateProfile.DEFAULTBITLENGTHS) {
      ret.add(
          new SelectItem(
              current, current + " " + getEjbcaWebBean().getText("BITS")));
    }
    return ret;
  }

  /**
   *  @return profiles
   */
  public List<SelectItem> getAvailableApprovalProfiles() {
    List<SelectItem> ret = new ArrayList<>();
    ApprovalProfileSession approvalProfileSession =
        getEjbcaWebBean().getEjb().getApprovalProfileSession();
    Map<Integer, String> approvalProfiles =
        approvalProfileSession.getApprovalProfileIdToNameMap();
    Set<Entry<Integer, String>> entries = approvalProfiles.entrySet();
    for (Entry<Integer, String> entry : entries) {
      ret.add(new SelectItem(entry.getKey(), entry.getValue()));
    }

    // Sort list by name
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem a, final SelectItem b) {
            return a.getLabel().compareToIgnoreCase(b.getLabel());
          }
        });
    ret.add(
        0,
        new SelectItem(
            -1, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("NONE")));
    return ret;
  }

  /**
   * @return algos
   */
  public List<SelectItem /*<String,String*/> getSignatureAlgorithmAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    // null becomes ""-value.
    ret.add(new SelectItem(null, getEjbcaWebBean().getText("INHERITFROMCA")));
    for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
      ret.add(new SelectItem(current, current));
    }
    return ret;
  }

  /**
   * @return alg
   */
  public String getSignatureAlgorithm() {
    return getCertificateProfile().getSignatureAlgorithm();
  }

  /**
   * @param signatureAlgorithm alg
   */
  public void setSignatureAlgorithm(final String signatureAlgorithm) {
    // Inherit signature algorithm from issuing CA is signaled by null, but is
    // rendered as "".
    final String sigAlg =
        StringUtils.isBlank(signatureAlgorithm) ? null : signatureAlgorithm;
    getCertificateProfile().setSignatureAlgorithm(sigAlg);
  }

  /**
   * Gets the validity.
   *
   * @return the validity as ISO8601 date or relative time.
   * @see org.cesecore.util.ValidityDate ValidityDate
   */
  public String getValidity() {
    return getCertificateProfile().getEncodedValidity();
  }

  /**
   * Sets the validity .
   *
   * @param value the validity as ISO8601 date or relative time.
   * @see org.cesecore.util.ValidityDate ValidityDate
   */
  public void setValidity(final String value) {
    String valueToSet = value;
    if (null != value) {
      try {
        // parse fixed date ISO8601
        ValidityDate.parseAsIso8601(value);
      } catch (ParseException e) {
        // parse simple time and get canonical string
        valueToSet =
            SimpleTime.toString(
                SimpleTime.getSecondsFormat().parseMillis(value),
                SimpleTime.TYPE_DAYS);
      }
      getCertificateProfile().setEncodedValidity(valueToSet);
    }
  }

  /**
   * Gets the validity offset.
   *
   * @return the offset as relative time.
   * @see org.cesecore.util.SimpleTime SimpleTime
   */
  public String getCertificateValidityOffset() {
    return certificateProfile.getCertificateValidityOffset();
  }

  /**
   * Sets the validity offset.
   *
   * @param value the offset as relative time.
   * @see org.cesecore.util.SimpleTime SimpleTime
   */
  public void setCertificateValidityOffset(final String value) {
    certificateProfile.setCertificateValidityOffset(
        SimpleTime.toString(
            SimpleTime.getSecondsFormat().parseMillis(value),
            SimpleTime.TYPE_MINUTES));
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCertificateValidityOffset() throws IOException {
    getCertificateProfile()
        .setUseCertificateValidityOffset(
            !getCertificateProfile().getUseCertificateValidityOffset());
    redirectToComponent("checkusecertificatevalidityoffsetgroup");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseExpirationRestrictionForWeekdays() throws IOException {
    getCertificateProfile()
        .setUseExpirationRestrictionForWeekdays(
            !getCertificateProfile().getUseExpirationRestrictionForWeekdays());
    redirectToComponent("checkuseexpirationtrestrictionforweekdaysgroup");
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionMonday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.MONDAY);
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionTuesday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.TUESDAY);
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionWednesday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.WEDNESDAY);
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionThursday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.THURSDAY);
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionFriday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.FRIDAY);
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionSaturday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.SATURDAY);
  }

  /**
   * @return bool
   */
  public boolean isExpirationRestrictionSunday() {
    return getCertificateProfile()
        .getExpirationRestrictionWeekday(Calendar.SUNDAY);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionMonday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.MONDAY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionTuesday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.TUESDAY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionWednesday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.WEDNESDAY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionThursday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.THURSDAY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionFriday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.FRIDAY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionSaturday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.SATURDAY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setExpirationRestrictionSunday(final boolean enabled) {
    getCertificateProfile()
        .setExpirationRestrictionWeekday(Calendar.SUNDAY, enabled);
  }

  /**
   * @return days
   */
  public List<SelectItem> getExpirationRestrictionWeekdaysAvailable() {
    final List<SelectItem> result = new ArrayList<>();
    result.add(
        new SelectItem(
            Boolean.TRUE,
            getEjbcaWebBean().getText("CERT_EXPIRATION_RESTRICTION_BEFORE")));
    result.add(
        new SelectItem(
            Boolean.FALSE,
            getEjbcaWebBean().getText("CERT_EXPIRATION_RESTRICTION_AFTER")));
    return result;
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseBasicConstraints() throws IOException {
    getCertificateProfile()
        .setUseBasicConstraints(
            !getCertificateProfile().getUseBasicConstraints());
    redirectToComponent("header_x509v3extensions");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUsePathLengthConstraint() throws IOException {
    getCertificateProfile()
        .setUsePathLengthConstraint(
            !getCertificateProfile().getUsePathLengthConstraint());
    if (getCertificateProfile().getUsePathLengthConstraint()) {
      getCertificateProfile().setPathLengthConstraint(1);
    } else {
      getCertificateProfile().setPathLengthConstraint(0);
    }
    redirectToComponent("header_x509v3extensions");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseKeyUsage() throws IOException {
    getCertificateProfile()
        .setUseKeyUsage(!getCertificateProfile().getUseKeyUsage());
    redirectToComponent("header_x509v3extensions_usages");
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageDigitalSignature() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.DIGITALSIGNATURE);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageNonRepudiation() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.NONREPUDIATION);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageKeyEncipherment() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.KEYENCIPHERMENT);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageDataEncipherment() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.DATAENCIPHERMENT);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageKeyAgreement() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.KEYAGREEMENT);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageKeyCertSign() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.KEYCERTSIGN);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageKeyCrlSign() {
    return getCertificateProfile().getKeyUsage(CertificateConstants.CRLSIGN);
  }
  /**
   * @return bool
   */
  public boolean isKeyUsageEncipherOnly() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.ENCIPHERONLY);
  }

  /**
   * @return bool
   */
  public boolean isKeyUsageDecipherOnly() {
    return getCertificateProfile()
        .getKeyUsage(CertificateConstants.DECIPHERONLY);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageDigitalSignature(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.DIGITALSIGNATURE, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageNonRepudiation(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.NONREPUDIATION, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageKeyEncipherment(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.KEYENCIPHERMENT, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageDataEncipherment(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.DATAENCIPHERMENT, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageKeyAgreement(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.KEYAGREEMENT, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageKeyCertSign(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.KEYCERTSIGN, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageKeyCrlSign(final boolean enabled) {
    getCertificateProfile().setKeyUsage(CertificateConstants.CRLSIGN, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageEncipherOnly(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.ENCIPHERONLY, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setKeyUsageDecipherOnly(final boolean enabled) {
    getCertificateProfile()
        .setKeyUsage(CertificateConstants.DECIPHERONLY, enabled);
  }

  /**
   * @return bool
   */
  public boolean isNonOverridableExtensionOIDs() {
    return !getCertificateProfile().getNonOverridableExtensionOIDs().isEmpty();
  }
  /**
   * Toggles which Set is populated, the one for overridable, or the one for
   * non-overridable true to populate non-overridable extension list, false for
   * overridable.
   *
   * @throws IOException Fail
   */
  public void toggleAllowExtensionOverride() throws IOException {
    getCertificateProfile()
        .setAllowExtensionOverride(
            !getCertificateProfile().getAllowExtensionOverride());
    redirectToComponent("checkallowextensionoverridegroup");
  }

  /**
   * @param enabled Enabled
   */
  public void setNonOverridableExtensionOIDs(final boolean enabled) {
    final CertificateProfile profile = getCertificateProfile();
    Set<String> extensions = getOverridableExtensionOIDs();
    if (enabled) {
      profile.setNonOverridableExtensionOIDs(extensions);
      profile.setOverridableExtensionOIDs(new LinkedHashSet<String>());
    } else {
      profile.setOverridableExtensionOIDs(extensions);
      profile.setNonOverridableExtensionOIDs(new LinkedHashSet<String>());
    }
  }

  /**
   * @return OIDs
   */
  public Set<String> getOverridableExtensionOIDs() {
    final CertificateProfile profile = getCertificateProfile();
    if (isNonOverridableExtensionOIDs()) {
      return profile.getNonOverridableExtensionOIDs();
    } else {
      return profile.getOverridableExtensionOIDs();
    }
  }

  /**
   * @param oids OIDs
   */
  public void setOverridableExtensionOIDs(final Set<String> oids) {
    final CertificateProfile profile = getCertificateProfile();
    if (isNonOverridableExtensionOIDs()) {
      profile.setNonOverridableExtensionOIDs(oids);
    } else {
      profile.setOverridableExtensionOIDs(oids);
    }
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseExtendedKeyUsage() throws IOException {
    getCertificateProfile()
        .setUseExtendedKeyUsage(
            !getCertificateProfile().getUseExtendedKeyUsage());
    redirectToComponent("header_x509v3extensions_usages");
  }

  /**
   * @return OIDs
   */
  public List<SelectItem> getExtendedKeyUsageOidsAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    AvailableExtendedKeyUsagesConfiguration ekuConfig =
        getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
    Map<String, String> ekus = ekuConfig.getAllEKUOidsAndNames();
    ArrayList<String> usedEKUs =
        getCertificateProfile().getExtendedKeyUsageOids();
    // If in view only mode, display only used EKU's
    if (certProfilesBean.getViewOnly()) {
      for (String oid : usedEKUs) {
        if (ekus.containsKey(oid)) {
          ret.add(
              new SelectItem(oid, getEjbcaWebBean().getText(ekus.get(oid))));
        } else {
          ret.add(new SelectItem(oid, oid));
        }
      }
    } else {
      for (Entry<String, String> eku : ekus.entrySet()) {
        ret.add(
            new SelectItem(
                eku.getKey(), getEjbcaWebBean().getText(eku.getValue())));
      }
      for (String oid : usedEKUs) {
        if (!ekus.containsKey(oid)) {
          ret.add(new SelectItem(oid, oid));
        }
      }
    }
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem first, final SelectItem second) {
            return first.getLabel().compareTo(second.getLabel());
          }
        });
    return ret;
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseSubjectAlternativeName() throws IOException {
    getCertificateProfile()
        .setUseSubjectAlternativeName(
            !getCertificateProfile().getUseSubjectAlternativeName());
    // Default store to enabled when extension is first enabled and vice versa
    getCertificateProfile()
        .setStoreSubjectAlternativeName(
            getCertificateProfile().getUseSubjectAlternativeName());
    redirectToComponent("header_x509v3extensions_names");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseIssuerAlternativeName() throws IOException {
    getCertificateProfile()
        .setUseIssuerAlternativeName(
            !getCertificateProfile().getUseIssuerAlternativeName());
    redirectToComponent("header_x509v3extensions_names");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseNameConstraints() throws IOException {
    getCertificateProfile()
        .setUseNameConstraints(
            !getCertificateProfile().getUseNameConstraints());
    redirectToComponent("header_x509v3extensions_names");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCRLDistributionPoint() throws IOException {
    getCertificateProfile()
        .setUseCRLDistributionPoint(
            !getCertificateProfile().getUseCRLDistributionPoint());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseDefaultCRLDistributionPoint() throws IOException {
    getCertificateProfile()
        .setUseDefaultCRLDistributionPoint(
            !getCertificateProfile().getUseDefaultCRLDistributionPoint());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCADefinedFreshestCRL() throws IOException {
    getCertificateProfile()
        .setUseCADefinedFreshestCRL(
            !getCertificateProfile().getUseCADefinedFreshestCRL());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseFreshestCRL() throws IOException {
    getCertificateProfile()
        .setUseFreshestCRL(!getCertificateProfile().getUseFreshestCRL());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCertificatePolicies() throws IOException {
    getCertificateProfile()
        .setUseCertificatePolicies(
            !getCertificateProfile().getUseCertificatePolicies());
    redirectToComponent("header_x509v3extensions_usages");
  }

  /**
   * @return Policies
   */
  public ListDataModel<CertificatePolicy> getCertificatePolicies() {
    if (certificatePoliciesModel == null) {
      final List<CertificatePolicy> certificatePolicies =
          getCertificateProfile().getCertificatePolicies();
      if (certificatePolicies != null) {
        certificatePoliciesModel = new ListDataModel<>(certificatePolicies);
      } else {
        certificatePoliciesModel = new ListDataModel<>();
      }
    }
    return certificatePoliciesModel;
  }

  /**
   * @return bool
   */
  public boolean isCurrentCertificatePolicyQualifierIdNone() {
    return "".equals(getCertificatePolicies().getRowData().getQualifierId());
  }

  /**
   * @return bool
   */
  public boolean isCurrentCertificatePolicyQualifierIdCpsUri() {
    return CertificatePolicy.ID_QT_CPS.equals(
        getCertificatePolicies().getRowData().getQualifierId());
  }

  /**
   * @return bool
   */
  public boolean isCurrentCertificatePolicyQualifierIdUserNotice() {
    return CertificatePolicy.ID_QT_UNNOTICE.equals(
        getCertificatePolicies().getRowData().getQualifierId());
  }

  /**
   * @return policy
   */
  public CertificatePolicy getNewCertificatePolicy() {
    if (newCertificatePolicy == null) {
      newCertificatePolicy = new CertificatePolicy("", "", "");
    }
    return newCertificatePolicy;
  }

  /**
   * @param anewCertificatePolicy fail
   */
  public void setNewCertificatePolicy(
      final CertificatePolicy anewCertificatePolicy) {
    this.newCertificatePolicy = anewCertificatePolicy;
  }
  /**
   * @throws IOException fail
   */
  public void actionNewCertificatePolicyQualifierIdNone() throws IOException {
    getNewCertificatePolicy().setQualifierId("");
    getNewCertificatePolicy().setQualifier("");
    redirectToComponent("header_x509v3extensions_usages");
  }
  /**
   * @throws IOException fail
   */
  public void actionNewCertificatePolicyQualifierIdCpsUri() throws IOException {
    getNewCertificatePolicy().setQualifierId(CertificatePolicy.ID_QT_CPS);
    getNewCertificatePolicy().setQualifier("");
    redirectToComponent("header_x509v3extensions_usages");
  }

  /**
   * @throws IOException fail
   */
  public void actionNewCertificatePolicyQualifierIdUserNotice()
      throws IOException {
    getNewCertificatePolicy().setQualifierId(CertificatePolicy.ID_QT_UNNOTICE);
    getNewCertificatePolicy().setQualifier("");
    redirectToComponent("header_x509v3extensions_usages");
  }

  /**
   * @return bool
   */
  public boolean isNewCertificatePolicyQualifierIdNone() {
    return "".equals(getNewCertificatePolicy().getQualifierId());
  }

  /**
   * @return bool
   */
  public boolean isNewCertificatePolicyQualifierIdCpsUri() {
    return CertificatePolicy.ID_QT_CPS.equals(
        getNewCertificatePolicy().getQualifierId());
  }

  /**
   * @return bool
   */
  public boolean isNewCertificatePolicyQualifierIdUserNotice() {
    return CertificatePolicy.ID_QT_UNNOTICE.equals(
        getNewCertificatePolicy().getQualifierId());
  }

  /**
   * @return policy
   * @throws IOException Fail
   */
  public String addCertificatePolicy() throws IOException {
    CertificatePolicy anewCertificatePolicy = getNewCertificatePolicy();
    if (anewCertificatePolicy.getPolicyID().trim().length() > 0) {
      // Only add the policy if something is specified in the PolicyID field
      anewCertificatePolicy =
          new CertificatePolicy(
              anewCertificatePolicy.getPolicyID().trim(),
              anewCertificatePolicy.getQualifierId(),
              anewCertificatePolicy.getQualifier().trim());
      getCertificateProfile().addCertificatePolicy(anewCertificatePolicy);
    }
    setNewCertificatePolicy(null);
    certificatePoliciesModel = null;
    redirectToComponent("header_x509v3extensions_usages");
    return "";
  }

  /**
   * @return Policy
   * @throws IOException Fail
   */
  public String deleteCertificatePolicy() throws IOException {
    final CertificatePolicy certificatePolicy =
        getCertificatePolicies().getRowData();
    getCertificateProfile().removeCertificatePolicy(certificatePolicy);
    newCertificatePolicy = certificatePolicy;
    certificatePoliciesModel = null;
    redirectToComponent("header_x509v3extensions_usages");
    return "";
  }

  /**
   * @return model
   */
  public ListDataModel<String> getCaIssuers() {
    if (caIssuersModel == null) {
      final List<String> caIssuers = getCertificateProfile().getCaIssuers();
      if (caIssuers != null) {
        caIssuersModel = new ListDataModel<>(caIssuers);
      } else {
        caIssuersModel = new ListDataModel<>();
      }
    }
    return caIssuersModel;
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseAuthorityInformationAccess() throws IOException {
    getCertificateProfile()
        .setUseAuthorityInformationAccess(
            !getCertificateProfile().getUseAuthorityInformationAccess());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseDefaultCAIssuer() throws IOException {
    getCertificateProfile()
        .setUseDefaultCAIssuer(
            !getCertificateProfile().getUseDefaultCAIssuer());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseDefaultOCSPServiceLocator() throws IOException {
    getCertificateProfile()
        .setUseDefaultOCSPServiceLocator(
            !getCertificateProfile().getUseDefaultOCSPServiceLocator());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @return Issuer
   */
  public String getNewCaIssuer() {
    return newCaIssuer;
  }

  /**
   * @param anewCaIssuer Issuer
   */
  public void setNewCaIssuer(final String anewCaIssuer) {
    this.newCaIssuer = anewCaIssuer.trim();
  }

  /**
   * @return redirect
   * @throws IOException fail
   */
  public String addCaIssuer() throws IOException {
    getCertificateProfile().addCaIssuer(newCaIssuer);
    newCaIssuer = "";
    caIssuersModel = null;
    redirectToComponent("header_x509v3extensions_valdata");
    return "";
  }

  /**
   * @return redirect
   * @throws IOException fail
   */
  public String deleteCaIssuer() throws IOException {
    final String caIssuer = getCaIssuers().getRowData();
    getCertificateProfile().removeCaIssuer(caIssuer);
    newCaIssuer = caIssuer;
    caIssuersModel = null;
    redirectToComponent("header_x509v3extensions_valdata");
    return "";
  }

  /**
   * @throws IOException fail
   */
  public void toggleUsePrivateKeyUsagePeriodNotBefore() throws IOException {
    getCertificateProfile()
        .setUsePrivateKeyUsagePeriodNotBefore(
            !getCertificateProfile().isUsePrivateKeyUsagePeriodNotBefore());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @return offset
   */
  public String getPrivateKeyUsagePeriodStartOffset() {
    final CertificateProfile acertificateProfile = getCertificateProfile();
    if (acertificateProfile.isUsePrivateKeyUsagePeriodNotBefore()) {
      return SimpleTime.toString(
          acertificateProfile.getPrivateKeyUsagePeriodStartOffset() * msPerS,
          SimpleTime.TYPE_DAYS);
    } else {
      return "";
    }
  }

  /**
   * @param value Value
   */
  public void setPrivateKeyUsagePeriodStartOffset(final String value) {
    if (null != value) {
      final long millis = SimpleTime.getSecondsFormat().parseMillis(value);
      if (millis >= 0) {
        getCertificateProfile()
            .setPrivateKeyUsagePeriodStartOffset(millis / msPerS);
      }
    }
  }

  /**
   * @throws IOException fail
   */
  public void toggleUsePrivateKeyUsagePeriodNotAfter() throws IOException {
    getCertificateProfile()
        .setUsePrivateKeyUsagePeriodNotAfter(
            !getCertificateProfile().isUsePrivateKeyUsagePeriodNotAfter());
    redirectToComponent("header_x509v3extensions_valdata");
  }

  /**
   * @return length
   */
  public String getPrivateKeyUsagePeriodLength() {
    final CertificateProfile acertificateProfile = getCertificateProfile();
    if (acertificateProfile.isUsePrivateKeyUsagePeriodNotAfter()) {
      return SimpleTime.toString(
          acertificateProfile.getPrivateKeyUsagePeriodLength() * msPerS,
          SimpleTime.TYPE_DAYS);
    } else {
      return "";
    }
  }

  /**
   * @param value value
   */
  public void setPrivateKeyUsagePeriodLength(final String value) {
    if (null != value) {
      final long millis = SimpleTime.getSecondsFormat().parseMillis(value);
      if (millis > 0) {
        getCertificateProfile().setPrivateKeyUsagePeriodLength(millis / msPerS);
      }
    }
  }

  /**
   * @throws IOException Fail
   */
  public void toggleUseQCStatement() throws IOException {
    getCertificateProfile()
        .setUseQCStatement(!getCertificateProfile().getUseQCStatement());
    redirectToComponent("header_qcStatements");
  }

  /**
   * @return PDIs
   */
  private List<PKIDisclosureStatement> getQCEtsiPdsList() {
    List<PKIDisclosureStatement> pdsList =
        getCertificateProfile().getQCEtsiPds();
    if (pdsList == null) {
      pdsList = new ArrayList<>();
      // Add a blank line, so the user can fill it in quickly (and blank lines
      // are
      // automatically deleted when saving, so this will never end up in
      // certificates)
      pdsList.add(new PKIDisclosureStatement("", "en"));
    }
    return pdsList;
  }

  /**
   * @return PDIs
   */
  public ListDataModel<PKIDisclosureStatement> getQCEtsiPds() {
    if (pdsListModel == null) {
      final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
      pdsListModel = new ListDataModel<>(pdsList);
      // Listener that sends back changes into the cert profile
      pdsListModel.addDataModelListener(
          new DataModelListener() {
            @Override
            public void rowSelected(final DataModelEvent event) {
              final PKIDisclosureStatement pds =
                  (PKIDisclosureStatement) event.getRowData();
              final int index = event.getRowIndex();
              if (index != -1 && index < pdsList.size()) {
                pdsList.set(index, pds);
                getCertificateProfile().setQCEtsiPds(pdsList);
              }
            }
          });
    }
    return pdsListModel;
  }

  /**
   * Called when the user presses the "Add" button to add a new PDS URL field.
   *
   * @return String
   * @throws IOException Fail
   */
  public String addQCEtsiPds() throws IOException {
    final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
    pdsList.add(
        new PKIDisclosureStatement(
            "", "en")); // start with blank values, that the user can fill in
    getCertificateProfile().setQCEtsiPds(pdsList);
    pdsListModel = null;
    redirectToComponent("header_qcStatements");
    return "";
  }

  /**
   * @return PDIs
   * @throws IOException Fail
   */
  public String deleteQCEtsiPds() throws IOException {
    final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
    int index = getQCEtsiPds().getRowIndex();
    pdsList.remove(index);
    getCertificateProfile().setQCEtsiPds(pdsList);
    pdsListModel = null;
    redirectToComponent("header_qcStatements");
    return "";
  }

  /**
   * Returns true if there's a PDS URL filled in that can be deleted.
   *
   * @return Bool
   */
  public boolean isAbleToDeletePDSUrl() {
    final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
    if (pdsList.size() == 1) {
      // Note that when we reach zero items, there will be a blank placeholder
      // where the user can fill in an URL.
      if (pdsList.get(0) == null || pdsList.get(0).getUrl() == null) {
        // can't delete the placeholder itself
        return false;
      }
      return !pdsList
          .get(0)
          .getUrl()
          .isEmpty(); // can't delete the placeholder itself
    } else {
      return true;
    }
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseQCEtsiValueLimit() throws IOException {
    getCertificateProfile()
        .setUseQCEtsiValueLimit(
            !getCertificateProfile().getUseQCEtsiValueLimit());
    redirectToComponent("header_qcStatements");
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseQCEtsiRetentionPeriod() throws IOException {
    getCertificateProfile()
        .setUseQCEtsiRetentionPeriod(
            !getCertificateProfile().getUseQCEtsiRetentionPeriod());
    redirectToComponent("header_qcStatements");
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseQCCustomString() throws IOException {
    getCertificateProfile()
        .setUseQCCustomString(!getCertificateProfile().getUseQCCustomString());
    redirectToComponent("header_qcStatements");
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseCertificateTransparencyInCerts() throws IOException {
    getCertificateProfile()
        .setUseCertificateTransparencyInCerts(
            !getCertificateProfile().isUseCertificateTransparencyInCerts());
    redirectToComponent("header_certificatetransparency");
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseCertificateTransparencyInOCSP() throws IOException {
    getCertificateProfile()
        .setUseCertificateTransparencyInOCSP(
            !getCertificateProfile().isUseCertificateTransparencyInOCSP());
    redirectToComponent("header_certificatetransparency");
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseCertificateTransparencyInPublishers()
      throws IOException {
    getCertificateProfile()
        .setUseCertificateTransparencyInPublishers(
            !getCertificateProfile()
                .isUseCertificateTransparencyInPublishers());
    redirectToComponent("header_certificatetransparency");
  }
  /**
   * @throws IOException fail
   */
  public void toggleNumberOfSctBy() throws IOException {
    getCertificateProfile()
        .setNumberOfSctByCustom(
            !getCertificateProfile().isNumberOfSctByCustom());
    getCertificateProfile()
        .setNumberOfSctByValidity(
            !getCertificateProfile().isNumberOfSctByValidity());
    redirectToComponent("header_certificatetransparency");
  }

  /**
   * @throws IOException fail
   */
  public void toggleMaxNumberOfSctBy() throws IOException {
    getCertificateProfile()
        .setMaxNumberOfSctByCustom(
            !getCertificateProfile().isMaxNumberOfSctByCustom());
    getCertificateProfile()
        .setMaxNumberOfSctByValidity(
            !getCertificateProfile().isMaxNumberOfSctByValidity());
    redirectToComponent("header_certificatetransparency");
  }


  /**
   * @return bool
   */
  public boolean isCtAvailable() {
    return CertificateTransparencyFactory.isCTAvailable();
  }


  /**
   * @return bool
   */
  public boolean isCtEnabled() {
    return getCertificateProfile().isCtEnabled();
  }


  /**
   * @return bool
   */
  public boolean isCtInCertsOrOCSPEnabled() {
    return getCertificateProfile().isUseCertificateTransparencyInCerts()
        || getCertificateProfile().isUseCertificateTransparencyInOCSP();
  }


  /**
   * @return bool
   */
  public boolean isCtInOCSPOrPublishersEnabled() {
    return getCertificateProfile().isUseCertificateTransparencyInOCSP()
        || getCertificateProfile().isUseCertificateTransparencyInPublishers();
  }


  /**
   * @return bool
   */
  public boolean isNumberOfSctsByValidity() {
    return getCertificateProfile().isNumberOfSctByValidity();
  }


  /**
   * @return bool
   */
  public boolean isNumberOfSctsByCustom() {
    return getCertificateProfile().isNumberOfSctByCustom();
  }


  /**
   * @return bool
   */
  public boolean isMaxNumberOfSctsByValidity() {
    return getCertificateProfile().isMaxNumberOfSctByValidity();
  }

  /**
   * @return bool
   */
  public boolean isMaxNumberOfSctsByCustom() {
    return getCertificateProfile().isMaxNumberOfSctByCustom();
  }

  /**
   * @return labels
   */
  public List<SelectItem> getDistinctCtLabelsAvailable() {
    // Since labels are members of CTlogs (and not the other way around due to
    // legacy design) we select distinct labels this way
    final List<SelectItem> ret = new ArrayList<>();
    final Map<String, String> distinctLables = new HashMap<>();
    for (final CTLogInfo current
        : getEjbcaWebBean().getGlobalConfiguration().getCTLogs().values()) {
      if (!distinctLables.containsKey(current.getLabel())) {
        ret.add(new SelectItem(current.getLabel()));
        distinctLables.put(current.getLabel(), current.getLabel());
      }
    }
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem label1, final SelectItem label2) {
            return label1.getLabel().compareToIgnoreCase(label2.getLabel());
          }
        });
    return ret;
  }

  /** @return the size of the select box */
  public int getDistinctCTLabelsAvailableSize() {
    final int min = 3;
    final int max = 6;
      return Math.max(min,
              Math.min(max, getDistinctCtLabelsAvailable().size()));
  }

  /**
   * @return labels
   */
  public List<String> getEnabledCtLabels() {
    return new ArrayList<>(getCertificateProfile().getEnabledCtLabels());
  }

  /**
   * @param selectedLabels Labels
   */
  public void setEnabledCtLabels(final List<String> selectedLabels) {
    getCertificateProfile()
        .setEnabledCTLabels(new LinkedHashSet<>(selectedLabels));
  }

  /**
   * @throws IOException Fail
   */
  public void toggleUseMicrosoftTemplate() throws IOException {
    getCertificateProfile()
        .setUseMicrosoftTemplate(
            !getCertificateProfile().getUseMicrosoftTemplate());
    redirectToComponent("otherextensions");
  }

  /**
   * @return Template
   */
  public List<SelectItem /*<String,String*/> getMicrosoftTemplateAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    for (final String current : CertificateProfile.AVAILABLE_MSTEMPLATES) {
      ret.add(new SelectItem(current, current));
    }
    return ret;
  }
  /**
   * @throws IOException fail
   */
  public void toggleUseDocumentTypeList() throws IOException {
    getCertificateProfile()
        .setUseDocumentTypeList(
            !getCertificateProfile().getUseDocumentTypeList());
    redirectToComponent("cvc_epassport");
  }

/**
 * @return types
 */
  public String getDocumentTypeListNew() {
    return documentTypeListNew;
  }

  /**
   * @param adocumentTypeListNew types
   */
  public void setDocumentTypeListNew(final String adocumentTypeListNew) {
    this.documentTypeListNew = adocumentTypeListNew.trim();
  }


  /**
   * @throws IOException fail
   */
  public void documentTypeListRemove() throws IOException {
    final String current = getDocumentTypeList().getRowData();
    ArrayList<String> documentTypeListValue =
        getCertificateProfile().getDocumentTypeList();
    documentTypeListValue.remove(current);
    getCertificateProfile().setDocumentTypeList(documentTypeListValue);
    documentTypeListNew = current;
    documentTypeList = null; // Trigger reload of model
    redirectToComponent("cvc_epassport");
  }

  /**
   * @throws IOException fail
   */
  public void documentTypeListAdd() throws IOException {
    if (documentTypeListNew.length() > 0) {
      ArrayList<String> documentTypeListValue =
          getCertificateProfile().getDocumentTypeList();
      documentTypeListValue.add(documentTypeListNew);
      getCertificateProfile().setDocumentTypeList(documentTypeListValue);
      documentTypeListNew = "";
      documentTypeList = null; // Trigger reload of model
    }
    redirectToComponent("cvc_epassport");
  }

  /**
   * @return types
   */
  public ListDataModel<String> getDocumentTypeList() {
    if (documentTypeList == null) {
      documentTypeList =
          new ListDataModel<>(getCertificateProfile().getDocumentTypeList());
    }
    return documentTypeList;
  }

  /**
   * @return bool
   */
  public boolean isCvcAvailable() {
    return CvcCA.getImplementationClasses().iterator().hasNext();
  }

  /**
   * @return bool
   */
  public boolean isCvcTerminalTypeIs() {
    return getCertificateProfile().isCvcTerminalTypeIs();
  }

  /**
   * @return bool
   */
  public boolean isCvcTerminalTypeAt() {
    return getCertificateProfile().isCvcTerminalTypeAt();
  }

  /**
   * @return bool
   */
  public boolean isCvcTerminalTypeSt() {
    return getCertificateProfile().isCvcTerminalTypeSt();
  }

  /**
   * @throws IOException fail
   */
  public void setCvcTerminalTypeIs() throws IOException {
    getCertificateProfile()
        .setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_IS);
    getCertificateProfile()
        .setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
    getCertificateProfile().setCVCLongAccessRights(null);
    redirectToComponent("cvc_epassport");
  }

  /**
   * @throws IOException fail
   */
  public void setCvcTerminalTypeAt() throws IOException {
    getCertificateProfile()
        .setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_AT);
    getCertificateProfile()
        .setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
    getCertificateProfile().setCVCLongAccessRights(null);
    redirectToComponent("cvc_epassport");
  }

  /**
   * @throws IOException fail
   */
  public void setCvcTerminalTypeSt() throws IOException {
    getCertificateProfile()
        .setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_ST);
    getCertificateProfile()
        .setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
    getCertificateProfile().setCVCLongAccessRights(null);
    redirectToComponent("cvc_epassport");
  }

  /**
   * @return types
   */
  public List<SelectItem /*<Integer,String*/> getCvcSignTermDVTypeAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(
        new SelectItem(
            CertificateProfile.CVC_SIGNTERM_DV_AB,
            getEjbcaWebBean().getText("CVCACCREDITATIONBODY")));
    ret.add(
        new SelectItem(
            CertificateProfile.CVC_SIGNTERM_DV_CSP,
            getEjbcaWebBean().getText("CVCCERTIFICATIONSERVICEPROVIDER")));
    return ret;
  }

  // Translation between UI and CertificateProfile's format
  /**
   * @return rights
   */
  public List<Integer> getCvcLongAccessRights() {
    byte[] arl = getCertificateProfile().getCVCLongAccessRights();
    if (arl == null) {
      arl = CertificateProfile.DEFAULT_CVC_RIGHTS_AT;
    }
    AccessRightAuthTerm arlflags;
    try {
      arlflags = new AccessRightAuthTerm(arl);
    } catch (IllegalArgumentException e) {
      // zero-length array or other error
      arlflags = new AccessRightAuthTerm();
    }
    final List<Integer> ret = new ArrayList<>();
    final int max = 37;
    for (int i = 0; i <= max; i++) {
      if (arlflags.getFlag(i)) {
        ret.add(Integer.valueOf(i));
      }
    }
    return ret;
  }
  // Translation between UI and CertificateProfile's format
  /**
   * @param in In
   */
  public void setCvcLongAccessRights(final List<Integer> in) {
    final AccessRightAuthTerm arlflags =
        new AccessRightAuthTerm(CertificateProfile.DEFAULT_CVC_RIGHTS_AT);
    for (final Integer current : in) {
      arlflags.setFlag(current, true);
    }
    getCertificateProfile()
        .setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
    getCertificateProfile().setCVCLongAccessRights(arlflags.getEncoded());
  }

  /**
   * @return bool
   */
  public boolean isCvcAccessRightDg3() {
    return isCvcAccessRight(CertificateProfile.CVC_ACCESS_DG3);
  }

  /**
   * @return bool
   */
  public boolean isCvcAccessRightDg4() {
    return isCvcAccessRight(CertificateProfile.CVC_ACCESS_DG4);
  }

  /**
   * @return bool
   */
  public boolean isCvcAccessRightSign() {
    return isCvcAccessRight(CertificateProfile.CVC_ACCESS_SIGN);
  }

  /**
   * @return bool
   */
  public boolean isCvcAccessRightQualSign() {
    return isCvcAccessRight(CertificateProfile.CVC_ACCESS_QUALSIGN);
  }

  /**
   * @param enabled bool
   */
  public void setCvcAccessRightDg3(final boolean enabled) {
    setCvcAccessRight(CertificateProfile.CVC_ACCESS_DG3, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setCvcAccessRightDg4(final boolean enabled) {
    setCvcAccessRight(CertificateProfile.CVC_ACCESS_DG4, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setCvcAccessRightSign(final boolean enabled) {
    setCvcAccessRight(CertificateProfile.CVC_ACCESS_SIGN, enabled);
  }

  /**
   * @param enabled bool
   */
  public void setCvcAccessRightQualSign(final boolean enabled) {
    setCvcAccessRight(CertificateProfile.CVC_ACCESS_QUALSIGN, enabled);
  }

  private boolean isCvcAccessRight(final int accessRight) {
    return (getCertificateProfile().getCVCAccessRights() & accessRight) != 0;
  }

  private void setCvcAccessRight(final int accessRight, final boolean enabled) {
    if (enabled) {
      getCertificateProfile()
          .setCVCAccessRights(
              getCertificateProfile().getCVCAccessRights() | accessRight);
    } else {
      getCertificateProfile()
          .setCVCAccessRights(
              getCertificateProfile().getCVCAccessRights() & ~accessRight);
    }
  }

  /**
   * @return rights
   */
  public List<SelectItem /*<Integer,String*/> getCvcAccessRightsAtAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    // TODO: Magic numbers
    ret.add(
        new SelectItem(
            String.valueOf(0),
            getEjbcaWebBean().getText("CVCACCESSAGEVERIFICATION")));
    ret.add(
        new SelectItem(
            String.valueOf(1),
            getEjbcaWebBean().getText("CVCACCESSCOMMUNITYIDVERIFICATION")));
    ret.add(
        new SelectItem(
            String.valueOf(2),
            getEjbcaWebBean().getText("CVCACCESSRESTRICTEDIDENTIFICATION")));
    ret.add(
        new SelectItem(
            String.valueOf(3),
            getEjbcaWebBean().getText("CVCACCESSPRIVILEGEDTERMINAL")));
    ret.add(
        new SelectItem(
            String.valueOf(4),
            getEjbcaWebBean().getText("CVCACCESSCANALLOWED")));
    ret.add(
        new SelectItem(
            String.valueOf(5),
            getEjbcaWebBean().getText("CVCACCESSPINMANAGEMENT")));
    ret.add(
        new SelectItem(
            String.valueOf(6),
            getEjbcaWebBean().getText("CVCACCESSINSTALLCERT")));
    ret.add(
        new SelectItem(
            String.valueOf(7),
            getEjbcaWebBean().getText("CVCACCESSINSTALLQUALIFIEDCERT")));
    for (int i = 8; i <= 28; i++) {
      ret.add(
          new SelectItem(
              String.valueOf(i),
              getEjbcaWebBean().getText("CVCACCESSREADDG", false, i - 8 + 1)));
    }
    ret.add(
        new SelectItem(
            String.valueOf(37),
            getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 17)));
    ret.add(
        new SelectItem(
            String.valueOf(36),
            getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 18)));
    ret.add(
        new SelectItem(
            String.valueOf(35),
            getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 19)));
    ret.add(
        new SelectItem(
            String.valueOf(34),
            getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 20)));
    ret.add(
        new SelectItem(
            String.valueOf(33),
            getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 21)));
    return ret;
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCustomDnOrder() throws IOException {
    getCertificateProfile()
        .setUseCustomDnOrder(!getCertificateProfile().getUseCustomDnOrder());
    redirectToComponent("otherdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCustomDnOrderLdap() throws IOException {
    getCertificateProfile()
        .setUseCustomDnOrderWithLdap(
            !getCertificateProfile().getUseCustomDnOrderWithLdap());
    redirectToComponent("otherdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseCNPostfix() throws IOException {
    getCertificateProfile()
        .setUseCNPostfix(!getCertificateProfile().getUseCNPostfix());
    redirectToComponent("otherdata");
  }

  /**
   * @throws IOException fail
   */
  public void toggleUseSubjectDNSubSet() throws IOException {
    getCertificateProfile()
        .setUseSubjectDNSubSet(
            !getCertificateProfile().getUseSubjectDNSubSet());
    redirectToComponent("otherdata");
  }

  /**
   * @return DNs
   */
  public List<SelectItem /*<Integer,String*/> getSubjectDNSubSetAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    final List<Integer> useSubjectDNFields =
        DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDN);
    for (int i = 0; i < useSubjectDNFields.size(); i++) {
      ret.add(
          new SelectItem(
              useSubjectDNFields.get(i),
              getEjbcaWebBean()
                  .getText(DnComponents.getDnLanguageTexts().get(i))));
    }
    return ret;
  }

  /** Toggle.
   * @throws IOException fail */
  public void toggleUseSubjectAltNameSubSet() throws IOException {
    getCertificateProfile()
        .setUseSubjectAltNameSubSet(
            !getCertificateProfile().getUseSubjectAltNameSubSet());
    redirectToComponent("otherdata");
  }

  /**
   * @return names
   */
  public List<SelectItem /*<Integer,String*/>
      getSubjectAltNameSubSetAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    final List<Integer> useSubjectANFields =
        DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTALTNAME);
    for (int i = 0; i < useSubjectANFields.size(); i++) {
      ret.add(
          new SelectItem(
              useSubjectANFields.get(i),
              getEjbcaWebBean()
                  .getText(DnComponents.getAltNameLanguageTexts().get(i))));
    }
    return ret;
  }

  /**
   * @return exts
   */
  public List<SelectItem> getAvailableCertificateExtensionsAvailable() {
    final List<SelectItem> ret = new ArrayList<>();

    AvailableCustomCertificateExtensionsConfiguration cceConfig =
        getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();

    List<Integer> usedExtensions =
        getCertificateProfile().getUsedCertificateExtensions();
    if (certProfilesBean.getViewOnly()) {
      // If in view mode, only display used values.
      for (int id : usedExtensions) {
        if (!cceConfig.isCustomCertExtensionSupported(id)) {
          String note =
              "ID #" + id + " (No longer used. Please unselect this option)";
          ret.add(new SelectItem(id, note));
        } else {
          ret.add(
              new SelectItem(
                  id,
                  getEjbcaWebBean()
                      .getText(
                          cceConfig
                              .getCustomCertificateExtension(id)
                              .getDisplayName())));
        }
      }

    } else {
      for (final CertificateExtension current
          : cceConfig.getAllAvailableCustomCertificateExtensions()) {
        ret.add(
            new SelectItem(
                current.getId(),
                getEjbcaWebBean().getText(current.getDisplayName())));
      }
      for (int id : usedExtensions) {
        if (!cceConfig.isCustomCertExtensionSupported(id)) {
          String note =
              "ID #" + id + " (No longer used. Please unselect this option)";
          ret.add(new SelectItem(id, note));
        }
      }
    }
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem first, final SelectItem second) {
            return first.getLabel().compareToIgnoreCase(second.getLabel());
          }
        });

    return ret;
  }

  public static class ApprovalRequestItem {
      /** Param. */
    private final ApprovalRequestType requestType;
    /** Param. */
    private int approvalProfileId;

    /**
     * @param arequestType type
     * @param anapprovalProfileId id
     */
    public ApprovalRequestItem(
        final ApprovalRequestType arequestType, final int anapprovalProfileId) {
      this.requestType = arequestType;
      this.approvalProfileId = anapprovalProfileId;
    }

    /**
     * @return Type
     */
    public ApprovalRequestType getRequestType() {
      return requestType;
    }

    /**
     * @return ID
     */
    public int getApprovalProfileId() {
      return approvalProfileId;
    }

    /**
     * @param anapprovalProfileId ID
     */
    public void setApprovalProfileId(final int anapprovalProfileId) {
      this.approvalProfileId = anapprovalProfileId;
    }

    /**
     * @return text
     */
    public String getDisplayText() {
      return EjbcaJSFHelper.getBean()
          .getEjbcaWebBean()
          .getText(requestType.getLanguageString());
    }
  }

  /**
   * @return items
   */
  public List<ApprovalRequestItem> getApprovalRequestItems() {
    if (approvalRequestItems == null) {
      approvalRequestItems = new ArrayList<>();
      Map<ApprovalRequestType, Integer> approvals =
          certificateProfile.getApprovals();
      for (ApprovalRequestType approvalRequestType
          : ApprovalRequestType.values()) {
        int approvalProfileId;
        if (approvals.containsKey(approvalRequestType)) {
          approvalProfileId = approvals.get(approvalRequestType);
        } else {
          approvalProfileId = -1;
        }
        // In certificate profiles we don't want to display the "CA Service
        // Activation" approval type,
        // because it is not relevant for certificate profiles But if we have a
        // configuration here, we'll display it
        if (!approvalRequestType.equals(ApprovalRequestType.ACTIVATECA)
            || approvalProfileId != -1) {
          approvalRequestItems.add(
              new ApprovalRequestItem(approvalRequestType, approvalProfileId));
        }
      }
    }
    return approvalRequestItems;
  }

  /**
   * @return size
   */
  public int getAvailableCertificateExtensionsAvailableSize() {
    final int max = 6;
    return Math.max(
        1, Math.min(max, getAvailableCertificateExtensionsAvailable().size()));
  }

  /**
   * @return CAs
   */
  public List<SelectItem /*<Integer,String*/> getAvailableCAsAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    final List<Integer> allCAs =
        getEjbcaWebBean().getEjb().getCaSession().getAllCaIds();
    final List<Integer> authorizedCAs =
        getEjbcaWebBean()
            .getEjb()
            .getCaSession()
            .getAuthorizedCaIds(getAdmin());
    final Map<Integer, String> caIdToNameMap =
        getEjbcaWebBean().getEjb().getCaSession().getCAIdToNameMap();

    // If in view mode, add only authorized CA's
    if (certProfilesBean.getViewOnly()) {
      for (final Integer caId : authorizedCAs) {
        ret.add(new SelectItem(caId, caIdToNameMap.get(caId), "", true));
      }
    } else {
      for (final Integer caId : allCAs) {
        ret.add(
            new SelectItem(
                caId,
                caIdToNameMap.get(caId),
                "",
                (authorizedCAs.contains(caId) ? false : true)));
      }
    }
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem first, final SelectItem second) {
            return first.getLabel().compareToIgnoreCase(second.getLabel());
          }
        });
    ret.add(
        0,
        new SelectItem(
            String.valueOf(CertificateProfile.ANYCA),
            getEjbcaWebBean().getText("ANYCA")));

    return ret;
  }

  /**
   * @return size
   */
  public int getAvailableCAsAvailableSize() {
      final int max = 7;
      return Math.max(1, Math.min(max, getAvailableCAsAvailable().size()));
  }

  /**
   * @return pubs
   */
  public List<SelectItem /*<Integer,String*/> getPublisherListAvailable() {
    final List<SelectItem> ret = new ArrayList<>();
    final Collection<Integer> authorizedPublisherIds =
        getEjbcaWebBean()
            .getEjb()
            .getCaAdminSession()
            .getAuthorizedPublisherIds(getAdmin());
    final Map<Integer, String> publisherIdToNameMap =
        getEjbcaWebBean()
            .getEjb()
            .getPublisherSession()
            .getPublisherIdToNameMap();
    for (final Integer publisherId : authorizedPublisherIds) {
      ret.add(
          new SelectItem(publisherId, publisherIdToNameMap.get(publisherId)));
    }
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem first, final SelectItem second) {
            return first.getLabel().compareToIgnoreCase(second.getLabel());
          }
        });
    return ret;
  }

  /**
   * @return size
   */
  public int getPublisherListAvailableSize() {
    final int max = 5;
    return Math.max(1, Math.min(max, getPublisherListAvailable().size()));
  }

  /**
   * Redirect the client browser to the relevant section of certificate profile
   * page.
   *
   * @param componentId ID
   * @throws IOException Fail
   */
  private void redirectToComponent(final String componentId)
      throws IOException {
    final ExternalContext ec =
        FacesContext.getCurrentInstance().getExternalContext();
    ec.redirect(
        getEjbcaWebBean().getBaseUrl()
            + getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
            + "ca/editcertificateprofiles/editcertificateprofile.jsf#cpf:"
            + componentId);
  }

  /**
   * @return const
   */
  public String getQcEtsiTypeEsign() {
    return CertificateProfileConstants.QC_ETSI_TYPE_ESIGN;
  }

  /**
   * @return const
   */
  public String getQcEtsiTypeEseal() {
    return CertificateProfileConstants.QC_ETSI_TYPE_ESEAL;
  }

  /**
   * @return const
   */
  public String getQcEtsiTypeWebauth() {
    return CertificateProfileConstants.QC_ETSI_TYPE_WEBAUTH;
  }
}
