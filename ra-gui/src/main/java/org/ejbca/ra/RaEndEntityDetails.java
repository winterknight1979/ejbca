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

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringUtil;
import org.cesecore.util.ValidityDateUtil;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * UI representation of a result set item from the back end.
 *
 * <p>Bravely ignoring hard token issuer and printing of user data fields.
 *
 * @version $Id: RaEndEntityDetails.java 28543 2018-03-23 06:52:44Z
 *     jekaterina_b_helmes $
 */
public class RaEndEntityDetails {

  public interface Callbacks {
      /**
       * @return Bean.
       */
    RaLocaleBean getRaLocaleBean();

    /**
     * @param eepId ID
     * @return Profile
     */
    EndEntityProfile getEndEntityProfile(int eepId);
  }
  /** Param. */

  private static final Logger LOG = Logger.getLogger(RaEndEntityDetails.class);
  /** Param. */
  private final Callbacks callbacks;

  /** Param. */
  private final String username;
  /** Param. */
  private final EndEntityInformation endEntityInformation;
  /** Param. */
  private final ExtendedInformation extendedInformation;
  /** Param. */
  private final String subjectDn;
  /** Param. */
  private final String subjectAn;
  /** Param. */
  private final String subjectDa;
  /** Param. */
  private final int eepId;
  /** Param. */
  private final String eepName;
  /** Param. */
  private final int cpId;
  /** Param. */
  private final String cpName;
  /** Param. */
  private final String caName;
  /** Param. */
  private final String created;
  /** Param. */
  private final String modified;
  /** Param. */
  private final int status;

  /** Param. */
  private EndEntityProfile endEntityProfile = null;
  /** Param. */
  private SubjectDn subjectDistinguishedName = null;
  /** Param. */
  private SubjectAlternativeName subjectAlternativeName = null;
  /** Param. */
  private SubjectDirectoryAttributes subjectDirectoryAttributes = null;

  /** Param. */
  private int styleRowCallCounter = 0;

  /** Param. */
  private RaEndEntityDetails next = null;
  /** Param. */
  private RaEndEntityDetails previous = null;

  /**
   * @param endEntity EE
   * @param thecallbacks Callbacks
   * @param cpIdToNameMap Map
   * @param eepIdToNameMap Map
   * @param caIdToNameMap Map
   */
  public RaEndEntityDetails(
      final EndEntityInformation endEntity,
      final Callbacks thecallbacks,
      final Map<Integer, String> cpIdToNameMap,
      final Map<Integer, String> eepIdToNameMap,
      final Map<Integer, String> caIdToNameMap) {
    this(
        endEntity,
        thecallbacks,
        cpIdToNameMap.get(Integer.valueOf(endEntity.getCertificateProfileId())),
        String.valueOf(
            eepIdToNameMap.get(
                Integer.valueOf(endEntity.getEndEntityProfileId()))),
        String.valueOf(
            caIdToNameMap.get(Integer.valueOf(endEntity.getCAId()))));
  }

  /**
   * @param endEntity Entity
   * @param thecallbacks Callback
   * @param certProfName Name
   * @param eeProfName Name
   * @param acaName Name
   */
  public RaEndEntityDetails(
      final EndEntityInformation endEntity,
      final Callbacks thecallbacks,
      final String certProfName,
      final String eeProfName,
      final String acaName) {
    this.endEntityInformation = endEntity;
    final ExtendedInformation anextendedInformation =
        endEntity.getExtendedInformation();
    this.extendedInformation =
        anextendedInformation == null
            ? new ExtendedInformation()
            : anextendedInformation;
    this.callbacks = thecallbacks;
    this.username = endEntity.getUsername();
    this.subjectDn = endEntity.getDN();
    this.subjectAn = endEntity.getSubjectAltName();
    this.subjectDa = this.extendedInformation.getSubjectDirectoryAttributes();
    this.cpId = endEntity.getCertificateProfileId();
    this.cpName = certProfName;
    this.eepId = endEntity.getEndEntityProfileId();
    this.eepName = eeProfName;
    this.caName = acaName;
    final Date timeCreated = endEntity.getTimeCreated();
    if (timeCreated != null) {
      this.created =
          ValidityDateUtil.formatAsISO8601ServerTZ(
              timeCreated.getTime(), TimeZone.getDefault());
    } else {
      this.created = "";
    }
    final Date timeModified = endEntity.getTimeModified();
    if (timeModified != null) {
      this.modified =
          ValidityDateUtil.formatAsISO8601ServerTZ(
              timeModified.getTime(), TimeZone.getDefault());
    } else {
      this.modified = "";
    }
    this.status = endEntity.getStatus();
  }

  /**
   * @return Info
   */
  public EndEntityInformation getEndEntityInformation() {
    return endEntityInformation;
  }

  /**
   * @return User
   */
  public String getUsername() {
    return username;
  }

  /**
   * @return DN
   */
  public String getSubjectDn() {
    return subjectDn;
  }

  /**
   * @return the Subject DN string of the current certificate in unescaped RDN
   *     format
   */
  public final String getSubjectDnUnescapedValue() {
    if (StringUtils.isNotEmpty(subjectDn)) {
      return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDn);
    } else {
      return subjectDn;
    }
  }

  /**
   * @return AN
   */
  public String getSubjectAn() {
    return subjectAn;
  }

  /**
   * @return DA
   */
  public String getSubjectDa() {
    return subjectDa;
  }

  /**
   * @return name
   */
  public String getCaName() {
    return caName;
  }

  /**
   * @return name
   */
  public String getCpName() {
    if (cpId == CertificateProfileConstants.NO_CERTIFICATE_PROFILE) {
      return callbacks
          .getRaLocaleBean()
          .getMessage("component_eedetails_info_unknowncp");
    } else if (cpName != null) {
      return cpName;
    }
    return callbacks
        .getRaLocaleBean()
        .getMessage("component_eedetails_info_missingcp", cpId);
  }

  /**
   * @return bool
   */
  public boolean isCpNameSameAsEepName() {
    return getEepName().equals(getCpName());
  }

  /**
   * @return Name
   */
  public String getEepName() {
    if (eepId == EndEntityConstants.NO_END_ENTITY_PROFILE) {
      return callbacks
          .getRaLocaleBean()
          .getMessage("component_eedetails_info_unknowneep", eepId);
    } else if (eepName != null) {
      return eepName;
    }
    return callbacks
        .getRaLocaleBean()
        .getMessage("component_eedetails_info_missingeep", eepId);
  }

  /**
   * @return Created
   */
  public String getCreated() {
    return created;
  }

  /**
   * @return Modified
   */
  public String getModified() {
    return modified;
  }

  /**
   * @return status
   */
  public String getStatus() {
    switch (status) {
      case EndEntityConstants.STATUS_FAILED:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_status_failed");
      case EndEntityConstants.STATUS_GENERATED:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_status_generated");
      case EndEntityConstants.STATUS_KEYRECOVERY:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_status_keyrecovery");
      case EndEntityConstants.STATUS_NEW:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_status_new");
      case EndEntityConstants.STATUS_REVOKED:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_status_revoked");
      default: break;
    }
    return callbacks
        .getRaLocaleBean()
        .getMessage("component_eedetails_status_other");
  }

  /**
   * @return type
   */
  public String getTokenType() {
    switch (endEntityInformation.getTokenType()) {
      case EndEntityConstants.TOKEN_USERGEN:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_tokentype_usergen");
      case EndEntityConstants.TOKEN_SOFT_JKS:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_tokentype_jks");
      case EndEntityConstants.TOKEN_SOFT_P12:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_tokentype_pkcs12");
      case EndEntityConstants.TOKEN_SOFT_PEM:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_eedetails_tokentype_pem");
      default: break;
    }
    return "?";
  }

  /**
   * Extracts subject DN from certificate request and converts the string to
   * cesecore namestyle.
   *
   * @return subject DN from CSR or null if CSR is missing / corrupted
   */
  public String getDnFromCsr() {
    if (endEntityInformation.getExtendedInformation().getCertificateRequest()
        != null) {
      try {
        PKCS10CertificationRequest pkcs10CertificationRequest =
            new PKCS10CertificationRequest(
                endEntityInformation
                    .getExtendedInformation()
                    .getCertificateRequest());
        // Convert to "correct" display format
        X500Name asubjectDn =
            CertTools.stringToBcX500Name(
                pkcs10CertificationRequest.getSubject().toString());
        return org.ietf.ldap.LDAPDN.unescapeRDN(asubjectDn.toString());
      } catch (IOException e) {
        LOG.info(
            "Failed to retrieve CSR attached to end entity "
                + username
                + ". Incorrect or corrupted structure",
            e);
        return null;
      }
    }
    LOG.info("No CSR found for end entity with username " + username);
    return null;
  }

  /**
   * Returns the specified key type for this end entity (e.g. "RSA 2048"), or
   * null if none is specified (e.g. if created from the Admin GUI)
   *
   * @return String
   */
  public String getKeyType() {
    if (extendedInformation != null
        && extendedInformation.getKeyStoreAlgorithmType() != null) {
      String keyTypeString = extendedInformation.getKeyStoreAlgorithmType();
      if (extendedInformation.getKeyStoreAlgorithmSubType() != null) {
        keyTypeString +=
            " " + extendedInformation.getKeyStoreAlgorithmSubType();
      }
      return keyTypeString;
    } else if (extendedInformation.getCertificateRequest() != null
        && extendedInformation.getKeyStoreAlgorithmType() == null) {
      return getKeysFromCsr();
    }
    return null; // null = hidden in UI
  }

  private String getKeysFromCsr() {
    if (endEntityInformation.getExtendedInformation().getCertificateRequest()
        != null) {
      try {
        PKCS10CertificationRequest pkcs10CertificationRequest =
            new PKCS10CertificationRequest(
                endEntityInformation
                    .getExtendedInformation()
                    .getCertificateRequest());
        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest =
            new JcaPKCS10CertificationRequest(pkcs10CertificationRequest);
        final String keySpecification =
            AlgorithmTools.getKeySpecification(
                jcaPKCS10CertificationRequest.getPublicKey());
        final String keyAlgorithm =
            AlgorithmTools.getKeyAlgorithm(
                jcaPKCS10CertificationRequest.getPublicKey());
        return keyAlgorithm + " " + keySpecification;
      } catch (InvalidKeyException e) {
        LOG.info(
            "Failed to retrieve public key from CSR attached to end entity "
                + username
                + ". Key is either uninitialized or corrupted",
            e);
      } catch (IOException e) {
        LOG.info(
            "Failed retrieve CSR attached to end entity "
                + username
                + ". Incorrect or corrupted structure",
            e);
      } catch (NoSuchAlgorithmException e) {
        LOG.info(
            "Unsupported key algorithm attached to CSR for end entity with"
                + " username "
                + username,
            e);
      }
    }
    LOG.info("No CSR found for end entity with username " + username);
    return null;
  }

  /** Download CSR attached to end entity in .pem format. */
  public void downloadCsr() {
    if (extendedInformation.getCertificateRequest() != null) {
      byte[] certificateSignRequest =
          extendedInformation.getCertificateRequest();
      downloadToken(
          certificateSignRequest, "application/octet-stream", ".pkcs10.pem");
    } else {
      throw new IllegalStateException(
          "Could not find CSR attached to end entity with username "
              + username
              + ". CSR is expected to be set at this point");
    }
  }

  private void downloadToken(
      final byte[] token,
      final String responseContentType,
      final String fileExtension) {
    if (token == null) {
      return;
    }
    // Download the CSR
    FacesContext fc = FacesContext.getCurrentInstance();
    ExternalContext ec = fc.getExternalContext();
    ec
        .responseReset(); // Some JSF component library or some Filter might
                          // have set some headers in the buffer beforehand. We
                          // want to get rid of them, else it may collide.
    ec.setResponseContentType(responseContentType);
    ec.setResponseContentLength(token.length);
    String fileName =
        CertTools.getPartFromDN(endEntityInformation.getDN(), "CN");
    if (fileName == null) {
      fileName = "request_csr";
    }

    final String filename = StringUtil.stripFilename(fileName + fileExtension);
    ec.setResponseHeader(
        "Content-Disposition",
        "attachment; filename=\""
            + filename
            + "\""); // The Save As popup magic is done here. You can give it
                     // any file name you want, this only won't work in MSIE, it
                     // will use current request URL as file name instead.
    OutputStream output = null;
    try {
      output = ec.getResponseOutputStream();
      output.write(token);
      output.flush();
      fc
          .responseComplete(); // Important! Otherwise JSF will attempt to
                               // render the response which obviously will fail
                               // since it's already written with a file and
                               // closed.
    } catch (IOException e) {
      LOG.info("Token " + filename + " could not be downloaded", e);
      callbacks
          .getRaLocaleBean()
          .getMessage("enroll_token_could_not_be_downloaded", filename);
    } finally {
      if (output != null) {
        try {
          output.close();
        } catch (IOException e) {
          throw new IllegalStateException("Failed to close outputstream", e);
        }
      }
    }
  }

  /**
   * @return bool
   */
  public boolean isTokenTypeUserGenerated() {
    return endEntityInformation.getTokenType()
        == EndEntityConstants.TOKEN_USERGEN;
  }

  /**
   * @return bool
   */
  public boolean isKeyRecoverable() {
    return endEntityInformation.getKeyRecoverable();
  }

  /**
   * @return bool
   */
  public boolean isEmailEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.EMAIL, 0);
  }

  /**
   * @return email
   */
  public String getEmail() {
    return endEntityInformation.getEmail();
  }

  /**
   * @return bool
   */
  public boolean isLoginsMaxEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.MAXFAILEDLOGINS, 0);
  }

  /**
   * @return logins
   */
  public String getLoginsMax() {
    return Integer.toString(extendedInformation.getMaxLoginAttempts());
  }

  /**
   * @return logins
   */
  public String getLoginsRemaining() {
    return Integer.toString(extendedInformation.getRemainingLoginAttempts());
  }
  /**
   * @return bool
   */
  public boolean isSendNotificationEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.SENDNOTIFICATION, 0);
  }
  /**
   * @return bool
   */
  public boolean isSendNotification() {
    return endEntityInformation.getSendNotification();
  }

  /**
   * @return bool
   */
  public boolean isCertificateSerialNumberOverrideEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.CERTSERIALNR, 0);
  }

  /**
   * @return override
   */
  public String getCertificateSerialNumberOverride() {
    final BigInteger certificateSerialNumber =
        extendedInformation.certificateSerialNumber();
    if (certificateSerialNumber != null) {
      return certificateSerialNumber.toString(16);
    }
    return "";
  }

  /**
   * @return bool
   */
  public boolean isOverrideNotBeforeEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.STARTTIME, 0);
  }

  /**
   * @return override
   */
  public String getOverrideNotBefore() {
    return extendedInformation.getCustomData(
        ExtendedInformation.CUSTOM_STARTTIME);
  }

  /**
   * @return bool
   */
  public boolean isOverrideNotAfterEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.ENDTIME, 0);
  }

  /**
   * @return override
   */
  public String getOverrideNotAfter() {
    return extendedInformation.getCustomData(
        ExtendedInformation.CUSTOM_ENDTIME);
  }

  /**
   * @return bool
   */
  public boolean isCardNumberEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.CARDNUMBER, 0);
  }

  /**
   * @return num
   */
  public String getCardNumber() {
    return endEntityInformation.getCardNumber();
  }

  /**
   * @return bool
   */
  public boolean isNameConstraintsPermittedEnabled() {
    return getEndEntityProfile()
        .getUse(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0);
  }

  /**
   * @return constraints
   */
  public String getNameConstraintsPermitted() {
    final List<String> value =
        extendedInformation.getNameConstraintsPermitted();
    if (value != null) {
      return Arrays.toString(
          extendedInformation.getNameConstraintsPermitted().toArray());
    }
    return "";
  }

  /**
   * @return bool
   */
  public boolean isNameConstraintsExcludedEnabled() {
    return getEndEntityProfile()
        .getUse(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0);
  }
  /** @return true if CSR exists in EEI */
  public boolean isCsrSet() {
    return extendedInformation.getCertificateRequest() != null;
  }

  /**
   * @return constraints
   */
  public String getNameConstraintsExcluded() {
    final List<String> value = extendedInformation.getNameConstraintsExcluded();
    if (value != null) {
      return Arrays.toString(
          extendedInformation.getNameConstraintsExcluded().toArray());
    }
    return "";
  }

  /**
   * @return bool
   */
  public boolean isAllowedRequestsEnabled() {
    return getEndEntityProfile().getUse(EndEntityProfile.ALLOWEDREQUESTS, 0);
  }

  /**
   * @return reqs
   */
  public String getAllowedRequests() {
    final String value =
        endEntityProfile.getValue(EndEntityProfile.ALLOWEDREQUESTS, 0);
    return value == null ? "1" : value;
  }

  /**
   * @return reqs
   */
  public String getAllowedRequestsUsed() {
    final String value =
        extendedInformation.getCustomData(
            ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
    return value == null ? "0" : value;
  }

  /**
   * @return bool
   */
  public boolean isIssuanceRevocationReasonEnabled() {
    return getEndEntityProfile()
        .getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
  }

  /**
   * @return reason
   */
  public String getIssuanceRevocationReason() {
    final String reasonCode =
        extendedInformation.getCustomData(
            ExtendedInformation.CUSTOM_REVOCATIONREASON);
    if (reasonCode != null) {
      return callbacks
          .getRaLocaleBean()
          .getMessage(
              "component_eedetails_field_issuancerevocation_reason_"
                  + reasonCode);
    }
    return callbacks
        .getRaLocaleBean()
        .getMessage(
            "component_eedetails_field_issuancerevocation_reason_"
                + RevokedCertInfo.NOT_REVOKED);
  }

  /**
   * @return DN
   */
  public SubjectDn getSubjectDistinguishedName() {
    if (subjectDistinguishedName == null) {
      this.subjectDistinguishedName =
          new SubjectDn(getEndEntityProfile(), subjectDn);
    }
    return subjectDistinguishedName;
  }

  /**
   * @return name
   */
  public SubjectAlternativeName getSubjectAlternativeName() {
    if (subjectAlternativeName == null) {
      this.subjectAlternativeName =
          new SubjectAlternativeName(getEndEntityProfile(), subjectAn);
    }
    return subjectAlternativeName;
  }

  /**
   * @return attrs
   */
  public SubjectDirectoryAttributes getSubjectDirectoryAttributes() {
    if (subjectDirectoryAttributes == null) {
      this.subjectDirectoryAttributes =
          new SubjectDirectoryAttributes(getEndEntityProfile(), subjectDa);
    }
    return subjectDirectoryAttributes;
  }

  private EndEntityProfile getEndEntityProfile() {
    if (endEntityProfile == null) {
      endEntityProfile = callbacks.getEndEntityProfile(eepId);
    }
    return endEntityProfile;
  }

  /**
   * Returns the add approval request ID stored in the extended information.
   *
   * @return the ID of the approval request that was submitted to create the end
   *     entity
   */
  public String getAddEndEntityApprovalRequestId() {
    String ret = "";
    final ExtendedInformation ext =
        endEntityInformation.getExtendedInformation();
    if (ext != null) {
      final Integer reqid = ext.getAddEndEntityApprovalRequestId();
      if (reqid != null) {
        ret = reqid.toString();
      }
    }
    return ret;
  }

  /**
   * Returns the edit approval request IDs stored in the extended information as
   * one String separated by ';'.
   *
   * @return the IDs of the approval request that were submitted to edit the end
   *     entity
   */
  public String getEditEndEntityApprovalRequestIds() {
    StringBuilder ret = new StringBuilder("");
    final ExtendedInformation ext =
        endEntityInformation.getExtendedInformation();
    if (ext != null) {
      final List<Integer> ids = ext.getEditEndEntityApprovalRequestIds();
      if (!ids.isEmpty()) {
        for (Integer id : ids) {
          ret = ret.append("; ").append(id);
        }
        ret.delete(0, 2);
      }
    }
    return ret.toString();
  }

  /**
   * Returns the revocation approval request IDs stored in the extended
   * information as one String separated by ';'.
   *
   * @return the IDs of the approval request that were submitted to revoke the
   *     end entity
   */
  public String getRevokeEndEntityApprovalRequestIds() {
    StringBuilder ret = new StringBuilder("");
    final ExtendedInformation ext =
        endEntityInformation.getExtendedInformation();
    if (ext != null) {
      final List<Integer> ids = ext.getRevokeEndEntityApprovalRequestIds();
      if (!ids.isEmpty()) {
        for (Integer id : ids) {
          ret = ret.append("; ").append(id);
        }
        ret.delete(0, 2);
      }
    }
    return ret.toString();
  }

  /** @return true every twice starting with every forth call */
  public boolean isEven() {
    styleRowCallCounter++;
    return (styleRowCallCounter + 1) / 2 % 2 == 0;
  }
  /** @return true every twice starting with every other call */
  public boolean isEvenTwice() {
    isEven();
    return isEven();
  }

  /**
   * @return next
   */
  public RaEndEntityDetails getNext() {
    return next;
  }

  /**
   * @param anext next
   */
  public void setNext(final RaEndEntityDetails anext) {
    this.next = anext;
  }

  /**
   * @return prev
   */
  public RaEndEntityDetails getPrevious() {
    return previous;
  }

  /**
   * @param aprevious prev
   */
  public void setPrevious(final RaEndEntityDetails aprevious) {
    this.previous = aprevious;
  }
}
