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
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDateUtil;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.cvc.AuthorizationField;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CardVerifiableCertificate;

/**
 * UI representation of a certificate from the back end.
 *
 * @version $Id: RaCertificateDetails.java 28543 2018-03-23 06:52:44Z
 *     jekaterina_b_helmes $
 */
public class RaCertificateDetails {

  public interface Callbacks {
      /**
       * @return bean
       */
    RaLocaleBean getRaLocaleBean();

    /**
     * @param raCertificateDetails details
     * @param newStatus status
     * @param newRevocationReason reason
     * @return bool
     * @throws ApprovalException fail
     * @throws WaitingForApprovalException fail
     */
    boolean changeStatus(
        RaCertificateDetails raCertificateDetails,
        int newStatus,
        int newRevocationReason)
        throws ApprovalException, WaitingForApprovalException;

    /**
     * @param raCertificateDetails details
     * @return bool
     * @throws ApprovalException fail
     * @throws CADoesntExistsException fail
     * @throws AuthorizationDeniedException fail
     * @throws WaitingForApprovalException fail
     * @throws NoSuchEndEntityException fail
     * @throws EndEntityProfileValidationException fail
     */
    boolean recoverKey(RaCertificateDetails raCertificateDetails)
        throws ApprovalException, CADoesntExistsException,
            AuthorizationDeniedException, WaitingForApprovalException,
            NoSuchEndEntityException, EndEntityProfileValidationException;

    /**
     * @param raCertificateDetails details
     * @return bool
     */
    boolean keyRecoveryPossible(RaCertificateDetails raCertificateDetails);

    /**
     * @return comp
     */
    UIComponent getConfirmPasswordComponent();
  }

  /** Param.   */
  private static final Logger LOG =
      Logger.getLogger(RaCertificateDetails.class);
  /** Param.   */
  public static final String PARAM_REQUESTID = "requestId";

  /** Param.   */
  private final Callbacks callbacks;

  /** Param.   */
  private CertificateDataWrapper cdw;
  /** Param.   */
  private String fingerprint;
  /** Param.   */
  private String fingerprintSha256 = "";
  /** Param.   */
  private String username;
  /** Param.   */
  private String type = "";
  /** Param.   */
  private String typeVersion = "";
  /** Param.   */
  private String serialnumber;
  /** Param.   */
  private String serialnumberRaw;
  /** Param.   */
  private String subjectDn;
  /** Param.   */
  private String subjectAn = "";
  /** Param.   */
  private String subjectDa = "";
  /** Param.   */
  private Integer eepId;
  /** Param.   */
  private String eepName;
  /** Param.   */
  private Integer cpId;
  /** Param.   */
  private String cpName;
  /** Param.   */
  private String issuerDn;
  /** Param.   */
  private String caName;
  /** Param.   */
  private String created = "-";
  /** Param.   */
  private long expireDate;
  /** Param.   */
  private String expires;
  /** Param.   */
  private int status;
  /** Param.   */
  private int revocationReason;
  /** Param.   */
  private String updated;
  /** Param.   */
  private String revocationDate = "";
  /** Param.   */
  private String publicKeyAlgorithm = "";
  /** Param.   */
  private String publicKeySpecification = "";
  /** Param.   */
  private String publicKeyParameter = "";
  /** Param.   */
  private String subjectKeyId = "";
  /** Param.   */
  private String basicConstraints = "";
  /** Param.   */
  private String cvcAuthorizationRole = "";
  /** Param.   */
  private String cvcAuthorizationAccessRights = "";
  /** Param.   */
  private final List<String> keyUsages = new ArrayList<>();
  /** Param.   */
  private final List<String> extendedKeyUsages = new ArrayList<>();
  /** Param.   */
  private boolean hasNameConstraints = false;
  /** Param.   */
  private boolean hasQcStatements = false;
  /** Param.   */
  private boolean hasCertificateTransparencyScts = false;
  /** Param.   */
  private String signatureAlgorithm;
  /** Param.   */
  private String password;
  /** Param.   */
  private String confirmPassword;
  /** Param.   */
  private int requestId;

  /** Param.   */
  private boolean more = false;
  /** Param.   */
  private boolean renderConfirmRecovery = false;
  /** Param.   */
  private Boolean keyRecoveryPossible;
  /** Param.   */
  private int styleRowCallCounter = 0;

  /** Param.   */
  private RaCertificateDetails next = null;
  /** Param.   */
  private RaCertificateDetails previous = null;

  /** Param.   */
  private int newRevocationReason =
      RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;

  /**
   * @param acdw CDW
   * @param thecallbacks CBs
   * @param cpIdToNameMap Map
   * @param eepIdToNameMap Map
   * @param caSubjectToNameMap Map
   */
  public RaCertificateDetails(
      final CertificateDataWrapper acdw,
      final Callbacks thecallbacks,
      final Map<Integer, String> cpIdToNameMap,
      final Map<Integer, String> eepIdToNameMap,
      final Map<String, String> caSubjectToNameMap) {
    this.callbacks = thecallbacks;
    reInitialize(acdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
  }

  /**
   * @param acdw CDW
   * @param cpIdToNameMap MAp
   * @param eepIdToNameMap Map
   * @param caSubjectToNameMap Map
   */
  public void reInitialize(
      final CertificateDataWrapper acdw,
      final Map<Integer, String> cpIdToNameMap,
      final Map<Integer, String> eepIdToNameMap,
      final Map<String, String> caSubjectToNameMap) {
    this.cdw = acdw;
    final CertificateData certificateData = acdw.getCertificateData();
    this.cpId = certificateData.getCertificateProfileId();
    if (cpId != null && cpIdToNameMap != null) {
      this.cpName = cpIdToNameMap.get(cpId);
    } else {
      this.cpName = null;
    }
    this.eepId = certificateData.getEndEntityProfileIdOrZero();
    if (eepIdToNameMap != null) {
      this.eepName = eepIdToNameMap.get(Integer.valueOf(eepId));
    } else {
      this.eepName = null;
    }
    this.issuerDn = certificateData.getIssuerDN();
    if (caSubjectToNameMap != null) {
      this.caName = getCaNameFromIssuerDn(caSubjectToNameMap, issuerDn);
    } else {
      this.caName = null;
    }
    this.status = certificateData.getStatus();
    this.revocationReason = certificateData.getRevocationReason();
    this.fingerprint = certificateData.getFingerprint();
    this.serialnumberRaw = certificateData.getSerialNumber();
    try {
      this.serialnumber = new BigInteger(this.serialnumberRaw).toString(16);
    } catch (NumberFormatException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Failed to format serial number as hex. Probably a CVC"
                + " certificate. Message: "
                + e.getMessage());
      }
    }
    this.username =
        certificateData.getUsername() == null
            ? ""
            : certificateData.getUsername();
    this.subjectDn = certificateData.getSubjectDnNeverNull();
    final Certificate certificate = acdw.getCertificate();
    byte[] certificateEncoded = null;
    if (certificate != null) {
      try {
        certificateEncoded = certificate.getEncoded();
      } catch (CertificateEncodingException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Failed to encode the certificate as a byte array: "
                  + e.getMessage());
        }
      }
    }
    if (certificate != null || certificateEncoded != null) {
      this.type = certificate.getType();
      this.fingerprintSha256 =
          new String(
              Hex.encode(
                  CertTools.generateSHA256Fingerprint(certificateEncoded)));
      final PublicKey publicKey = certificate.getPublicKey();
      this.publicKeyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
      this.publicKeySpecification =
          AlgorithmTools.getKeySpecification(publicKey);
      if (publicKey instanceof RSAPublicKey) {
        this.publicKeyParameter =
            ((RSAPublicKey) publicKey).getModulus().toString(16);
      } else if (certificate.getPublicKey() instanceof DSAPublicKey) {
        this.publicKeyParameter =
            ((DSAPublicKey) publicKey).getY().toString(16);
      } else if (certificate.getPublicKey() instanceof ECPublicKey) {
        this.publicKeyParameter =
            ((ECPublicKey) publicKey).getW().getAffineX().toString(16)
                + " "
                + ((ECPublicKey) publicKey).getW().getAffineY().toString(16);
      }
      this.created =
          ValidityDateUtil.formatAsISO8601ServerTZ(
              CertTools.getNotBefore(certificate).getTime(),
              TimeZone.getDefault());
      this.signatureAlgorithm =
          AlgorithmTools.getCertSignatureAlgorithmNameAsString(certificate);
      if (certificate instanceof X509Certificate) {
        final X509Certificate x509Certificate = (X509Certificate) certificate;
        this.typeVersion = Integer.toString(x509Certificate.getVersion());
        this.subjectAn = CertTools.getSubjectAlternativeName(certificate);
        try {
          this.subjectDa =
              SubjectDirAttrExtension.getSubjectDirectoryAttributes(
                  certificate);
        } catch (ParseException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Failed to parse Subject Directory Attributes extension: "
                    + e.getMessage());
          }
        }
        final int abasicConstraints = x509Certificate.getBasicConstraints();
        if (abasicConstraints == Integer.MAX_VALUE) {
          this.basicConstraints = "";
        } else if (abasicConstraints == -1) {
          this.basicConstraints =
              callbacks
                  .getRaLocaleBean()
                  .getMessage("component_certdetails_info_basicconstraints_ee");
        } else {
          this.basicConstraints =
              callbacks
                  .getRaLocaleBean()
                  .getMessage(
                      "component_certdetails_info_basicconstraints_ca",
                      abasicConstraints);
        }
        keyUsages.clear();
        final boolean[] keyUsageArray = x509Certificate.getKeyUsage();
        if (keyUsageArray != null) {
          for (int i = 0; i < keyUsageArray.length; i++) {
            if (keyUsageArray[i]) {
              keyUsages.add(String.valueOf(i));
            }
          }
        }
        extendedKeyUsages.clear();
        try {
          final List<String> anextendedKeyUsages =
              x509Certificate.getExtendedKeyUsage();
          if (anextendedKeyUsages != null) {
            this.extendedKeyUsages.addAll(anextendedKeyUsages);
          }
        } catch (CertificateParsingException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Failed to parse Extended Key Usage extension: "
                    + e.getMessage());
          }
        }
        this.hasNameConstraints =
            x509Certificate.getExtensionValue(Extension.nameConstraints.getId())
                != null;
        final CertificateTransparency ct =
            CertificateTransparencyFactory.getInstance();
        this.hasCertificateTransparencyScts =
            ct != null ? ct.hasSCTs(certificate) : false;
        this.hasQcStatements = QCStatementExtension.hasQcStatement(certificate);
      } else if (certificate instanceof CardVerifiableCertificate) {
        final CardVerifiableCertificate cardVerifiableCertificate =
            (CardVerifiableCertificate) certificate;
        this.typeVersion = String.valueOf(CVCertificateBody.CVC_VERSION);
        // Role and access rights
        try {
          final AuthorizationField authorizationField =
              cardVerifiableCertificate
                  .getCVCertificate()
                  .getCertificateBody()
                  .getAuthorizationTemplate()
                  .getAuthorizationField();
          if (authorizationField != null) {
            this.cvcAuthorizationRole =
                String.valueOf(authorizationField.getAuthRole());
            this.cvcAuthorizationAccessRights =
                String.valueOf(authorizationField.getAccessRights());
          }
        } catch (NoSuchFieldException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Failed to parse CVC AuthorizationTemplate's"
                    + " AuthorizationField: "
                    + e.getMessage());
          }
        }
      }
    }
    this.expireDate = certificateData.getExpireDate();
    this.expires =
        ValidityDateUtil.formatAsISO8601ServerTZ(expireDate, TimeZone.getDefault());
    if (status == CertificateConstants.CERT_ARCHIVED
        || status == CertificateConstants.CERT_REVOKED) {
      this.updated =
          ValidityDateUtil.formatAsISO8601ServerTZ(
              certificateData.getRevocationDate(), TimeZone.getDefault());
      this.revocationDate =
          ValidityDateUtil.formatAsISO8601ServerTZ(
              certificateData.getRevocationDate(), TimeZone.getDefault());
    } else {
      this.updated =
          ValidityDateUtil.formatAsISO8601ServerTZ(
              certificateData.getUpdateTime(), TimeZone.getDefault());
    }
    final String subjectKeyIdB64 = certificateData.getSubjectKeyId();
    if (subjectKeyIdB64 != null) {
      this.subjectKeyId =
          new String(Hex.encode(Base64.decode(subjectKeyIdB64.getBytes())));
    }
    styleRowCallCounter = 0; // Reset
  }

  /**
   * @return FP
   */
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @return FP
   */
  public String getFingerprintSha256() {
    return fingerprintSha256;
  }

  /**
   * @return User
   */

  public String getUsername() {
    return username;
  }

  /**
   * @return Type
   */
  public String getType() {
    return type;
  }

  /**
   * @return Bool
   */
  public boolean isTypeX509() {
    return "X.509".equals(type);
  }

  /**
   * @return CVC
   */
  public boolean isTypeCvc() {
    return "CVC".equals(type);
  }

  /**
   * @return Version
   */
  public String getTypeVersion() {
    return typeVersion;
  }

  /**
   * @return SN
   */
  public String getSerialnumber() {
    return serialnumber;
  }

  /**
   * @return SN
   */
  public String getSerialnumberRaw() {
    return serialnumberRaw;
  }

  /**
   * @return DN
   */
  public String getIssuerDn() {
    return issuerDn;
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
   * @return Nam
   */
  public String getCaName() {
    return caName;
  }
  /**
   * @return Certificate Profile Name from the provided CP ID or a localized
   *     error String
   */
  public String getCpName() {
    if (cpId != null
        && cpId.intValue()
            == CertificateProfileConstants.NO_CERTIFICATE_PROFILE) {
      return callbacks
          .getRaLocaleBean()
          .getMessage("component_certdetails_info_unknowncp");
    } else if (cpName != null) {
      return cpName;
    }
    return callbacks
        .getRaLocaleBean()
        .getMessage("component_certdetails_info_missingcp", cpId);
  }

  /**
   * @return bool
   */
  public boolean isCpNameSameAsEepName() {
    return getEepName().equals(getCpName());
  }
  /**
   * @return End Entity Profile Name from the provided EEP ID or a localized
   *     error String
   */
  public String getEepName() {
    if (eepId == EndEntityConstants.NO_END_ENTITY_PROFILE) {
      return callbacks
          .getRaLocaleBean()
          .getMessage("component_certdetails_info_unknowneep");
    }
    if (eepName != null) {
      return eepName;
    }
    return callbacks
        .getRaLocaleBean()
        .getMessage("component_certdetails_info_missingeep", eepId);
  }

  /**
   * @return created
   */
  public String getCreated() {
    return created;
  }

  /**
   * @return expiry
   */
  public String getExpires() {
    return expires;
  }

  /**
   * @return bool
   */
  public boolean isExpired() {
    return expireDate < System.currentTimeMillis();
  }

  /**
   * @return bool
   */
  public boolean isActive() {
    return status == CertificateConstants.CERT_ACTIVE
        || status == CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION;
  }

  /**
   * @return bool
   */
  public boolean isSuspended() {
    return status == CertificateConstants.CERT_REVOKED
        && revocationReason
            == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
  }

  /** @return a localized certificate (revocation) status string */
  public String getStatus() {
    switch (status) {
      case CertificateConstants.CERT_ACTIVE:
      case CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_certdetails_status_active");
      case CertificateConstants.CERT_ARCHIVED:
      case CertificateConstants.CERT_REVOKED:
        return callbacks
            .getRaLocaleBean()
            .getMessage(
                "component_certdetails_status_revoked_" + revocationReason);
      default:
        return callbacks
            .getRaLocaleBean()
            .getMessage("component_certdetails_status_other");
    }
  }

  /**
   * @return updated
   */
  public String getUpdated() {
    return updated;
  }

  /**
   * @return dat
   */
  public String getRevocationDate() {
    return revocationDate;
  }

  /**
   * @return alg
   */
  public String getPublicKeyAlgorithm() {
    return publicKeyAlgorithm;
  }

  /**
   * @return spec
   */
  public String getPublicKeySpecification() {
    return publicKeySpecification;
  }

  /**
   * @return param
   */
  public String getPublicKeyParameter() {
    return publicKeyParameter;
  }

  /**
   * @return id
   */
  public String getSubjectKeyId() {
    return subjectKeyId;
  }

  /**
   * @return constraints
   */
  public String getBasicConstraints() {
    return basicConstraints;
  }

  /**
   * @return role
   */
  public String getCvcAuthorizationRole() {
    return cvcAuthorizationRole;
  }

  /**
   * @return rights
   */
  public String getCvcAuthorizationAccessRights() {
    return cvcAuthorizationAccessRights;
  }

  /**
   * @return usage
   */
  public List<String> getKeyUsages() {
    return keyUsages;
  }

  /**
   * @return usagge
   */
  public List<String> getExtendedKeyUsages() {
    return extendedKeyUsages;
  }

  /**
   * @return constraints
   */
  public String getNameConstraints() {
    return hasNameConstraints
        ? callbacks
            .getRaLocaleBean()
            .getMessage("component_certdetails_info_present")
        : "";
  }

  /**
   * @return qc
   */
  public String getQcStatements() {
    return hasQcStatements
        ? callbacks
            .getRaLocaleBean()
            .getMessage("component_certdetails_info_present")
        : "";
  }

  /**
   * @return scts
   */
  public String getCertificateTransparencyScts() {
    return hasCertificateTransparencyScts
        ? callbacks
            .getRaLocaleBean()
            .getMessage("component_certdetails_info_present")
        : "";
  }

  /**
   * @return Alg
   */
  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  /**
   * @return dump
   */
  public String getDump() {
    final Certificate certificate = cdw.getCertificate();
    if (certificate != null) {
      try {
        return CertTools.dumpCertificateAsString(certificate);
      } catch (RuntimeException e) {
        try {
          return ASN1Dump.dumpAsString(
              ASN1Primitive.fromByteArray(certificate.getEncoded()));
        } catch (CertificateEncodingException | IOException e2) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Failed to parse certificate ASN.1: " + e2.getMessage());
          }
        }
      }
    }
    return "";
  }

  /** @return Certificate as java.security.cert.Certificate */
  public Certificate getCertificate() {
    return cdw.getCertificate();
  }

  /** @return true if more details should be shown */
  public boolean isMore() {
    return more;
  }

  /** Toggle. */
  public void actionToggleMore() {
    more = !more;
    styleRowCallCounter = 0; // Reset
  }

  /** @return true every twice starting with every forth call */
  public boolean isEven() {
    styleRowCallCounter++;
    return (styleRowCallCounter + 1) / 2 % 2 == 0;
  }

  /**
   * @param caSubjectToNameMap Map
   * @param anissuerDn DN
   * @return CA Name from the provided issuer DN or the IssuerDN itself if no
   *     name is known
   */
  private String getCaNameFromIssuerDn(
      final Map<String, String> caSubjectToNameMap, final String anissuerDn) {
    if (anissuerDn != null && caSubjectToNameMap.containsKey(anissuerDn)) {
      return String.valueOf(caSubjectToNameMap.get(anissuerDn));
    }
    return String.valueOf(anissuerDn);
  }

  /**
   * @return details
   */
  public RaCertificateDetails getNext() {
    return next;
  }

  /**
   * @param anext details
   */
  public void setNext(final RaCertificateDetails anext) {
    this.next = anext;
  }

  /**
   * @return details
   */
  public RaCertificateDetails getPrevious() {
    return previous;
  }

  /**
   * @param aprevious details
   */
  public void setPrevious(final RaCertificateDetails aprevious) {
    this.previous = aprevious;
  }

  /**
   * @return list
   */
  public List<SelectItem> getNewRevocationReasons() {
    return getNewRevocationReasons(!isSuspended());
  }

  /**
   * @param includeOnHold bool
   * @return list
   */
  private List<SelectItem> getNewRevocationReasons(
      final boolean includeOnHold) {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(
        new SelectItem(
            Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_0")));
    ret.add(
        new SelectItem(
            Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_1")));
    ret.add(
        new SelectItem(
            Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_2")));
    ret.add(
        new SelectItem(
            Integer.valueOf(
                RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_3")));
    ret.add(
        new SelectItem(
            Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_SUPERSEDED),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_4")));
    ret.add(
        new SelectItem(
            Integer.valueOf(
                RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_5")));
    if (includeOnHold) {
      ret.add(
          new SelectItem(
              Integer.valueOf(
                  RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD),
              callbacks
                  .getRaLocaleBean()
                  .getMessage(
                      "component_certdetails_status_revoked_reason_6")));
    }
    ret.add(
        new SelectItem(
            Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_8")));
    ret.add(
        new SelectItem(
            Integer.valueOf(
                RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_9")));
    ret.add(
        new SelectItem(
            Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE),
            callbacks
                .getRaLocaleBean()
                .getMessage("component_certdetails_status_revoked_reason_10")));
    return ret;
  }

  /**
   * @return reason
   */
  public Integer getNewRevocationReason() {
    return Integer.valueOf(newRevocationReason);
  }


  /**
   * @param anewRevocationReason reason
   */
  public void setNewRevocationReason(final Integer anewRevocationReason) {
    this.newRevocationReason = anewRevocationReason.intValue();
  }

  /**
   * Revoke.
   */
  public void actionRevoke() {
    try {
      if (callbacks.changeStatus(
          this, CertificateConstants.CERT_REVOKED, newRevocationReason)) {
        callbacks
            .getRaLocaleBean()
            .addMessageInfo("component_certdetails_info_revocation_successful");
      } else {
        callbacks
            .getRaLocaleBean()
            .addMessageError("component_certdetails_error_revocation_failed");
      }
    } catch (ApprovalException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageError(
              "component_certdetails_error_revocation_approvalrequest");
    } catch (WaitingForApprovalException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo(
              "component_certdetails_info_revocation_approvalrequest",
              e.getRequestId());
    }
    styleRowCallCounter = 0; // Reset
  }

  /** Reac. */
  public void actionReactivate() {
    try {
      if (callbacks.changeStatus(
          this,
          CertificateConstants.CERT_ACTIVE,
          RevokedCertInfo.NOT_REVOKED)) {
        callbacks
            .getRaLocaleBean()
            .addMessageInfo(
                "component_certdetails_info_reactivation_successful");
      } else {
        callbacks
            .getRaLocaleBean()
            .addMessageError("component_certdetails_error_reactivation_failed");
      }
    } catch (ApprovalException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageError(
              "component_certdetails_error_reactivation_approvalrequest");
    } catch (WaitingForApprovalException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo(
              "component_certdetails_info_reactivation_approvalrequest",
              e.getRequestId());
    }
    styleRowCallCounter = 0; // Reset
  }

  /** Recover. */
  public void actionRecovery() {
    try {
      if (callbacks.recoverKey(this)) {
        callbacks
            .getRaLocaleBean()
            .addMessageInfo("component_certdetails_keyrecovery_successful");
      } else {
        callbacks
            .getRaLocaleBean()
            .addMessageInfo("component_certdetails_keyrecovery_unknown_error");
        LOG.info("Failed to perform key recovery for user: " + subjectDn);
      }
    } catch (ApprovalException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo("component_certdetails_keyrecovery_pending");
      if (LOG.isDebugEnabled()) {
        LOG.debug("Request is still waiting for approval", e);
      }
    } catch (WaitingForApprovalException e) {
      // Setting requestId will render link to 'enroll with request id' page
      requestId = e.getRequestId();
      LOG.info(
          "Request with Id: "
              + e.getRequestId()
              + " has been sent for approval");
    } catch (CADoesntExistsException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo("component_certdetails_keyrecovery_unknown_error");
      LOG.debug("CA does not exist", e);
    } catch (AuthorizationDeniedException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo("component_certdetails_keyrecovery_unauthorized");
      LOG.debug("Not authorized to perform key recovery", e);
    } catch (NoSuchEndEntityException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo(
              "component_certdetails_keyrecovery_no_such_end_entity", username);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "End entity with username: " + username + " does not exist", e);
      }
    } catch (EndEntityProfileValidationException e) {
      callbacks
          .getRaLocaleBean()
          .addMessageInfo("component_certdetails_keyrecovery_unknown_error");
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "End entity with username: "
                + username
                + " does not match end entity profile");
      }
    }
    styleRowCallCounter = 0; // Reset
    renderConfirmRecoveryToggle();
  }

  /**
   * Validate that password and password confirm entries match and render error
   * messages otherwise.
   *
   * @param event event
   */
  public final void validatePassword(final ComponentSystemEvent event) {
    if (renderConfirmRecovery) {
      FacesContext fc = FacesContext.getCurrentInstance();
      UIComponent components = event.getComponent();
      UIInput uiInputPassword =
          (UIInput) components.findComponent("passwordField");
      String apassword =
          uiInputPassword.getLocalValue() == null
              ? ""
              : uiInputPassword.getLocalValue().toString();
      UIInput uiInputConfirmPassword =
          (UIInput) components.findComponent("passwordConfirmField");
      String aconfirmPassword =
          uiInputConfirmPassword.getLocalValue() == null
              ? ""
              : uiInputConfirmPassword.getLocalValue().toString();
      if (apassword.isEmpty()) {
        fc.addMessage(
            callbacks.getConfirmPasswordComponent().getClientId(fc),
            callbacks
                .getRaLocaleBean()
                .getFacesMessage("enroll_password_can_not_be_empty"));
        fc.renderResponse();
      }
      if (!apassword.equals(aconfirmPassword)) {
        fc.addMessage(
            callbacks.getConfirmPasswordComponent().getClientId(fc),
            callbacks
                .getRaLocaleBean()
                .getFacesMessage("enroll_passwords_are_not_equal"));
        fc.renderResponse();
      }
    }
  }

  /**
   * @return ID
   */
  public final String getParamRequestId() {
    return PARAM_REQUESTID;
  }

  /**
   * @return pwd
   */
  public String getConfirmPassword() {
    return confirmPassword;
  }

  /**
   * @param aconfirmPassword pwd
   */
  public void setConfirmPassword(final String aconfirmPassword) {
    this.confirmPassword = aconfirmPassword;
  }

  /**
   * @return pwd
   */
  public String getPassword() {
    return password;
  }

  /**
   * @param apassword pwd
   */
  public void setPassword(final String apassword) {
    this.password = apassword;
  }

  /**
   * @return ID
   */
  public int getRequestId() {
    return requestId;
  }

  /**
   * @param arequestId ID
   */
  public void setRequestId(final int arequestId) {
    this.requestId = arequestId;
  }

  /**
   * @return bool
   */
  public boolean isKeyRecoveryPossible() {
    // This check performs multiple database queries. Only check it on new page
    // load
    if (keyRecoveryPossible == null) {
      this.keyRecoveryPossible = callbacks.keyRecoveryPossible(this);
    }
    return keyRecoveryPossible;
  }

  /**
   * @return bool
   */
  public boolean isRenderConfirmRecovery() {
    return renderConfirmRecovery;
  }

  /** Toggle. */
  public void renderConfirmRecoveryToggle() {
    renderConfirmRecovery = !renderConfirmRecovery;
  }

  /**
   * @return bool
   */
  public boolean isRequestIdInfoRendered() {
    return requestId != 0;
  }
}
