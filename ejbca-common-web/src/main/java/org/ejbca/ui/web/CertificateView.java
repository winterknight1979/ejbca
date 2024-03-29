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

package org.ejbca.ui.web;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatusHelper;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDateUtil;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.HTMLTools;

/**
 * A class transforming X509 certificate data into more readable form used by
 * JSP pages.
 *
 * @version $Id: CertificateView.java 28737 2018-04-17 14:03:02Z aminkh $
 */
public class CertificateView implements Serializable {

  private static final long serialVersionUID = -3511834437471085177L;
  /** Param. */
  private Certificate certificate;
  /** Param. */
  private DNFieldExtractor subjectDnFieldExtractor;
  /** Param. */
  private DNFieldExtractor issuerDnFieldExtractor;
  /** Param. */
  private final RevokedInfoView revokedinfo;
  /** Param. */
  private final String username;
  /** Param. */
  private String subjectaltnamestring;
  /** Param. */
  private String subjectdirattrstring;
  /** Param. */
  private CertificateData certificateData;

  /** Param. */
  public static final String[] KEYUSAGETEXTS = {
    "KU_DIGITALSIGNATURE",
    "KU_NONREPUDIATION",
    "KU_KEYENCIPHERMENT",
    "KU_DATAENCIPHERMENT",
    "KU_KEYAGREEMENT",
    "KU_KEYCERTSIGN",
    "KU_CRLSIGN",
    "KU_ENCIPHERONLY",
    "KU_DECIPHERONLY"
  };
  /** Param. */
  public static final String UNKNOWN = "-";

  /**
   * Creates a new instance of CertificateView.
   *
   * @param cdw CDW
   */
  public CertificateView(final CertificateDataWrapper cdw) {
    certificateData = cdw.getCertificateData();
    revokedinfo =
        new RevokedInfoView(
            CertificateStatusHelper.getCertificateStatus(certificateData),
            getSerialNumberBigInt(certificate, certificateData));
    certificate = cdw.getCertificate();
    username = certificateData.getUsername();
    subjectDnFieldExtractor =
        new DNFieldExtractor(
            certificateData.getSubjectDnNeverNull(),
            DNFieldExtractor.TYPE_SUBJECTDN);
    issuerDnFieldExtractor =
        new DNFieldExtractor(
            certificateData.getIssuerDN(), DNFieldExtractor.TYPE_SUBJECTDN);
  }

  /**
   * Creates a new instance of CertificateView for CA certificates.
   *
   * @param acertificate Cert
   * @param therevokedinfo Info
   */
  public CertificateView(
      final Certificate acertificate, final RevokedInfoView therevokedinfo) {
    this.certificate = acertificate;
    this.revokedinfo = therevokedinfo;
    this.username = null;
    subjectDnFieldExtractor =
        new DNFieldExtractor(
            CertTools.getSubjectDN(acertificate),
            DNFieldExtractor.TYPE_SUBJECTDN);
    subjectDnFieldExtractor =
        new DNFieldExtractor(
            CertTools.getIssuerDN(acertificate),
            DNFieldExtractor.TYPE_SUBJECTDN);
  }

  /**
   * Method that returns the version number of the X509 certificate.
   *
   * @return String
   */
  public String getVersion() {
    if (certificate == null) {
      return UNKNOWN;
    }
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      return Integer.toString(x509cert.getVersion());
    } else {
      return String.valueOf(CVCertificateBody.CVC_VERSION);
    }
  }

  /**
   * @return Type
   */
  public String getType() {
    if (certificate == null) {
      return UNKNOWN;
    }
    return certificate.getType();
  }

  /**
   * @return SN
   */
  public String getSerialNumber() {
    if (certificate == null) {
      return certificateData.getSerialNumberHex();
    }
    return CertTools.getSerialNumberAsString(certificate);
  }

  /**
   * @return SN
   */
  public BigInteger getSerialNumberBigInt() {
    return getSerialNumberBigInt(certificate, certificateData);
  }

  private BigInteger getSerialNumberBigInt(
      final Certificate acertificate,
      final CertificateData thecertificateData) {
    if (acertificate == null) {
      try {
        // This will work for X.509
        return new BigInteger(thecertificateData.getSerialNumber(), 10);
      } catch (NumberFormatException e) {
        return BigInteger.valueOf(0);
      }
    }
    return CertTools.getSerialNumber(acertificate);
  }

  /**
   * @return DN
   */
  public String getIssuerDN() {
    if (certificate == null) {
      return HTMLTools.htmlescape(certificateData.getIssuerDN());
    }
    return HTMLTools.htmlescape(CertTools.getIssuerDN(certificate));
  }

  /**
   * @return DN
   */
  public String getIssuerDNUnEscaped() {
    if (certificate == null) {
      return certificateData.getIssuerDN();
    }
    return CertTools.getIssuerDN(certificate);
  }

  /**
   * @param field Field
   * @param number Number
   * @return DN
   */
  public String getIssuerDNField(final int field, final int number) {
    return HTMLTools.htmlescape(issuerDnFieldExtractor.getField(field, number));
  }

  /**
   * @return DN
   */
  public String getSubjectDN() {
    if (certificate == null) {
      return HTMLTools.htmlescape(certificateData.getSubjectDnNeverNull());
    }
    return HTMLTools.htmlescape(CertTools.getSubjectDN(certificate));
  }

  /**
   * @return subjectDN in unescaped format to be passed later to custom
   *     publishers.
   */
  public String getSubjectDNUnescaped() {
    if (certificate == null) {
      return certificateData.getSubjectDnNeverNull();
    }
    return CertTools.getSubjectDN(certificate);
  }

  /**
   * @param value String to enescape
   * @return value in unescaped RDN format
   */
  public final String getUnescapedRdnValue(final String value) {
    if (StringUtils.isNotEmpty(value)) {
      return org.ietf.ldap.LDAPDN.unescapeRDN(value);
    } else {
      return value;
    }
  }

  /**
   * @return the Subject DN string of the current certificate in unescaped RDN
   *     format
   */
  public final String getSubjectDnUnescapedRndValue() {
    String subjectDn = getSubjectDN();
    if (StringUtils.isNotEmpty(subjectDn)) {
      return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDn);
    } else {
      return subjectDn;
    }
  }

  /**
   * @param field Field
   * @param number Number
   * @return DN
   */
  public String getSubjectDNField(final int field, final int number) {
    return HTMLTools.htmlescape(
        subjectDnFieldExtractor.getField(field, number));
  }

  /**
   * @return validity
   */
  public Date getValidFrom() {
    if (certificate == null) {
      return new Date(0);
    }
    return CertTools.getNotBefore(certificate);
  }

  /**
   * @return validity
   */
  public String getValidFromString() {
    if (certificate == null) {
      return "-";
    }
    return ValidityDateUtil.formatAsISO8601(
        CertTools.getNotBefore(certificate), ValidityDateUtil.TIMEZONE_SERVER);
  }

  /**
   * @return validity
   */
  public Date getValidTo() {
    if (certificate == null) {
      return new Date(certificateData.getExpireDate());
    }
    return CertTools.getNotAfter(certificate);
  }

  /**
   * @return validity
   */
  public String getValidToString() {
    return ValidityDateUtil.formatAsISO8601(
        getValidTo(), ValidityDateUtil.TIMEZONE_SERVER);
  }

  /**
   * @return bool
   */
  public boolean checkValidity() {
    if (certificate == null) {
      // We can't check not before field in this case, so make a best effort
      return certificateData.getExpireDate() >= System.currentTimeMillis();
    }
    boolean valid = true;
    try {
      CertTools.checkValidity(certificate, new Date());
    } catch (CertificateExpiredException e) {
      valid = false;
    } catch (CertificateNotYetValidException e) {
      valid = false;
    }
    return valid;
  }

  /**
   * @param date date
   * @return bool
   */
  public boolean checkValidity(final Date date) {
    if (certificate == null) {
      // We can't check not before field in this case, so make a best effort
      return certificateData.getExpireDate() >= date.getTime();
    }
    boolean valid = true;
    try {
      CertTools.checkValidity(certificate, date);
    } catch (CertificateExpiredException e) {
      valid = false;
    } catch (CertificateNotYetValidException e) {
      valid = false;
    }
    return valid;
  }

  /**
   * @return Algo
   */
  public String getPublicKeyAlgorithm() {
    if (certificate == null) {
      return UNKNOWN;
    }
    return certificate.getPublicKey().getAlgorithm();
  }

  /**
   * @param localizedBitsText bits
   * @return spec
   */
  public String getKeySpec(final String localizedBitsText) {
    if (certificate == null) {
      return UNKNOWN;
    }
    if (certificate.getPublicKey() instanceof ECPublicKey) {
      return AlgorithmTools.getKeySpecification(certificate.getPublicKey());
    } else {
      return ""
          + KeyUtil.getKeyLength(certificate.getPublicKey())
          + " "
          + localizedBitsText;
    }
  }

  /**
   * @return length
   */
  public String getPublicKeyLength() {
    if (certificate == null) {
      return UNKNOWN;
    }
    int len = KeyUtil.getKeyLength(certificate.getPublicKey());
    return len > 0 ? "" + len : null;
  }

  /**
   * @return Mod
   */
  public String getPublicKeyModulus() {
    final int len = 50;
    if (certificate == null) {
      return UNKNOWN;
    }
    String mod = null;
    if (certificate.getPublicKey() instanceof RSAPublicKey) {
      mod =
          ""
              + ((RSAPublicKey) certificate.getPublicKey())
                  .getModulus()
                  .toString(16);
      mod = mod.toUpperCase();
      mod = StringUtils.abbreviate(mod, len);
    } else if (certificate.getPublicKey() instanceof DSAPublicKey) {
      mod =
          "" + ((DSAPublicKey) certificate.getPublicKey()).getY().toString(16);
      mod = mod.toUpperCase();
      mod = StringUtils.abbreviate(mod, len);
    } else if (certificate.getPublicKey() instanceof ECPublicKey) {
      mod =
          ""
              + ((ECPublicKey) certificate.getPublicKey())
                  .getW()
                  .getAffineX()
                  .toString(16);
      mod =
          mod
              + ((ECPublicKey) certificate.getPublicKey())
                  .getW()
                  .getAffineY()
                  .toString(16);
      mod = mod.toUpperCase();
      mod = StringUtils.abbreviate(mod, len);
    }
    return mod;
  }

  /**
   * @return Algo
   */
  public String getSignatureAlgoritm() {
    if (certificate == null) {
      // We could lookup the issuer and show a probably algorithm that was used,
      // but we will never know for sure
      return UNKNOWN;
    }
    // Only used for displaying to user so we can use this value that always
    // works
    return AlgorithmTools.getCertSignatureAlgorithmNameAsString(certificate);
  }

  /**
   * Method that returns if key is allowed for given usage. Usage must be one of
   * this class key usage constants.
   *
   * @param usage Usage
   * @return bool
   */
  public boolean getKeyUsage(final int usage) {
    if (certificate == null) {
      return false;
    }
    boolean returnval = false;
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      if (x509cert.getKeyUsage() != null) {
        returnval = x509cert.getKeyUsage()[usage];
      }
    } else {
      returnval = false;
    }
    return returnval;
  }

  /**
   * @param ekuConfig Config
   * @return Usage
   */
  public String[] getExtendedKeyUsageAsTexts(
      final AvailableExtendedKeyUsagesConfiguration ekuConfig) {
    if (certificate == null) {
      return new String[0];
    }
    List<String> extendedkeyusage = null;
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      try {
        extendedkeyusage = x509cert.getExtendedKeyUsage();
      } catch (CertificateParsingException e) {
      }
    }
    if (extendedkeyusage == null) {
      extendedkeyusage = new ArrayList<>();
    }
    final String[] returnval = new String[extendedkeyusage.size()];
    for (int i = 0; i < extendedkeyusage.size(); i++) {
      returnval[i] = ekuConfig.getExtKeyUsageName(extendedkeyusage.get(i));
    }
    return returnval;
  }

  /**
   * @return URIs
   */
  public List<String> getAuthorityInformationAccessCaIssuerUris() {
    return CertTools.getAuthorityInformationAccessCAIssuerUris(certificate);
  }

  /**
   * @return URLs
   */
  public List<String> getAuthorityInformationAccessOcspUrls() {
    return CertTools.getAuthorityInformationAccessOcspUrls(certificate);
  }

  /**
   * @param localizedNoneText Mone
   * @param localizedNolimitText Limit
   * @param localizedEndEntityText EE
   * @param localizedCaPathLengthText Path
   * @return Constraints
   */
  public String getBasicConstraints(
      final String localizedNoneText,
      final String localizedNolimitText,
      final String localizedEndEntityText,
      final String localizedCaPathLengthText) {
    if (certificate == null) {
      return UNKNOWN;
    }
    String retval = localizedNoneText; // ejbcawebbean.getText("EXT_NONE");
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      int bc = x509cert.getBasicConstraints();
      if (bc == Integer.MAX_VALUE) {
        retval =
            localizedNolimitText;
        // ejbcawebbean.getText("EXT_PKIX_BC_CANOLIMIT");
      } else if (bc == -1) {
        retval =
            localizedEndEntityText;
        // ejbcawebbean.getText("EXT_PKIX_BC_ENDENTITY");
      } else {
        retval =
            localizedCaPathLengthText
            /*ejbcawebbean.getText("EXT_PKIX_BC_CAPATHLENGTH")*/
                + " : "
                + x509cert.getBasicConstraints();
      }
    } else if (certificate.getType().equals("CVC")) {
      CardVerifiableCertificate cvccert =
          (CardVerifiableCertificate) certificate;
      try {
        retval =
            cvccert
                .getCVCertificate()
                .getCertificateBody()
                .getAuthorizationTemplate()
                .getAuthorizationField()
                .getAuthRole()
                .toString();
      } catch (NoSuchFieldException e) {
        retval = localizedNoneText; // ejbcawebbean.getText("EXT_NONE");
      }
    }
    return retval;
  }

  /**
   * @return Sig
   */
  public String getSignature() {
    if (certificate == null) {
      return UNKNOWN;
    }
    return new BigInteger(CertTools.getSignature(certificate)).toString(16);
  }

  /**
   * @return SHA
   */
  public String getSHA1Fingerprint() {
    if (certificate == null) {
      return certificateData.getFingerprint().toUpperCase();
    }
    String returnval = "";
    try {
      byte[] res = CertTools.generateSHA1Fingerprint(certificate.getEncoded());
      String ret = new String(Hex.encode(res));
      returnval = ret.toUpperCase();
    } catch (CertificateEncodingException e) {
    }
    return returnval;
  }

  /**
   * @return SHA
   */
  public String getSHA256Fingerprint() {
    if (certificate == null) {
      return UNKNOWN;
    }
    String returnval = "";
    try {
      byte[] res =
          CertTools.generateSHA256Fingerprint(certificate.getEncoded());
      String ret = new String(Hex.encode(res));
      returnval = ret.toUpperCase();
    } catch (CertificateEncodingException e) {
    }
    return returnval;
  }

  /**
   * @return MD5
   */
  public String getMD5Fingerprint() {
    if (certificate == null) {
      return UNKNOWN;
    }
    String returnval = "";
    try {
      byte[] res = CertTools.generateMD5Fingerprint(certificate.getEncoded());
      String ret = new String(Hex.encode(res));
      returnval = ret.toUpperCase();
    } catch (CertificateEncodingException e) {
    }
    return returnval;
  }

  /**
   * @return bool
   */
  public boolean isRevokedAndOnHold() {
    return revokedinfo != null && revokedinfo.isRevokedAndOnHold();
  }


  /**
   * @return bool
   */
  public boolean isRevoked() {
    return revokedinfo != null && revokedinfo.isRevoked();
  }

  /**
   * @return reason
   */
  public String getRevocationReason() {
    String returnval = null;
    if (revokedinfo != null) {
      returnval = revokedinfo.getRevocationReason();
    }
    return returnval;
  }

  /**
   * @return Date
   */
  public Date getRevocationDate() {
    Date returnval = null;
    if (revokedinfo != null) {
      returnval = revokedinfo.getRevocationDate();
    }
    return returnval;
  }

  /**
   * @return User
   */
  public String getUsername() {
    return username;
  }

  /**
   * @return Cert
   */
  public Certificate getCertificate() {
    return certificate;
  }

  /**
   * @return Attrs
   */
  public String getSubjectDirAttr() {
    if (certificate == null) {
      return UNKNOWN;
    }
    if (subjectdirattrstring == null) {
      try {
        subjectdirattrstring =
            SubjectDirAttrExtension.getSubjectDirectoryAttributes(certificate);
      } catch (Exception e) {
        subjectdirattrstring = e.getMessage();
      }
    }
    return subjectdirattrstring;
  }

  /**
   * @return name
   */
  public String getSubjectAltName() {
    if (certificate == null) {
      return UNKNOWN;
    }
    if (subjectaltnamestring == null) {
      subjectaltnamestring = CertTools.getSubjectAlternativeName(certificate);
    }
    return subjectaltnamestring;
  }
  /**
   * @return bool
   */
  public boolean hasNameConstraints() {
    if (certificate == null) {
      return false;
    }
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      byte[] ext =
          x509cert.getExtensionValue(Extension.nameConstraints.getId());
      return ext != null;
    }
    return false;
  }
  /**
   * @return bool
   */
  public boolean hasQcStatement() {
    if (certificate == null) {
      return false;
    }
    return QCStatementExtension.hasQcStatement(certificate);
  }

  /**
   * @return bool
   */
  public boolean hasCertificateTransparencySCTs() {
    if (certificate == null) {
      return false;
    }
    CertificateTransparency ct = CertificateTransparencyFactory.getInstance();
    return (ct != null && ct.hasSCTs(certificate));
  }
}
