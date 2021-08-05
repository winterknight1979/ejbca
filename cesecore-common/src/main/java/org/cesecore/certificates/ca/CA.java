/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CesecoreRuntimeException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypeConstants;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;

/**
 * CA is a base class that should be inherited by all CA types.
 *
 * @version $Id: CA.java 31725 2019-03-07 10:05:50Z tarmo_r_helmes $
 */
public abstract class CA extends UpgradeableDataHashMap // NOPMD: Long class
    implements Serializable {

  private static final long serialVersionUID = -8755429830955594642L;

  /** Log4j instance. */
  private static Logger log = Logger.getLogger(CA.class);
  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  // protected fields.
  /** Type. */
  public static final String CATYPE = "catype";
  /** DN. */
  protected static final String SUBJECTDN = "subjectdn";
  /** ID. */
  protected static final String CAID = "caid";
  /** Name. */
  public static final String NAME = "name";
  /** Validity. */
  @Deprecated protected static final String VALIDITY = "validity";
  /** Validity. */
  protected static final String ENCODED_VALIDITY = "encodedvalidity";
  /** Expiry. */
  protected static final String EXPIRETIME = "expiretime";
  /** Chain. */
  protected static final String CERTIFICATECHAIN = "certificatechain";
  /** Chain. */
  protected static final String RENEWEDCERTIFICATECHAIN =
      "renewedcertificatechain";
  /** Chain. */
  protected static final String ROLLOVERCERTIFICATECHAIN =
      "rollovercertificatechain";
  /** Token. */
  public static final String CATOKENDATA = "catoken";
  /** Signer. */
  protected static final String SIGNEDBY = "signedby";
  /** Desc,. * */
  protected static final String DESCRIPTION = "description";
  /** Reason. */
  protected static final String REVOCATIONREASON = "revokationreason";
  /** Date. */
  protected static final String REVOCATIONDATE = "revokationdate";
  /** ID. */
  protected static final String CERTIFICATEPROFILEID = "certificateprofileid";
  /** ID. */
  protected static final String DEFAULTCERTIFICATEPROFILEID =
      "defaultcertificateprofileid";
  /** Period. */
  protected static final String CRLPERIOD = "crlperiod";
  /** Period. */
  protected static final String DELTACRLPERIOD = "deltacrlperiod";
  /** Interval. */
  protected static final String CRLISSUEINTERVAL = "crlIssueInterval";
  /** Overlap. */
  protected static final String CRLOVERLAPTIME = "crlOverlapTime";
  /** Publishers. */
  protected static final String CRLPUBLISHERS = "crlpublishers";
  /** Validators. */
  protected static final String VALIDATORS = "keyvalidators";
  /** Finish. */
  private static final String FINISHUSER = "finishuser";
  /** Certs. */
  protected static final String REQUESTCERTCHAIN = "requestcertchain";
  /** Extension. */
  protected static final String EXTENDEDCASERVICES = "extendedcaservices";
  /** Extension. */
  protected static final String EXTENDEDCASERVICE = "extendedcaservice";
  /** Data. */
  protected static final String USENOCONFLICTCERTIFICATEDATA =
      "usenoconflictcertificatedata";
  /** SN size. */
  protected static final String SERIALNUMBEROCTETSIZE = "serialnumberoctetsize";

  /**
   * @deprecated since 6.8.0, replaced by the approvals Action:ApprovalProfile
   *     mapping
   */
  @Deprecated
  protected static final String APPROVALSETTINGS = "approvalsettings";
  /**
   * @deprecated since 6.6.0, use the appropriate approval profile instead
   *     Needed order to be able to upgrade from 6.5 and earlier
   */
  @Deprecated
  protected static final String NUMBEROFREQAPPROVALS = "numberofreqapprovals";
  /**
   * @deprecated since 6.8.0, replaced by the approvals Action:ApprovalProfile
   *     mapping
   */
  @Deprecated protected static final String APPROVALPROFILE = "approvalprofile";
  /** Health. */
  protected static final String INCLUDEINHEALTHCHECK = "includeinhealthcheck";
  /** PK. */
  private static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS =
      "doEnforceUniquePublicKeys";
  /** DN. */
  private static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME =
      "doEnforceUniqueDistinguishedName";
  /** SN. */
  private static final String DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER =
      "doEnforceUniqueSubjectDNSerialnumber";
  /** Hoistory. */
  private static final String USE_CERTREQ_HISTORY = "useCertreqHistory";
  /** Storage. */
  private static final String USE_USER_STORAGE = "useUserStorage";
  /** Storage. */
  private static final String USE_CERTIFICATE_STORAGE = "useCertificateStorage";
  /** Nonexisting. */
  private static final String ACCEPT_REVOCATION_NONEXISTING_ENTRY =
      "acceptRevocationNonExistingEntry";
  /** Latest. */
  private static final String LATESTLINKCERTIFICATE = "latestLinkCertificate";
  /** Keep. */
  private static final String KEEPEXPIREDCERTSONCRL = "keepExpiredCertsOnCRL";
  /** Approvals. */
  private static final String APPROVALS = "approvals";

  /** Map. */
  private HashMap<Integer, ExtendedCAService> extendedcaservicemap =
      new HashMap<>();

  /** Cert chain. */
  private ArrayList<Certificate> certificatechain = null;
  /** Renewed chaon. */
  private ArrayList<Certificate> renewedcertificatechain = null;
  /** Request chain. */
  private ArrayList<Certificate> requestcertchain = null;

  /** Info. */
  private CAInfo cainfo = null;
  /** Token. */
  private CAToken caToken = null;

  /** No args constructor required for ServiceLocator. */
  protected CA() { }

  /**
   * Creates a new instance of CA, this constructor should be used when a new CA
   * is created.
   *
   * @param info Info
   */
  public CA(final CAInfo info) {
    init(info);
  }

  /**
   * Init.
   *
   * @param info Info
   */
  public void init(final CAInfo info) {
    data = new LinkedHashMap<>();

    this.cainfo = info;

    setEncodedValidity(info.getEncodedValidity());
    setSignedBy(info.getSignedBy());
    data.put(DESCRIPTION, info.getDescription());
    data.put(REVOCATIONREASON, Integer.valueOf(-1));
    data.put(
        CERTIFICATEPROFILEID, Integer.valueOf(info.getCertificateProfileId()));
    data.put(
        USENOCONFLICTCERTIFICATEDATA, info.isUseNoConflictCertificateData());
    if (!info.isUseCertificateStorage()) {
      data.put(
          DEFAULTCERTIFICATEPROFILEID,
          Integer.valueOf(info.getDefaultCertificateProfileId()));
    }
    setKeepExpiredCertsOnCRL(info.getKeepExpiredCertsOnCRL());
    setCRLPeriod(info.getCRLPeriod());
    setCRLIssueInterval(info.getCRLIssueInterval());
    setCRLOverlapTime(info.getCRLOverlapTime());
    setDeltaCRLPeriod(info.getDeltaCRLPeriod());
    setCRLPublishers(info.getCRLPublishers());
    setValidators(info.getValidators());
    setFinishUser(info.getFinishUser());
    setIncludeInHealthCheck(info.getIncludeInHealthCheck());
    setDoEnforceUniquePublicKeys(info.isDoEnforceUniquePublicKeys());
    setDoEnforceUniqueDistinguishedName(
        info.isDoEnforceUniqueDistinguishedName());
    setDoEnforceUniqueSubjectDNSerialnumber(
        info.isDoEnforceUniqueSubjectDNSerialnumber());
    setUseCertReqHistory(info.isUseCertReqHistory());
    setUseUserStorage(info.isUseUserStorage());
    setUseCertificateStorage(info.isUseCertificateStorage());
    setAcceptRevocationNonExistingEntry(
        info.isAcceptRevocationNonExistingEntry());

    ArrayList<Integer> extendedservicetypes = new ArrayList<>();
    for (ExtendedCAServiceInfo next : info.getExtendedCAServiceInfos()) {
      createExtendedCAService(next);
      if (log.isDebugEnabled()) {
        log.debug(
            "Adding extended service to CA '"
                + info.getName()
                + "': "
                + next.getType()
                + ", "
                + next.getImplClass());
      }
      extendedservicetypes.add(next.getType());
    }
    data.put(EXTENDEDCASERVICES, extendedservicetypes);
    setApprovals(info.getApprovals());
  }

  private void createExtendedCAService(final ExtendedCAServiceInfo info) {
    // Create implementation using reflection
    try {
      Class<?> implClass = Class.forName(info.getImplClass());
      final ExtendedCAService service =
          (ExtendedCAService)
              implClass
                  .getConstructor(ExtendedCAServiceInfo.class)
                  .newInstance(new Object[] {info});
      setExtendedCAService(service);
    } catch (ClassNotFoundException e) {
      log.warn("failed to add extended CA service: ", e);
    } catch (IllegalArgumentException e) {
      log.warn("failed to add extended CA service: ", e);
    } catch (SecurityException e) {
      log.warn("failed to add extended CA service: ", e);
    } catch (InstantiationException e) {
      log.warn("failed to add extended CA service: ", e);
    } catch (IllegalAccessException e) {
      log.warn("failed to add extended CA service: ", e);
    } catch (InvocationTargetException e) {
      log.warn("failed to add extended CA service: ", e);
    } catch (NoSuchMethodException e) {
      log.warn("failed to add extended CA service: ", e);
    }
  }

  /**
   * Constructor.
   *
   * @param data Data
   */
  public CA(final HashMap<Object, Object> data) {
    init(data);
  }

  /**
   * Constructor used when retrieving existing CA from database.
   *
   * @param data data
   */
  public void init(final HashMap<Object, Object> data) {
    loadData(data);
    extendedcaservicemap = new HashMap<>();
  }

  /** @param info Info */
  public void setCAInfo(final CAInfo info) {
    this.cainfo = info;
  }

  /** @return Info */
  public CAInfo getCAInfo() {
    return this.cainfo;
  }

  /** @return DN */
  public String getSubjectDN() {
    return cainfo.getSubjectDN();
  }

  /** @param subjectDn DN */
  public void setSubjectDN(final String subjectDn) {
    cainfo.subjectdn = subjectDn;
  }

  /** @return ID */
  public int getCAId() {
    return cainfo.getCAId();
  }

  /** @param caid ID */
  public void setCAId(final int caid) {
    cainfo.caid = caid;
  }

  /** @return Name */
  public String getName() {
    return cainfo.getName();
  }

  /** @param caname Name */
  public void setName(final String caname) {
    cainfo.name = caname;
  }

  /** @return Status */
  public int getStatus() {
    return cainfo.getStatus();
  }

  /** @param status status */
  public void setStatus(final int status) {
    cainfo.status = status;
  }

  /** @return one of CAInfo.CATYPE_CVC or CATYPE_X509 */
  public int getCAType() {
    return ((Integer) data.get(CATYPE)).intValue();
  }

  /** @return validity */
  @Deprecated
  public long getValidity() {
    return ((Number) data.get(VALIDITY)).longValue();
  }

  /**
   * Gets the validity.
   *
   * @return the validity as ISO8601 date or relative time.
   * @see org.cesecore.util.ValidityDate ValidityDate
   */
  @SuppressWarnings("deprecation")
  public String getEncodedValidity() {
    String result = (String) data.get(ENCODED_VALIDITY);
    if (StringUtils.isBlank(result)) {
      result = ValidityDate.getStringBeforeVersion661(getValidity());
    }
    return result;
  }

  /**
   * Sets the validity as relative time (format '*y *mo *d *h *m *s', i.e. '1y
   * +2mo -3d 4h 5m 6s') or as fixed end date (ISO8601 format, i.e. 'yyyy-MM-dd
   * HH:mm:ssZZ', 'yyyy-MM-dd HH:mmZZ' or 'yyyy-MM-ddZZ' with optional '+00:00'
   * appended).
   *
   * @param encodedValidity validity
   */
  public void setEncodedValidity(final String encodedValidity) {
    data.put(ENCODED_VALIDITY, encodedValidity);
  }

  /** @return date */
  public Date getExpireTime() {
    return (Date) data.get(EXPIRETIME);
  }

  /** @param expiretime date */
  public void setExpireTime(final Date expiretime) {
    data.put(EXPIRETIME, expiretime);
  }

  /** @return signer */
  public int getSignedBy() {
    return ((Integer) data.get(SIGNEDBY)).intValue();
  }

  /** @param signedby signer */
  public void setSignedBy(final int signedby) {
    data.put(SIGNEDBY, Integer.valueOf(signedby));
  }

  /** @return Description */
  public String getDescription() {
    return (String) data.get(DESCRIPTION);
  }

  /** @param description Description */
  public void setDescription(final String description) {
    data.put(DESCRIPTION, description);
  }

  /** @return reason */
  public int getRevocationReason() {
    return ((Integer) data.get(REVOCATIONREASON)).intValue();
  }

  /** @param reason reason */
  public void setRevocationReason(final int reason) {
    data.put(REVOCATIONREASON, Integer.valueOf(reason));
  }

  /** @return date */
  public Date getRevocationDate() {
    return (Date) data.get(REVOCATIONDATE);
  }

  /** @param date Date */
  public void setRevocationDate(final Date date) {
    data.put(REVOCATIONDATE, date);
  }

  /** @return Period */
  public long getCRLPeriod() {
    return ((Long) data.get(CRLPERIOD)).longValue();
  }

  /** @param crlperiod Period */
  public void setCRLPeriod(final long crlperiod) {
    data.put(CRLPERIOD, Long.valueOf(crlperiod));
  }

  /** @return period */
  public long getDeltaCRLPeriod() {
    if (data.containsKey(DELTACRLPERIOD)) {
      return ((Long) data.get(DELTACRLPERIOD)).longValue();
    } else {
      return 0;
    }
  }

  /** @param deltacrlperiod period */
  public void setDeltaCRLPeriod(final long deltacrlperiod) {
    data.put(DELTACRLPERIOD, Long.valueOf(deltacrlperiod));
  }

  /** @return interval */
  public long getCRLIssueInterval() {
    return ((Long) data.get(CRLISSUEINTERVAL)).longValue();
  }
  /** @param crlIssueInterval Interval */
  public void setCRLIssueInterval(final long crlIssueInterval) {
    data.put(CRLISSUEINTERVAL, Long.valueOf(crlIssueInterval));
  }

  /** @return time */
  public long getCRLOverlapTime() {
    return ((Long) data.get(CRLOVERLAPTIME)).longValue();
  }

  /** @param crlOverlapTime Time */
  public void setCRLOverlapTime(final long crlOverlapTime) {
    data.put(CRLOVERLAPTIME, Long.valueOf(crlOverlapTime));
  }

  /** @return Publishers */
  @SuppressWarnings("unchecked")
  public Collection<Integer> getCRLPublishers() {
    return (Collection<Integer>) data.get(CRLPUBLISHERS);
  }

  /** @param crlpublishers Publishers */
  public void setCRLPublishers(final Collection<Integer> crlpublishers) {
    data.put(CRLPUBLISHERS, crlpublishers);
  }

  /** @return Validators */
  @SuppressWarnings("unchecked")
  public Collection<Integer> getValidators() {
    return (Collection<Integer>) data.get(VALIDATORS);
  }

  /** @param validators Validators */
  public void setValidators(final Collection<Integer> validators) {
    data.put(VALIDATORS, validators);
  }

  /** @return boolean */
  public boolean getKeepExpiredCertsOnCRL() {
    if (data.containsKey(KEEPEXPIREDCERTSONCRL)) {
      return ((Boolean) data.get(KEEPEXPIREDCERTSONCRL)).booleanValue();
    } else {
      return false;
    }
  }

  /** @param keepexpiredcertsoncrl boolean * */
  public void setKeepExpiredCertsOnCRL(final boolean keepexpiredcertsoncrl) {
    data.put(KEEPEXPIREDCERTSONCRL, Boolean.valueOf(keepexpiredcertsoncrl));
  }

  /** @return Profile ID */
  public int getCertificateProfileId() {
    return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();
  }

  /** @return profile ID */
  public int getDefaultCertificateProfileId() {
    Integer defaultCertificateProfileId =
        (Integer) data.get(DEFAULTCERTIFICATEPROFILEID);
    if (defaultCertificateProfileId != null) {
      return defaultCertificateProfileId.intValue();
    } else {
      return 0;
    }
  }

  /** @return the CAs token reference. */
  public CAToken getCAToken() {
    if (caToken == null) {
      @SuppressWarnings("unchecked")
      HashMap<String, String> tokendata =
          (HashMap<String, String>) data.get(CATOKENDATA);
      final CAToken ret = new CAToken(tokendata);
      String signaturealg = tokendata.get(CAToken.SIGNATUREALGORITHM);
      String encryptionalg = tokendata.get(CAToken.ENCRYPTIONALGORITHM);
      String keysequence = CAToken.DEFAULT_KEYSEQUENCE;
      Object seqo = tokendata.get(CAToken.SEQUENCE);
      if (seqo != null) {
        keysequence = (String) seqo;
      }
      int keysequenceformat = StringTools.KEY_SEQUENCE_FORMAT_NUMERIC;
      Object seqfo = tokendata.get(CAToken.SEQUENCE_FORMAT);
      if (seqfo != null) {
        keysequenceformat = (Integer) seqfo;
      }
      // Set values for new CA token
      ret.setSignatureAlgorithm(signaturealg);
      ret.setEncryptionAlgorithm(encryptionalg);
      ret.setKeySequence(keysequence);
      ret.setKeySequenceFormat(keysequenceformat);
      caToken = ret;
    }
    return caToken;
  }

  /**
   * Sets the CA token.
   *
   * @param catoken token
   * @throws InvalidAlgorithmException if algorithm is not valid
   */
  public void setCAToken(final CAToken catoken)
      throws InvalidAlgorithmException {
    // Check that the signature algorithm is one of the a
    // llowed ones, only check if
    // there is a sigAlg though
    // things like a NulLCryptoToken does not have signature algorithms
    final String sigAlg = catoken.getSignatureAlgorithm();
    if (StringUtils.isNotEmpty(sigAlg)
      && !StringTools.containsCaseInsensitive(
          AlgorithmConstants.AVAILABLE_SIGALGS, sigAlg)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.invalidsignaturealg",
                sigAlg,
                ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
        throw new InvalidAlgorithmException(msg);

    }
    final String encAlg = catoken.getEncryptionAlgorithm();
    if (StringUtils.isNotEmpty(encAlg)
      && !StringTools.containsCaseInsensitive(
          AlgorithmConstants.AVAILABLE_SIGALGS, encAlg)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.invalidsignaturealg",
                encAlg,
                ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
        throw new InvalidAlgorithmException(msg);

    }
    data.put(CATOKENDATA, catoken.saveData());
    this.caToken = catoken;
  }

  /**
   * Returns a collection of CA certificates, or null if no request certificate
   * chain exists.
   *
   * @return certificates
   */
  public Collection<Certificate> getRequestCertificateChain() {
    if (requestcertchain == null) {
      @SuppressWarnings("unchecked")
      final Collection<String> storechain =
          (Collection<String>) data.get(REQUESTCERTCHAIN);
      if (storechain != null) {
        this.requestcertchain = new ArrayList<>();
        for (final String b64Cert : storechain) {
          try {
            this.requestcertchain.add(
                CertTools.getCertfromByteArray(
                    Base64.decode(b64Cert.getBytes()), Certificate.class));
          } catch (CertificateParsingException e) {
            throw new IllegalStateException(
                "Database seems to contain invalid "
                    + "certificate information.",
                e);
          }
        }
      }
    }
    return requestcertchain;
  }
  /** @param requestcertificatechain Chain */
  public void setRequestCertificateChain(
      final Collection<Certificate> requestcertificatechain) {
    final ArrayList<String> storechain = new ArrayList<>();
    for (final Certificate cert : requestcertificatechain) {
      try {
        storechain.add(new String(Base64.encode(cert.getEncoded())));
      } catch (Exception e) {
        throw new CesecoreRuntimeException(e);
      }
    }
    data.put(REQUESTCERTCHAIN, storechain);
    this.requestcertchain = new ArrayList<>();
    this.requestcertchain.addAll(requestcertificatechain);
  }

  /**
   * Returns a collection of CA-certificates, with this CAs cert i position 0,
   * or null if no CA-certificates exist. The root CA certificate will thus be
   * in the last position.
   *
   * @return Collection of Certificate
   */
  public List<Certificate> getCertificateChain() {
    if (certificatechain == null) {
      @SuppressWarnings("unchecked")
      Collection<String> storechain =
          (Collection<String>) data.get(CERTIFICATECHAIN);
      if (storechain == null) {
        return null;
      }
      this.certificatechain = new ArrayList<>();
      for (final String b64Cert : storechain) {
        try {
          Certificate cert =
              CertTools.getCertfromByteArray(
                  Base64.decode(b64Cert.getBytes()), Certificate.class);
          if (cert != null) {
            if (log.isDebugEnabled()) {
              log.debug(
                  "Adding CA certificate from "
                      + "CERTIFICATECHAIN to certificatechain:");
              log.debug("Cert subjectDN: " + CertTools.getSubjectDN(cert));
              log.debug("Cert issuerDN: " + CertTools.getIssuerDN(cert));
            }
            this.certificatechain.add(cert);
          } else {
            throw new IllegalArgumentException(
                "Can not create certificate object from: " + b64Cert);
          }
        } catch (Exception e) {
          throw new IllegalStateException(e);
        }
      }
    }
    return certificatechain;
  }

  /** @param aCertificatechain Chain */
  public void setCertificateChain(final List<Certificate> aCertificatechain) {
    final ArrayList<String> storechain = new ArrayList<>();
    for (final Certificate cert : aCertificatechain) {
      try {
        storechain.add(new String(Base64.encode(cert.getEncoded())));
      } catch (CertificateEncodingException e) {
        throw new IllegalArgumentException(e);
      }
    }
    data.put(CERTIFICATECHAIN, storechain);
    this.certificatechain = new ArrayList<>(aCertificatechain);
    this.cainfo.setCertificateChain(aCertificatechain);
  }

  /**
   * @return the list of renewed CA certificates in order from the ol dest as
   *     first to the newest as the last one
   */
  public List<Certificate> getRenewedCertificateChain() {
    if (renewedcertificatechain == null) {
      @SuppressWarnings("unchecked")
      Collection<String> storechain =
          (Collection<String>) data.get(RENEWEDCERTIFICATECHAIN);
      if (storechain == null) {
        return null;
      }
      renewedcertificatechain = new ArrayList<>();
      for (final String b64Cert : storechain) {
        try {
          Certificate cert =
              CertTools.getCertfromByteArray(
                  Base64.decode(b64Cert.getBytes()), Certificate.class);
          if (log.isDebugEnabled()) {
            log.debug(
                "Adding CA certificate from "
                    + "RENEWEDCERTIFICATECHAIN to "
                    + "renewedcertificatechain:");
            log.debug("Cert subjectDN: " + CertTools.getSubjectDN(cert));
            log.debug("Cert issuerDN: " + CertTools.getIssuerDN(cert));
          }
          renewedcertificatechain.add(cert);
        } catch (CertificateParsingException e) {
          throw new IllegalStateException(
              "Some certificates from renewed certificate "
                  + "chain could not be parsed",
              e);
        }
      }
    }
    return renewedcertificatechain;
  }

  /**
   * Make sure to respect the order of renewed CA certificates in the
   * collection: from the oldest as first to the newest as the last one.
   *
   * @param aCertificatechain collection of the renewed CA certificates to be
   *     stored
   */
  public void setRenewedCertificateChain(
      final List<Certificate> aCertificatechain) {
    ArrayList<String> storechain = new ArrayList<>();
    for (Certificate cert : aCertificatechain) {
      try {
        String b64Cert = new String(Base64.encode(cert.getEncoded()));
        storechain.add(b64Cert);
      } catch (CertificateEncodingException e) {
        throw new IllegalStateException(
            "Renewed certificates could not be encoded", e);
      }
    }
    data.put(RENEWEDCERTIFICATECHAIN, storechain);

    renewedcertificatechain = new ArrayList<>();
    renewedcertificatechain.addAll(aCertificatechain);
    cainfo.setRenewedCertificateChain(aCertificatechain);
  }

  /** @param aCertificatechain Certs */
  public void setRolloverCertificateChain(
      final Collection<Certificate> aCertificatechain) {
    Iterator<Certificate> iter = aCertificatechain.iterator();
    ArrayList<String> storechain = new ArrayList<>();
    while (iter.hasNext()) {
      Certificate cert = iter.next();
      try {
        String b64Cert = new String(Base64.encode(cert.getEncoded()));
        storechain.add(b64Cert);
      } catch (Exception e) {
        throw new CesecoreRuntimeException(e);
      }
    }
    data.put(ROLLOVERCERTIFICATECHAIN, storechain);
  }

  /** @return Certs */
  public List<Certificate> getRolloverCertificateChain() {
    final List<?> storechain = (List<?>) data.get(ROLLOVERCERTIFICATECHAIN);
    if (storechain == null) {
      return null;
    }
    final List<Certificate> chain = new ArrayList<>(storechain.size());
    for (Object o : storechain) {
      final String b64Cert = (String) o;
      try {
        final byte[] decoded = Base64.decode(b64Cert.getBytes("US-ASCII"));
        final Certificate cert =
            CertTools.getCertfromByteArray(decoded, Certificate.class);
        chain.add(cert);
      } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException(e);
      } catch (CertificateParsingException e) {
        throw new IllegalStateException(e);
      }
    }
    return chain;
  }
  /** remove certs. */
  public void clearRolloverCertificateChain() {
    data.remove(ROLLOVERCERTIFICATECHAIN);
  }

  /** @return the CAs certificate, or null if no CA-certificates exist. */
  public Certificate getCACertificate() {
    if (certificatechain == null) {
      getCertificateChain();
      // if it's still null, return null
      if (certificatechain == null) {
        return null;
      }
    }
    if (certificatechain.size() == 0) {
      return null;
    }
    Certificate ret = certificatechain.get(0);
    if (log.isDebugEnabled()) {
      log.debug(
          "CA certificate chain is "
              + certificatechain.size()
              + " levels deep.");
      log.debug("CA-cert subjectDN: " + CertTools.getSubjectDN(ret));
      log.debug("CA-cert issuerDN: " + CertTools.getIssuerDN(ret));
    }
    return ret;
  }

  /**
   * @param request Request message
   * @return true if we should use the next CA certificate for rollover, instead
   *     of the current CA certificate.
   */
  public boolean getUseNextCACert(final RequestMessage request) {
    final Certificate currentCert = getCACertificate();
    if (request == null) {
      // We get here when creating a new CA
      log.trace(
          "getUseNextCACert: request is null. "
              + "most likely this is a new CA");
      return false;
    }

    final BigInteger requestSerNo = request.getSerialNo();
    if (requestSerNo == null) {
      log.debug(
          "getUseNextCACert: No serial number in request. "
              + "Will use current CA cert.");
      return false;
    }

    final BigInteger currentSerNo = CertTools.getSerialNumber(currentCert);
    if (currentSerNo == null || currentSerNo.equals(requestSerNo)) {
      // Normal case
      log.trace(
          "getUseNextCACert: CA serial number matches "
              + "request serial number");
      return false;
    }

    final List<Certificate> rolloverChain = getRolloverCertificateChain();
    if (rolloverChain == null || rolloverChain.isEmpty()) {
      log.debug(
          "getUseNextCACert: Serial number in request does not "
              + "match CA serial number, and no roll over certificate "
              + "chain is present. Will use current CA cert.");
      return false;
    }

    final Certificate rolloverCert = rolloverChain.get(0);
    final BigInteger rolloverSerNo = CertTools.getSerialNumber(rolloverCert);
    if (rolloverSerNo != null && rolloverSerNo.equals(requestSerNo)) {
      log.debug(
          "getUseNextCACert: Serial number in request matches next "
              + "(rollover) CA cert. Using next CA cert and key.");
      return true; // this is the only case where we use the next CA cert
    }

    log.debug(
        "getUseNextCACert: Serial number in request does not match"
            + " CA serial number nor next (rollover) CA cert."
            + " Will use current CA cert.");
    return false;
  }
  /** @return boolean */
  protected boolean getFinishUser() {
    return getBoolean(FINISHUSER, true);
  }

  private void setFinishUser(final boolean finishuser) {
    putBoolean(FINISHUSER, finishuser);
  }
  /** @return boolean */
  protected boolean getIncludeInHealthCheck() {
    return getBoolean(INCLUDEINHEALTHCHECK, true);
  }
  /** @param includeInHealthCheck boolean */
  protected void setIncludeInHealthCheck(final boolean includeInHealthCheck) {
    putBoolean(INCLUDEINHEALTHCHECK, includeInHealthCheck);
  }
  /** @return boolean */
  public boolean isDoEnforceUniquePublicKeys() {
    return getBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, false);
  }

  private void setDoEnforceUniquePublicKeys(
      final boolean doEnforceUniquePublicKeys) {
    putBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, doEnforceUniquePublicKeys);
  }
  /** @return boolean */
  public boolean isDoEnforceUniqueDistinguishedName() {
    return getBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, false);
  }

  private void setDoEnforceUniqueDistinguishedName(
      final boolean doEnforceUniqueDistinguishedName) {
    putBoolean(
        DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, doEnforceUniqueDistinguishedName);
  }

  /** @return boolean */
  public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
    return getBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, false);
  }

  private void setDoEnforceUniqueSubjectDNSerialnumber(
      final boolean doEnforceUniqueSubjectDNSerialnumber) {
    putBoolean(
        DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER,
        doEnforceUniqueSubjectDNSerialnumber);
  }

  /**
   * Whether certificate request history should be used or not. The default
   * value here is used when the value is missing in the database, and is true
   * for compatibility with old CAs since it was not configurable and always
   * enabled before 3.10.4. For new CAs the default value is set in the web or
   * CLI code and is false since 6.0.0.
   *
   * @return true/false
   */
  public boolean isUseCertReqHistory() {
    return getBoolean(USE_CERTREQ_HISTORY, true);
  }

  private void setUseCertReqHistory(final boolean useCertReqHistory) {
    putBoolean(USE_CERTREQ_HISTORY, useCertReqHistory);
  }

  /**
   * @return whether users should be stored or not, default true as was the case
   *     before 3.10.x
   */
  public boolean isUseUserStorage() {
    return getBoolean(USE_USER_STORAGE, true);
  }

  private void setUseUserStorage(final boolean useUserStorage) {
    putBoolean(USE_USER_STORAGE, useUserStorage);
  }

  /**
   * @return whether issued certificates should be stored or not, default true
   *     as was the case before 3.10.x
   */
  public boolean isUseCertificateStorage() {
    return getBoolean(USE_CERTIFICATE_STORAGE, true);
  }

  private void setUseCertificateStorage(final boolean useCertificateStorage) {
    putBoolean(USE_CERTIFICATE_STORAGE, useCertificateStorage);
  }

  private void setAcceptRevocationNonExistingEntry(
      final boolean acceptRevocationNonExistingEntry) {
    putBoolean(
        ACCEPT_REVOCATION_NONEXISTING_ENTRY, acceptRevocationNonExistingEntry);
  }

  /** @return whether revocations for non existing entry accepted */
  public boolean isAcceptRevocationNonExistingEntry() {
    return getBoolean(ACCEPT_REVOCATION_NONEXISTING_ENTRY, false);
  }

  /** @return A 1:1 mapping between Approval Action:Approval Profile ID */
  @SuppressWarnings("unchecked")
  public Map<ApprovalRequestType, Integer> getApprovals() {
    return (Map<ApprovalRequestType, Integer>) data.get(APPROVALS);
  }

  /**
   * Set approvals.
   *
   * @param approvals Approvals
   */
  public void setApprovals(final Map<ApprovalRequestType, Integer> approvals) {
    // We must store this as a predictable order map in the database,
    // in order for
    // databaseprotection to work
    data.put(
        APPROVALS,
        approvals != null
            ? new LinkedHashMap<>(approvals)
            : new LinkedHashMap<>());
  }

  /**
   * @return a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
   *     action that requires approvals, default none and never null.
   * @deprecated since 6.8.0, see getApprovals()
   */
  @Deprecated
  @SuppressWarnings("unchecked")
  public Collection<Integer> getApprovalSettings() {
    if (data.get(APPROVALSETTINGS) == null) {
      return new ArrayList<>();
    }
    return (Collection<Integer>) data.get(APPROVALSETTINGS);
  }

  /**
   * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action
   * that requires approvals.
   *
   * @param approvalSettings settings
   * @deprecated since 6.8.0, see setApprovals()
   */
  @Deprecated
  public void setApprovalSettings(final Collection<Integer> approvalSettings) {
    data.put(APPROVALSETTINGS, approvalSettings);
  }

  /**
   * @return the number of different administrators that needs to approve an
   *     action, default 1.
   * @deprecated since 6.6.0, use the appropriate approval profile instead.
   *     Needed in order to be able to upgrade from 6.5 and earlier
   */
  @Deprecated
  public int getNumOfRequiredApprovals() {
    if (data.get(NUMBEROFREQAPPROVALS) == null) {
      return 1;
    }
    return ((Integer) data.get(NUMBEROFREQAPPROVALS)).intValue();
  }

  /**
   * The number of different administrators that needs to approve.
   *
   * @param numOfReqApprovals # of approvals
   * @deprecated since 6.6.0, use the appropriate approval profile instead.
   *     Needed in order to be able to upgrade from 6.5 and earlier
   */
  @Deprecated
  public void setNumOfRequiredApprovals(final int numOfReqApprovals) {
    data.put(NUMBEROFREQAPPROVALS, Integer.valueOf(numOfReqApprovals));
  }

  /**
   * @return the id of the approval profile. Defult -1 (= none)
   * @deprecated since 6.8.0, see getApprovals()
   */
  @Deprecated
  public int getApprovalProfile() {
    if (data.get(APPROVALPROFILE) == null) {
      return -1;
    }
    return ((Integer) data.get(APPROVALPROFILE)).intValue();
  }

  /**
   * The id of the approval profile.
   *
   * @param approvalProfileID ID
   * @deprecated since 6.8.0, see setApprovals()
   */
  @Deprecated
  public void setApprovalProfile(final int approvalProfileID) {
    data.put(APPROVALPROFILE, Integer.valueOf(approvalProfileID));
  }

  /**
   * Update CA.
   *
   * @param cryptoToken Crypto Token
   * @param aCainfo CA Info
   * @param cceConfig Config
   * @throws InvalidAlgorithmException Fail
   */
  public void updateCA(
      final CryptoToken cryptoToken,
      final CAInfo aCainfo,
      final AvailableCustomCertificateExtensionsConfiguration cceConfig)
      throws InvalidAlgorithmException {
    setEncodedValidity(aCainfo.getEncodedValidity());
    storeData(aCainfo);
    setKeepExpiredCertsOnCRL(aCainfo.getKeepExpiredCertsOnCRL());

    if (aCainfo.getCAToken() != null) {
      setCAToken(aCainfo.getCAToken());
    }
    setFinishUser(aCainfo.getFinishUser());
    setIncludeInHealthCheck(aCainfo.getIncludeInHealthCheck());
    setDoEnforceUniquePublicKeys(aCainfo.isDoEnforceUniquePublicKeys());
    setDoEnforceUniqueDistinguishedName(
        aCainfo.isDoEnforceUniqueDistinguishedName());
    setDoEnforceUniqueSubjectDNSerialnumber(
        aCainfo.isDoEnforceUniqueSubjectDNSerialnumber());
    setUseCertReqHistory(aCainfo.isUseCertReqHistory());
    setUseUserStorage(aCainfo.isUseUserStorage());
    setUseCertificateStorage(aCainfo.isUseCertificateStorage());
    setAcceptRevocationNonExistingEntry(
        aCainfo.isAcceptRevocationNonExistingEntry());
    List<Certificate> newcerts = aCainfo.getCertificateChain();
    if (newcerts != null && newcerts.size() > 0) {
      setCertificateChain(newcerts);
      Certificate cacert = newcerts.iterator().next();
      setExpireTime(CertTools.getNotAfter(cacert));
    }
    // Update or create extended CA services
    final Collection<ExtendedCAServiceInfo> infos =
        aCainfo.getExtendedCAServiceInfos();
    if (infos != null) {
      final Collection<ExtendedCAServiceInfo> newInfos = new ArrayList<>();
      Collection<Integer> extendedservicetypes =
          getExternalCAServiceTypes(); // Se we can add things to this
      for (ExtendedCAServiceInfo info : infos) {
        ExtendedCAService service = this.getExtendedCAService(info.getType());
        if (service == null) {
          if (log.isDebugEnabled()) {
            log.debug(
                "Creating new extended CA service of type: " + info.getType());
          }
          createExtendedCAService(info);
          extendedservicetypes.add(info.getType());
          newInfos.add(info);
        } else {
          if (log.isDebugEnabled()) {
            log.debug(
                "Updating extended CA service of type: " + info.getType());
          }
          service.update(cryptoToken, info, this, cceConfig);
          // the service's signing certificate might get
          // created at this point!
          setExtendedCAService(service);

          // Now read back the info object from the service.
          // This is necessary because the service's
          // signing certificate is
          // "lazy-created",
          // i.e. created when the service becomes active
          // the first time.
          final ExtendedCAServiceInfo newInfo =
              service.getExtendedCAServiceInfo();
          newInfos.add(newInfo);
        }
      }
      aCainfo.setExtendedCAServiceInfos(newInfos);
      data.put(EXTENDEDCASERVICES, extendedservicetypes);
    }

    if (aCainfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
      updateUninitializedCA(aCainfo);
    }

    this.cainfo = aCainfo;
  }

  private void storeData(final CAInfo aCainfo) {
      data.put(DESCRIPTION, aCainfo.getDescription());
      data.put(CRLPERIOD, Long.valueOf(aCainfo.getCRLPeriod()));
      data.put(DELTACRLPERIOD, Long.valueOf(aCainfo.getDeltaCRLPeriod()));
      data.put(CRLISSUEINTERVAL, Long.valueOf(aCainfo.getCRLIssueInterval()));
      data.put(CRLOVERLAPTIME, Long.valueOf(aCainfo.getCRLOverlapTime()));
      data.put(CRLPUBLISHERS, aCainfo.getCRLPublishers());
      data.put(VALIDATORS, aCainfo.getValidators());
      data.put(APPROVALS, aCainfo.getApprovals());
      data.put(
              USENOCONFLICTCERTIFICATEDATA,
              aCainfo.isUseNoConflictCertificateData());
      if (aCainfo.getCertificateProfileId() > 0) {
          data.put(
                  CERTIFICATEPROFILEID,
                  Integer.valueOf(aCainfo.getCertificateProfileId()));
      }
      if (aCainfo.getDefaultCertificateProfileId() > 0
              && !aCainfo.isUseCertificateStorage()) {
          data.put(
                  DEFAULTCERTIFICATEPROFILEID,
                  Integer.valueOf(aCainfo.getDefaultCertificateProfileId()));
      }
  }

  /**
   * Called when an uninitialized CA is updated, either from updateCA or from
   * other places in the code.
   *
   * <p>A few more values are also set in the overridden method in X509CA.
   *
   * @param aCainfo Info
   */
  public void updateUninitializedCA(final CAInfo aCainfo) {
    setSignedBy(aCainfo.getSignedBy());
  }

  /**
   * @param cryptoToken Token
   * @param publicKey provided public key. Will not have any precedence over
   *     subject.extendedInformation.certificateRequest
   * @param subject end entity information. If it contains certificateRequest
   *     under extendedInformation, it will be used instead of the provided
   *     RequestMessage and publicKey
   * @param onotBefore null or a custom date to use as notBefore date
   * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g.
   *     X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
   * @param encodedValidity requested validity as SimpleTime string or ISO8601
   *     date string (see ValidityDate.java).
   * @param config config
   * @return The newly created certificate
   * @throws Exception On error
   */
  public Certificate generateCertificate(
      final CryptoToken cryptoToken,
      final EndEntityInformation subject,
      final PublicKey publicKey,
      final int keyusage,
      final  Date onotBefore,
      final String encodedValidity,
      final CaCertConfig config)
      throws Exception {

    // Calculate the notAfter date
    Date notBefore;
    if (onotBefore == null) {
      notBefore = new Date();
    } else {
        notBefore = onotBefore;
    }
    final Date notAfter;
    if (StringUtils.isNotBlank(encodedValidity)) {
      notAfter = ValidityDate.getDate(encodedValidity, notBefore);
    } else {
      notAfter = null;
    }


    return generateCertificate(
        cryptoToken,
        subject,
        null,
        publicKey,
        keyusage,
        new CaCertValidity(
        notBefore,
        notAfter),
        config);
  }

  public static class CaCertValidity {
      /** Param. */
      private final Date notBefore;
      /** Param. */
      private final Date notAfter;

      /**
       * @param nb not before
       * @param na not after
       */
      public CaCertValidity(final Date nb, final Date na) {
          this.notBefore = nb;
          this.notAfter = na;
      }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

  }

  public static class CaCertConfig {
      /** Param. */
      private final CertificateProfile certProfile;
      /** Param. */
      private final Extensions extensions;
      /** Param. */
      private final String sequence;
      /** Param. */
      private final CertificateGenerationParams certGenParams;
      /** Param. */
      private final AvailableCustomCertificateExtensionsConfiguration cceConfig;
      /**
       * @param profile Profile
       * @param asequence Seq
       * @param conf Config
       */
      public CaCertConfig(final CertificateProfile profile,
              final String asequence,
              final AvailableCustomCertificateExtensionsConfiguration conf) {
          this.certProfile = profile;
          this.sequence = asequence;
          this.cceConfig = conf;
          this.extensions = null;
          this.certGenParams = null;
      }

      /**
       * @param profile Profile
       * @param ext Ext
       * @param asequence Seq
       * @param params Params
       * @param conf Config
       */
      public CaCertConfig(final CertificateProfile profile,
              final Extensions ext,
              final String asequence,
              final CertificateGenerationParams params,
              final AvailableCustomCertificateExtensionsConfiguration conf) {
          this.certProfile = profile;
          this.sequence = asequence;
          this.cceConfig = conf;
          this.extensions = ext;
          this.certGenParams = params;
      }

      /**
       * @param profile Profile
       * @param ext Ext
       * @param asequence Seq
       * @param conf Config
       */
      public CaCertConfig(final CertificateProfile profile,
              final Extensions ext,
              final String asequence,
              final AvailableCustomCertificateExtensionsConfiguration conf) {
          this.certProfile = profile;
          this.sequence = asequence;
          this.cceConfig = conf;
          this.extensions = ext;
          this.certGenParams = null;
      }

    /**
     * @return the certProfile
     */
    public CertificateProfile getCertProfile() {
        return certProfile;
    }

    /**
     * @return the extensions
     */
    public Extensions getExtensions() {
        return extensions;
    }

    /**
     * @return the sequence
     */
    public String getSequence() {
        return sequence;
    }

    /**
     * @return the certGenParams
     */
    public CertificateGenerationParams getCertGenParams() {
        return certGenParams;
    }

    /**
     * @return the cceConfig
     */
    public AvailableCustomCertificateExtensionsConfiguration getCceConfig() {
        return cceConfig;
    }



  }

  /**
   * @param cryptoToken Token
   * @param request provided request message containing optional information,
   *     and will be set with the signing key and provider. If the certificate
   *     profile allows subject DN override this value will be used instead of
   *     the value from subject.getDN. Its public key is going to be used if
   *     publicKey == null &amp;&amp;
   *     subject.extendedInformation.certificateRequest == null. Can be null.
   * @param publicKey provided public key which will have precedence over public
   *     key from the provided RequestMessage but not over
   *     subject.extendedInformation.certificateRequest
   * @param subject end entity information. If it contains certificateRequest
   *     under extendedInformation, it will be used instead of the provided
   *     RequestMessage and publicKey
   * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g.
   *     X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
   * @param validity Validity
   * @param config  Config
   *
   * @return the generated certificate
   * @throws CryptoTokenOfflineException if the crypto token was unavailable
   * @throws CertificateExtensionException if any of the certificate extensions
   *     were invalid
   * @throws CertificateCreateException if an error occurred when trying to
   *     create a certificate.
   * @throws OperatorCreationException if CA's private key contained an unknown
   *     algorithm or provider
   * @throws IllegalNameException if the name specified in the certificate
   *     request contains illegal characters
   * @throws IllegalValidityException if validity was invalid
   * @throws InvalidAlgorithmException if the signing algorithm in the
   *     certificate profile (or the CA Token if not found) was invalid.
   * @throws CAOfflineException if the CA wasn't active
   * @throws SignatureException if the CA's certificate's and request's
   *     certificate's and signature algorithms differ
   * @throws IllegalKeyException if the using public key is not allowed to be
   *     used by specified certProfile
   */
  public abstract Certificate generateCertificate(
      CryptoToken cryptoToken,
      EndEntityInformation subject,
      RequestMessage request,
      PublicKey publicKey,
      int keyusage,
      CaCertValidity validity,
      CaCertConfig config)
      throws CryptoTokenOfflineException, CAOfflineException,
          InvalidAlgorithmException, IllegalValidityException,
          IllegalNameException, OperatorCreationException,
          CertificateCreateException, CertificateExtensionException,
          SignatureException, IllegalKeyException;

  /**
   * CRL holder .
   *
   * @param cryptoToken Token
   * @param certs Certificates
   * @param crlnumber CRl number
   * @return CRL holder
   * @throws Exception Fail
   */
  public abstract X509CRLHolder generateCRL(
      CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber)
      throws Exception;

  /**
   * CRL holder .
   *
   * @param cryptoToken Token
   * @param certs Certificates
   * @param crlnumber CRl number
   * @param basecrlnumber Base CRL
   * @return CRL holder
   * @throws Exception Fail
   */
  public abstract X509CRLHolder generateDeltaCRL(
      CryptoToken cryptoToken,
      Collection<RevokedCertInfo> certs,
      int crlnumber,
      int basecrlnumber)
      throws Exception;

  /**
   * Create a signed PKCS#7 / CMS message.
   *
   * @param cryptoToken Token
   * @param cert Certificate
   * @param includeChain True to include all certs
   * @return A DER-encoded PKCS#7
   * @throws SignRequestSignatureException if the certificate doesn't seem to be
   *     signed by this CA
   * @see CertTools#createCertsOnlyCMS(List) for how to craete a certs-only
   *     PKCS7/CMS
   */
  public abstract byte[] createPKCS7(
      CryptoToken cryptoToken, X509Certificate cert, boolean includeChain)
      throws SignRequestSignatureException;

  /**
   * Creates a roll over PKCS7 for the next CA certificate, signed with the
   * current CA key. Used by ScepServlet.
   *
   * @param cryptoToken Token
   * @return Encoded signed certificate chain, suitable for use in SCEP.
   * @throws SignRequestSignatureException if the certificate doesn't seem to be
   *     signed by this CA
   */
  public abstract byte[] createPKCS7Rollover(CryptoToken cryptoToken)
      throws SignRequestSignatureException;

  /**
   * Creates a certificate signature request (CSR), that can be sent to an
   * external Root CA. Request format can vary depending on the type of CA. For
   * X509 CAs PKCS#10 requests are created, for CVC CAs CVC requests are
   * created.
   *
   * @param cryptoToken Token
   * @param attributes PKCS10 attributes to be included in the request, a
   *     Collection of ASN1Encodable objects, ready to put in the request. Can
   *     be null.
   * @param signAlg the signature algorithm used by the CA
   * @param cacert the CAcertficate the request is targeted for, may be used or
   *     ignored by implementation depending on the request type created.
   * @param signatureKeyPurpose which CA token key pair should be used to create
   *     the request, normally SecConst.CAKEYPURPOSE_CERTSIGN but can also be
   *     SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
   * @param certificateProfile Certificate profile to use for CA-type specific
   *     purposes, such as CV Certificate Extensions.
   * @param cceConfig containing a list of available custom certificate
   *     extensions
   * @return byte array with binary encoded request
   * @throws CryptoTokenOfflineException if the crypto token is offline
   * @throws CertificateExtensionException if there was a problem constructing a
   *     certificate extension.
   */
  public abstract byte[] createRequest(
      CryptoToken cryptoToken,
      Collection<ASN1Encodable> attributes,
      String signAlg,
      Certificate cacert,
      int signatureKeyPurpose,
      CertificateProfile certificateProfile,
      AvailableCustomCertificateExtensionsConfiguration cceConfig)
      throws CryptoTokenOfflineException, CertificateExtensionException;

  /**
   * Signing request.
   *
   * @param cryptoToken Crypyo token
   * @param request requet
   * @return Request as byte array
   * @throws CryptoTokenOfflineException On errror
   */
  public abstract byte[] createAuthCertSignRequest(
      CryptoToken cryptoToken, byte[] request)
      throws CryptoTokenOfflineException;

  /**
   * General encryption method used to encrypt using a CA.
   *
   * @param cryptoToken token
   * @param data the data to encrypt
   * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
   * @return encrypted data
   * @throws CryptoTokenOfflineException If crypto token is off-line so
   *     encryption key can not be used.
   * @throws CMSException In case parsing/encryption of CMS data fails.
   * @throws NoSuchProviderException If encryption provider is not available.
   * @throws NoSuchAlgorithmException If desired encryption algorithm is not
   *     available.
   * @throws IOException In case reading/writing data streams failed during
   *     encryption
   */
  public abstract byte[] encryptData(
      CryptoToken cryptoToken, byte[] data, int keyPurpose)
      throws CryptoTokenOfflineException, NoSuchAlgorithmException,
          NoSuchProviderException, CMSException, IOException;

  /**
   * General encryption method used to decrypt using a CA.
   *
   * @param cryptoToken Token
   * @param data the data to decrypt
   * @param cAKeyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
   * @return decrypted data
   * @throws CMSException In case parsing/decryption of CMS data fails.
   * @throws CryptoTokenOfflineException If crypto token is off-line so
   *     decryption key can not be used.
   */
  public abstract byte[] decryptData(
      CryptoToken cryptoToken, byte[] data, int cAKeyPurpose)
      throws CMSException, CryptoTokenOfflineException;

  // Methods used with extended services
  /**
   * Initializes the ExtendedCAService.
   *
   * @param cryptoToken the cryptotoken used to initiate the service
   * @param type the type of the extended key service
   * @param ca the CA used to initiate the service
   * @param cceConfig containing a list of available custom certificate
   *     extensions
   * @throws Exception On error
   */
  public void initExtendedService(
      final CryptoToken cryptoToken,
      final int type,
      final CA ca,
      final AvailableCustomCertificateExtensionsConfiguration cceConfig)
      throws Exception {
    ExtendedCAService service = getExtendedCAService(type);
    if (service != null) {
      service.init(cryptoToken, ca, cceConfig);
      setExtendedCAService(service);
    }
  }

  /**
   * Method used to retrieve information about the service.
   *
   * @param type type
   * @return info
   */
  public ExtendedCAServiceInfo getExtendedCAServiceInfo(final int type) {
    ExtendedCAServiceInfo ret = null;
    ExtendedCAService service = getExtendedCAService(type);
    if (service != null) {
      ret = service.getExtendedCAServiceInfo();
    }
    return ret;
  }

  /**
   * Method used to perform the service.
   *
   * @param cryptoToken token
   * @param request request
   * @return service response
   * @throws ExtendedCAServiceRequestException If there was a problem with the
   *     request
   * @throws IllegalExtendedCAServiceRequestException If the request is illegal
   * @throws ExtendedCAServiceNotActiveException If the service is inactive or
   *     not found
   * @throws OperatorCreationException If creation fails
   * @throws CertificateException Ig there was a problem with the certificate
   * @throws CertificateEncodingException if there was a problem constructing a
   *     certificate extension.
   */
  public ExtendedCAServiceResponse extendedService(
      final CryptoToken cryptoToken, final ExtendedCAServiceRequest request)
      throws ExtendedCAServiceRequestException,
          IllegalExtendedCAServiceRequestException,
          ExtendedCAServiceNotActiveException, CertificateEncodingException,
          CertificateException, OperatorCreationException {
    ExtendedCAService service = getExtendedCAService(request.getServiceType());
    if (service == null) {
      final String msg =
          "Extended CA service is null for service request: "
              + request.getClass().getName();
      log.error(msg);
      throw new IllegalExtendedCAServiceRequestException();
    }
    // Enrich request with CA in order for the service to be
    // able to use CA keys and// certificates
    service.setCA(this);
    return service.extendedService(cryptoToken, request);
  }

  /**
   * Get extended service.
   *
   * @param type Type
   * @return Service
   */
  @SuppressWarnings("rawtypes")
  public HashMap getExtendedCAServiceData(final int type) {
    HashMap serviceData = (HashMap) data.get(EXTENDEDCASERVICE + type);
    return serviceData;
  }

  /**
   * Set extended service.
   *
   * @param type Type
   * @param serviceData Data
   */
  public void setExtendedCAServiceData(
      final int type, @SuppressWarnings("rawtypes") final HashMap serviceData) {
    data.put(EXTENDEDCASERVICE + type, serviceData);
  }

  /**
   * Get extended service.
   *
   * @param type Type
   * @return Service
   */
  protected ExtendedCAService getExtendedCAService(final int type) {
    ExtendedCAService returnval = null;
    try {
      returnval = extendedcaservicemap.get(Integer.valueOf(type));
      if (returnval == null) {
        @SuppressWarnings("rawtypes")
        HashMap serviceData = getExtendedCAServiceData(type);
        if (serviceData != null) {
          // We must have run upgrade on the extended CA
          // services for this to work
          String implClassname =
              (String)
                  serviceData.get(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS);
          if (implClassname == null) {
            // We need this hardcoded implementation
            // classnames in order to be able to
            // upgrade extended services from before
            // See ECA-6341 and
            // UpgradeSessionBean.migrateDatabase500()
            log.info(
                "implementation classname is null for "
                    + "extended service type: "
                    + type
                    + ". Will try our known ones.");
            implClassname = setClassName(type, implClassname);
          }
          if (implClassname != null) {
            if (log.isDebugEnabled()) {
              log.debug(
                  "implementation classname for extended"
                      + " service type: "
                      + type
                      + " is "
                      + implClassname);
            }
            Class<?> implClass = Class.forName(implClassname);
            returnval =
                (ExtendedCAService)
                    implClass
                        .getConstructor(HashMap.class)
                        .newInstance(new Object[] {serviceData});
            extendedcaservicemap.put(Integer.valueOf(type), returnval);
          }
        } else {
          log.error(
              "Servicedata is null for "
                  + "extended CA service of type: "
                  + type);
        }
      }
    } catch (ClassNotFoundException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    } catch (IllegalArgumentException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    } catch (SecurityException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    } catch (InstantiationException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    } catch (IllegalAccessException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    } catch (InvocationTargetException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    } catch (NoSuchMethodException e) {
      log.warn(
          "Extended CA service of type " + type + " can not get created: ", e);
    }
    return returnval;
  }

private String setClassName(final int type, final String classname) {
    String implClassname = classname;
    switch (type) {
      case 2: // Old XKMSCAService that should not be used
        log.info(
            "Found an XKMS CA service type. Will"
                + " not create the deprecated service.");
        break;
      case ExtendedCAServiceTypeConstants.TYPE_CMSEXTENDEDSERVICE:
        implClassname =
            "org.ejbca.core.model.ca.caadmin."
                + "extendedcaservices.CmsCAService";
        break;
      case ExtendedCAServiceTypeConstants.TYPE_HARDTOKENENCEXTENDEDSERVICE:
        implClassname =
            "org.ejbca.core.model.ca.caadmin."
                + "extendedcaservices"
                + ".HardTokenEncryptCAService";
        break;
      case ExtendedCAServiceTypeConstants.TYPE_KEYRECOVERYEXTENDEDSERVICE:
        implClassname =
            "org.ejbca.core.model.ca.caadmin."
                + "extendedcaservices.KeyRecoveryCAService";
        break;
      default:
        log.error(
            "implementation classname is null for "
                + "extended service type: "
                + type
                + ". Service not created.");
        break;
    }
    return implClassname;
}

  /**
   * Set extended service.
   *
   * @param extendedcaservice Service.
   */
  @SuppressWarnings("rawtypes")
  public void setExtendedCAService(final ExtendedCAService extendedcaservice) {
    ExtendedCAServiceInfo info = extendedcaservice.getExtendedCAServiceInfo();
    setExtendedCAServiceData(
        info.getType(), (HashMap) extendedcaservice.saveData());
    extendedcaservicemap.put(
        Integer.valueOf(info.getType()), extendedcaservice);
  }

  /**
   * Returns a Collection of ExternalCAServices (int) added to this CA.
   *
   * @return types
   */
  @SuppressWarnings("unchecked")
  public Collection<Integer> getExternalCAServiceTypes() {
    if (data.get(EXTENDEDCASERVICES) == null) {
      return new ArrayList<>();
    }
    return (Collection<Integer>) data.get(EXTENDEDCASERVICES);
  }

  /**
   * Method to upgrade new (or existing externacaservices). This method needs to
   * be called outside the regular upgrade since the CA isn't instantiated in
   * the regular upgrade.
   *
   * @return true/false
   */
  public abstract boolean upgradeExtendedCAServices();

  /**
   * Create a certificate with all the current CA certificate info, but signed
   * by the old issuer.
   *
   * @param cryptoToken token
   * @param createLinkCertificate create?
   * @param certProfile profile
   * @param cceConfig config
   * @param oldCaCert old cert
   * @throws CryptoTokenOfflineException on error
   */
  public abstract void createOrRemoveLinkCertificate(
      CryptoToken cryptoToken,
      boolean createLinkCertificate,
      CertificateProfile certProfile,
      AvailableCustomCertificateExtensionsConfiguration cceConfig,
      Certificate oldCaCert)
      throws CryptoTokenOfflineException;

  /**
   * Store the latest link certificate in this object.
   *
   * @param encodedLinkCertificate certificate
   */
  protected void updateLatestLinkCertificate(
      final byte[] encodedLinkCertificate) {
    if (encodedLinkCertificate == null) {
      data.remove(LATESTLINKCERTIFICATE);
    } else {
      try {
        data.put(
            LATESTLINKCERTIFICATE,
            new String(Base64.encode(encodedLinkCertificate), "UTF8"));
      } catch (final UnsupportedEncodingException e) {
        throw new CesecoreRuntimeException(e); // Lack of UTF8 would be fatal.
      }
    }
  }

  /** @return the CA latest link certificate or null */
  public byte[] getLatestLinkCertificate() {
    if (data.get(LATESTLINKCERTIFICATE) == null) {
      return null;
    }
    try {
      return Base64.decode(
          ((String) data.get(LATESTLINKCERTIFICATE)).getBytes("UTF8"));
    } catch (final UnsupportedEncodingException e) {
      throw new CesecoreRuntimeException(e); // Lack of UTF8 would be fatal.
    }
  }
}
