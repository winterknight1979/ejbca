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

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * Holds non sensitive information about a CA.
 *
 * @version $Id: CAInfo.java 29149 2018-06-07 14:42:22Z andrey_s_helmes $
 */
public abstract class CAInfo implements Serializable {

  private static final long serialVersionUID = 2L;
  /** Type. */
  public static final int CATYPE_X509 = 1;
  /** Type. */
  public static final int CATYPE_CVC = 2;

  /** Constants indicating that the CA is selfsigned. */
  public static final int SELFSIGNED = 1;
  /** Constant indicating that the CA is signed by an external CA. */
  public static final int SIGNEDBYEXTERNALCA = 2;

  /**
   * Constant indicating where the special caid border is. All CAs with CA id
   * not below this value should be created
   */
  public static final int SPECIALCAIDBORDER = 10;
  /** DN. */
  protected String subjectdn;
  /** ID. */
  protected int caid;
  /** Name. */
  protected String name;
  /**
   * CAConstants.CA_ACTIVE etc, 0 means not defined (i.e. not updated when
   * editing CA).
   */
  protected int status = 0;
  /** Validity. */
  protected String encodedValidity;
  /** Time. */
  protected Date expiretime;
  /** Time. */
  protected Date updatetime;
  /** CATYPE_X509 or CATYPE_CVC. */
  protected int catype;
  /** A CAId or CAInfo.SELFSIGNED. */
  protected int signedby;

  /** Chain. */
  protected Collection<CertificateWrapper> certificatechain;
  /** Chain. */
  protected Collection<CertificateWrapper> renewedcertificatechain;
  /** Chain. */
  protected transient List<Certificate> certificatechainCached;
  /** Chain. */
  protected transient Collection<Certificate> renewedcertificatechainCached;
  /** Token. */
  protected CAToken catoken;
  /** Desc. */
  protected String description;
  /** Reason. */
  protected int revocationReason;
  /** Reason. */
  protected Date revocationDate;
  /** Profile. */
  protected int certificateprofileid;
  /** Profile. */
  protected int defaultCertificateProfileId;
  /** Default value 1 day. */
  protected long crlperiod = 1 * SimpleTime.MILLISECONDS_PER_DAY;
  /** Default value 0. */
  protected long crlIssueInterval = 0;
  /** Default value 10 minutes. */
  protected long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_MINUTE;
  /** Default value 0 = disabled. */
  protected long deltacrlperiod = 0;

  /** Publishers. */
  protected Collection<Integer> crlpublishers;
  /** Validators. */
  protected Collection<Integer> validators;
  /** Expired. */
  protected boolean keepExpiredCertsOnCRL = false;
  /** User. */
  protected boolean finishuser;
  /** Info. */
  protected Collection<ExtendedCAServiceInfo> extendedcaserviceinfos;
  /** Conflict. */
  protected boolean useNoConflictCertificateData =
      false; // By Default we use normal certificate data table.

  /**
   * @deprecated since 6.8.0, where approval settings and profiles became
   *     interlinked.
   */
  @Deprecated private Collection<Integer> approvalSettings;
  /**
   * @deprecated since 6.8.0, where approval settings and profiles became
   *     interlinked.
   */
  @Deprecated private int approvalProfile;

  /**
   * @deprecated since 6.6.0, use the appropriate approval profile instead
   *     Needed for a while in order to be able to import old statedumps from
   *     6.5 and earlier
   */
  @Deprecated protected int numOfReqApprovals;

  /** Approvals. */
  private LinkedHashMap<ApprovalRequestType, Integer> approvals;

  /** Healthcheck. */
  protected boolean includeInHealthCheck;
  /** PK. */
  protected boolean doEnforceUniquePublicKeys;
  /** DN. */
  protected boolean doEnforceUniqueDistinguishedName;
  /** SN. */
  protected boolean doEnforceUniqueSubjectDNSerialnumber;
  /** History. */
  protected boolean useCertReqHistory;
  /** Storage. */
  protected boolean useUserStorage;
  /** Storage. */
  protected boolean useCertificateStorage;
  /** Accept. */
  protected boolean acceptRevocationNonExistingEntry;

  /** @return DN */
  public String getSubjectDN() {
    return subjectdn;
  }

  /** @param aSubjectDn DN */
  public void setSubjectDN(final String aSubjectDn) {
    this.subjectdn =
        CertTools.stringToBCDNString(StringTools.strip(aSubjectDn));
  }

  /** @return ID */
  public int getCAId() {
    return this.caid;
  }

  /** @param aCaid ID */
  public void setCAId(final int aCaid) {
    this.caid = aCaid;
  }

  /** @return name */
  public String getName() {
    return this.name;
  }

  /** @param aName name */
  public void setName(final String aName) {
    this.name = aName;
  }

  /**
   * CAConstants.CA_ACTIVE etc, 0 means not defined (i.e. not updated when
   * editing CA)
   *
   * @return status code
   */
  public int getStatus() {
    return status;
  }

  /** @param aStatus status */
  public void setStatus(final int aStatus) {
    this.status = aStatus;
  }

  /** @return CAInfo.CATYPE_X509 or CAInfo.CATYPE_CVC */
  public int getCAType() {
    return catype;
  }

  /** @param aCatype type */
  public void setCAType(final int aCatype) {
    this.catype = aCatype;
  }

  /** @return type */
  public String getCaTypeAsString() {
    if (catype == CAInfo.CATYPE_CVC) {
      return "CVC";
    }
    if (catype == CAInfo.CATYPE_X509) {
      return "X.509";
    }
    return String.valueOf(catype);
  }

  /** @return A CAId or CAInfo.SELFSIGNED, CAInfo.SIGNEDBYEXTERNALCA etc */
  public int getSignedBy() {
    return signedby;
  }

  /** @param aSignedby signer */
  public void setSignedBy(final int aSignedby) {
    this.signedby = aSignedby;
  }

  /** @param aEncodedValidity validity */
  public void setEncodedValidity(final String aEncodedValidity) {
    this.encodedValidity = aEncodedValidity;
  }

  /** @return validity */
  public String getEncodedValidity() {
    return encodedValidity;
  }

  /** @return time */
  public Date getExpireTime() {
    return this.expiretime;
  }

  /** @param aExpiretime time */
  public void setExpireTime(final Date aExpiretime) {
    this.expiretime = aExpiretime;
  }

  /** @return date */
  public Date getUpdateTime() {
    return this.updatetime;
  }

  /** @param aUpdatetime time */
  public void setUpdateTime(final Date aUpdatetime) {
    this.updatetime = aUpdatetime;
  }

  /**
   * Retrieves the certificate chain for the CA. The returned certificate chain
   * MUST have the RootCA certificate in the last position and the CAs
   * certificate in the first.
   *
   * @return chain
   */
  public List<Certificate> getCertificateChain() {
    if (certificatechain == null) {
      return null;
    }
    if (certificatechainCached == null) {
      certificatechainCached = EJBTools.unwrapCertCollection(certificatechain);
    }
    return certificatechainCached;
  }

  /** @param aCertificatechain chain */
  public void setCertificateChain(final List<Certificate> aCertificatechain) {
    this.certificatechainCached = aCertificatechain;
    this.certificatechain = EJBTools.wrapCertCollection(aCertificatechain);
  }

  /** @return chain */
  public Collection<Certificate> getRenewedCertificateChain() {
    if (renewedcertificatechain == null) {
      return null;
    }
    if (renewedcertificatechainCached == null) {
      renewedcertificatechainCached =
          EJBTools.unwrapCertCollection(renewedcertificatechain);
    }
    return renewedcertificatechainCached;
  }

  /** @param aCertificatechain chain */
  public void setRenewedCertificateChain(
     final Collection<Certificate> aCertificatechain) {
    this.renewedcertificatechainCached = aCertificatechain;
    this.renewedcertificatechain =
        EJBTools.wrapCertCollection(aCertificatechain);
  }

  /** @return token */
  public CAToken getCAToken() {
    return this.catoken;
  }

  /** @param aCatoken token */
  public void setCAToken(final CAToken aCatoken) {
    this.catoken = aCatoken;
  }

  /** @return description */
  public String getDescription() {
    return this.description;
  }

  /** @param aDescription desc */
  public void setDescription(final String aDescription) {
    this.description = aDescription;
  }

  /** @return reason */
  public int getRevocationReason() {
    return this.revocationReason;
  }

  /** @param aRevocationReason reason */
  public void setRevocationReason(final int aRevocationReason) {
    this.revocationReason = aRevocationReason;
  }

  /** @return date */
  public Date getRevocationDate() {
    return this.revocationDate;
  }

  /** @param aRevocationDate date */
  public void setRevocationDate(final Date aRevocationDate) {
    this.revocationDate = aRevocationDate;
  }

  /** @param aCertificateprofileid ID */
  public void setCertificateProfileId(final int aCertificateprofileid) {
    this.certificateprofileid = aCertificateprofileid;
  }

  /** @return the ID of the certificate profile for this CA */
  public int getCertificateProfileId() {
    return this.certificateprofileid;
  }

  /**
   * @return the id of default cetificate profile for certificates this CA
   *     issues
   */
  public int getDefaultCertificateProfileId() {
    return defaultCertificateProfileId;
  }
  /** @param aDefaultCertificateProfileId ID */
  public void setDefaultCertificateProfileId(
          final int aDefaultCertificateProfileId) {
    this.defaultCertificateProfileId = aDefaultCertificateProfileId;
  }

  /** @return period */
  public long getCRLPeriod() {
    return crlperiod;
  }

  /** @param aCrlperiod period */
  public void setCRLPeriod(final long aCrlperiod) {
    this.crlperiod = aCrlperiod;
  }

  /** @return period */
  public long getDeltaCRLPeriod() {
    return deltacrlperiod;
  }

  /** @param aDeltacrlperiod period */
  public void setDeltaCRLPeriod(final long aDeltacrlperiod) {
    this.deltacrlperiod = aDeltacrlperiod;
  }

  /** @return interval */
  public long getCRLIssueInterval() {
    return crlIssueInterval;
  }

  /** @param crlissueinterval interval */
  public void setCRLIssueInterval(final long crlissueinterval) {
    this.crlIssueInterval = crlissueinterval;
  }

  /** @return time */
  public long getCRLOverlapTime() {
    return crlOverlapTime;
  }

  /** @param crloverlaptime time */
  public void setCRLOverlapTime(final long crloverlaptime) {
    this.crlOverlapTime = crloverlaptime;
  }

  /** @return publishers */
  public Collection<Integer> getCRLPublishers() {
    return crlpublishers;
  }

  /** @param aCrlpublishers publihers */
  public void setCRLPublishers(final Collection<Integer> aCrlpublishers) {
    this.crlpublishers = aCrlpublishers;
  }

  /** @return validators */
  public Collection<Integer> getValidators() {
    if (validators == null) {
      // Make sure we never return null for upgraded CAs, avoiding possible NPE
      return new ArrayList<Integer>();
    }
    return validators;
  }

  /** @param aValidators validators */
  public void setValidators(final Collection<Integer> aValidators) {
    this.validators = aValidators;
  }

  /** @return bool */
  public boolean getKeepExpiredCertsOnCRL() {
    return this.keepExpiredCertsOnCRL;
  }

  /** @param aKeepExpiredCertsOnCRL bool */
  public void setKeepExpiredCertsOnCRL(final boolean aKeepExpiredCertsOnCRL) {
    this.keepExpiredCertsOnCRL = aKeepExpiredCertsOnCRL;
  }

  /** @return user */
  public boolean getFinishUser() {
    return finishuser;
  }

  /** @param aFinishuser user */
  public void setFinishUser(final boolean aFinishuser) {
    this.finishuser = aFinishuser;
  }

  /** @return bool */
  public boolean getIncludeInHealthCheck() {
    return this.includeInHealthCheck;
  }

  /** @param aIncludeInHealthCheck bool */
  public void setIncludeInHealthCheck(final boolean aIncludeInHealthCheck) {
    this.includeInHealthCheck = aIncludeInHealthCheck;
  }

  /**
   * Lists the extended CA services.
   *
   * @return Collection of ExtendedCAServiceInfo
   */
  public Collection<ExtendedCAServiceInfo> getExtendedCAServiceInfos() {
    return this.extendedcaserviceinfos;
  }

  /** @param aExtendedcaserviceinfos info */
  public void setExtendedCAServiceInfos(
     final  Collection<ExtendedCAServiceInfo> aExtendedcaserviceinfos) {
    this.extendedcaserviceinfos = aExtendedcaserviceinfos;
  }

  /**
   * @return a map of approvals, mapped as approval setting (as defined in this
   *     class) : approval profile ID. Never returns null.
   */
  public Map<ApprovalRequestType, Integer> getApprovals() {
    return approvals;
  }

  /** @param aApprovals approvals */
  public void setApprovals(final Map<ApprovalRequestType, Integer> aApprovals) {
    LinkedHashMap<ApprovalRequestType, Integer> nApprovals;
    if (aApprovals == null) {
      nApprovals = new LinkedHashMap<ApprovalRequestType, Integer>();
    } else {
        nApprovals
          = new LinkedHashMap<ApprovalRequestType, Integer>(aApprovals);
    }
    this.approvals = nApprovals;
  }

  /**
   * Returns the ID of an approval profile.
   *
   * @return profilw
   * @deprecated since 6.8.0. Use getApprovals() instead;
   */
  @Deprecated
  public int getApprovalProfile() {
    return approvalProfile;
  }

  /**
   * Sets the ID of an approval profile.
   *
   * @param approvalProfileID ID
   * @deprecated since 6.8.0. Use setApprovals() instead;
   */
  @Deprecated
  public void setApprovalProfile(final int approvalProfileID) {
    this.approvalProfile = approvalProfileID;
  }

  /**
   * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
   * action that requires approvals, default none.
   *
   * <p>Never null
   *
   * @return settings
   * @deprecated since 6.8.0. Use getApprovals() instead;
   */
  @Deprecated
  public Collection<Integer> getApprovalSettings() {
    return approvalSettings;
  }

  /**
   * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action
   * that requires approvals.
   *
   * @param aapprovalSettings settings
   * @deprecated since 6.8.0. Use getApprovals() instead;
   */
  @Deprecated
  public void setApprovalSettings(final Collection<Integer> aapprovalSettings) {
    this.approvalSettings = aapprovalSettings;
  }

  /** @return true if the NoConflictCertificateData used. */
  public boolean isUseNoConflictCertificateData() {
    return this.useNoConflictCertificateData;
  }

  /**
   * @param auseNoConflictCertificateData true means that the
   *     NoConflictCertificateData will be used instead of CertificateData.
   */
  public void setUseNoConflictCertificateData(
      final boolean auseNoConflictCertificateData) {
    this.useNoConflictCertificateData = auseNoConflictCertificateData;
  }

  /**
   * @return true if the UserData used to issue a certificate should be kept in
   *     the database.
   */
  public boolean isUseCertReqHistory() {
    return this.useCertReqHistory;
  }

  /**
   * @param auseCertReqHistory true means that the UserData used at the time of
   *     certificate issuance should be kept in the database.
   */
  public void setUseCertReqHistory(final boolean auseCertReqHistory) {
    this.useCertReqHistory = auseCertReqHistory;
  }

  /**
   * @return true if the UserData used to issue a certificate should be kept in
   *     the database.
   */
  public boolean isUseUserStorage() {
    return this.useUserStorage;
  }

  /**
   * @param auseUserStorage true means that the latest UserData used to issue a
   *     certificate should be kept in the database.
   */
  public void setUseUserStorage(final boolean auseUserStorage) {
    this.useUserStorage = auseUserStorage;
  }

  /** @return true if the issued certificate should be kept in the database. */
  public boolean isUseCertificateStorage() {
    return this.useCertificateStorage;
  }

  /**
   * @param auseCertificateStorage true means that the issued certificate should
   *     be kept in the database.
   */
  public void setUseCertificateStorage(final boolean auseCertificateStorage) {
    this.useCertificateStorage = auseCertificateStorage;
  }

  /** @return true if revocation for non existing entries is accepted */
  public boolean isAcceptRevocationNonExistingEntry() {
    return acceptRevocationNonExistingEntry;
  }

  /**
   * @param aacceptRevocationNonExistingEntry true means that revocation for non
   *     existing entry is accepted.
   */
  public void setAcceptRevocationNonExistingEntry(
      final boolean aacceptRevocationNonExistingEntry) {
    this.acceptRevocationNonExistingEntry = aacceptRevocationNonExistingEntry;
  }

  /**
   * @return answer this: should this CA issue certificates to only one user
   *     with certificates from one specific key.
   */
  public boolean isDoEnforceUniquePublicKeys() {
    return this.doEnforceUniquePublicKeys;
  }

  /** @param adoEnforceUniquePublicKeys boolean */
  public void setDoEnforceUniquePublicKeys(
      final boolean adoEnforceUniquePublicKeys) {
    this.doEnforceUniquePublicKeys = adoEnforceUniquePublicKeys;
  }

  /**
   * @return answer this: should this CA issue certificates to only one user of
   *     a specific subjectDN serialnumber.
   */
  public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
    return this.doEnforceUniqueSubjectDNSerialnumber;
  }

  /** @param adoEnforceUniqueSubjectDNSN boolean */
  public void setDoEnforceUniqueSubjectDNSerialnumber(
      final boolean adoEnforceUniqueSubjectDNSN) {
    this.doEnforceUniqueSubjectDNSerialnumber = adoEnforceUniqueSubjectDNSN;
  }

  /** @param adoEnforceUniqueDistinguishedName boolean */
  public void setDoEnforceUniqueDistinguishedName(
      final boolean adoEnforceUniqueDistinguishedName) {
    this.doEnforceUniqueDistinguishedName = adoEnforceUniqueDistinguishedName;
  }

  /**
   * @return answer this: should this CA issue certificates to only one user
   *     with certificates with a specific subject DN.
   */
  public boolean isDoEnforceUniqueDistinguishedName() {
    return this.doEnforceUniqueDistinguishedName;
  }
}
