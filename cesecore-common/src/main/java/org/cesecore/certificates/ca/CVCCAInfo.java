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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * Holds non-sensitive information about a CVC CA (Card Verifiable Certificate).
 *
 * @version $Id: CVCCAInfo.java 34456 2020-02-06 18:36:20Z anatom $
 */
public class CVCCAInfo extends CAInfo {

  private static final long serialVersionUID = 2L;

  /**
   * This constructor can be used when creating a CA. This constructor uses
   * defaults for the fields that are not specified.
   *
   * @param subjectdn DN
   * @param name name
   * @param status status
   * @param certificateprofileid ID
   * @param encodedValidity Validity
   * @param signedby signer
   * @param certificatechain chain
   * @param catoken token
   */
  public CVCCAInfo(
      final String subjectdn,
      final String name,
      final int status,
      final int certificateprofileid,
      final String encodedValidity,
      final int signedby,
      final List<Certificate> certificatechain,
      final CAToken catoken) {
    this(
        subjectdn,
        name,
        status,
        new Date(),
        certificateprofileid,
        0, // defaultCertprofileId
        encodedValidity,
        null, // expire time
        CAInfo.CATYPE_CVC,
        signedby,
        certificatechain, // Certificate chain
        catoken, // CA token
        "", // Description
        -1, // Revocation reason
        null, // Revocation date
        1 * SimpleTime.MILLISECONDS_PER_DAY, // CRL period
        0L, // CRL issue interval
        10 * SimpleTime.MILLISECONDS_PER_MINUTE, // CRL overlap time
        0L, // Delta CRL period
        new ArrayList<Integer>(), // CRL publishers
        new ArrayList<Integer>(), // Key validators
        true, // Finish user
        new ArrayList<ExtendedCAServiceInfo>(), // Extended CA services
        new HashMap<ApprovalRequestType, Integer>(),
        true, // includeInHealthCheck
        true, // isDoEnforceUniquePublicKeys
        true, // isDoEnforceUniqueDistinguishedName
        false, // isDoEnforceUniqueSubjectDNSerialnumber
        false, // useCertReqHistory
        true, // useUserStorage
        true, // useCertificateStorage
        false // acceptRevocationNonExistingEntry
        );
  }

  /**
   * Constructor that should be used when creating CA and retrieving CA info.
   * Please use the shorter form if you do not need to set all of the values.
   *
   * @param subjectDn DN
   * @param name Name
   * @param status Status
   * @param updateTime Update
   * @param certificateprofileid ID
   * @param defaultCertprofileId ID
   * @param encodedValidity Validity
   * @param expiretime Expiry
   * @param catype Type of CA
   * @param signedBy Signer
   * @param certificatechain Chain
   * @param catoken Token
   * @param description Description
   * @param revocationReason Reason for revoking
   * @param revocationDate Date of revoking
   * @param crlperiod CRL period
   * @param crlIssueInterval CRL Issue interval
   * @param crlOverlapTime CRL Overlap
   * @param deltacrlperiod CRL change
   * @param crlpublishers Publisher of CRL
   * @param keyValidators Validators
   * @param finishuser boolean
   * @param extendedcaserviceinfos info
   * @param approvals approvals
   * @param includeInHealthCheck bool
   * @param aDoEnforceUniquePublicKeys bool
   * @param aDoEnforceUniqueDistinguishedName bool
   * @param aDoEnforceUniqueSubjectDNSerialnumber bool
   * @param aUseCertReqHistory bool
   * @param aUseUserStorage bool
   * @param aUseCertificateStorage bool
   * @param aAcceptRevocationNonExistingEntry bool
   */
  public CVCCAInfo(
      final String subjectDn,
      final String name,
      final int status,
      final Date updateTime,
      final int certificateprofileid,
      final int defaultCertprofileId,
      final String encodedValidity,
      final Date expiretime,
      final int catype,
      final int signedBy,
      final List<Certificate> certificatechain,
      final CAToken catoken,
      final String description,
      final int revocationReason,
      final Date revocationDate,
      final long crlperiod,
      final long crlIssueInterval,
      final long crlOverlapTime,
      final long deltacrlperiod,
      final Collection<Integer> crlpublishers,
      final Collection<Integer> keyValidators,
      final boolean finishuser,
      final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos,
      final Map<ApprovalRequestType, Integer> approvals,
      final boolean includeInHealthCheck,
      final boolean aDoEnforceUniquePublicKeys,
      final boolean aDoEnforceUniqueDistinguishedName,
      final boolean aDoEnforceUniqueSubjectDNSerialnumber,
      final boolean aUseCertReqHistory,
      final boolean aUseUserStorage,
      final boolean aUseCertificateStorage,
      final boolean aAcceptRevocationNonExistingEntry) {
    this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectDn));
    this.caid = CertTools.stringToBCDNString(this.subjectdn).hashCode();
    this.name = name;
    this.status = status;
    this.updatetime = updateTime;
    setEncodedValidity(encodedValidity);
    this.expiretime = expiretime;
    this.catype = catype;
    this.signedby = signedBy;
    setCertificateChain(certificatechain);
    this.catoken = catoken;
    this.description = description;
    this.revocationReason = revocationReason;
    this.revocationDate = revocationDate;
    this.crlperiod = crlperiod;
    this.crlIssueInterval = crlIssueInterval;
    this.crlOverlapTime = crlOverlapTime;
    this.deltacrlperiod = deltacrlperiod;
    this.crlpublishers = crlpublishers;
    this.validators = keyValidators;
    this.finishuser = finishuser;
    this.certificateprofileid = certificateprofileid;
    this.defaultCertificateProfileId = defaultCertprofileId;
    this.extendedcaserviceinfos = extendedcaserviceinfos;
    setApprovals(approvals);
    this.includeInHealthCheck = includeInHealthCheck;
    this.doEnforceUniquePublicKeys = aDoEnforceUniquePublicKeys;
    this.doEnforceUniqueDistinguishedName = aDoEnforceUniqueDistinguishedName;
    this.doEnforceUniqueSubjectDNSerialnumber =
        aDoEnforceUniqueSubjectDNSerialnumber;
    this.useCertReqHistory = aUseCertReqHistory;
    this.useUserStorage = aUseUserStorage;
    this.useCertificateStorage = aUseCertificateStorage;
    this.acceptRevocationNonExistingEntry = aAcceptRevocationNonExistingEntry;
  }

  /**
   * Constructor that should be used when updating CA data. Used by the web. Jsp
   * and stuff like that.
   *
   * @param caid CA ID
   * @param encodedValidity Validity
   * @param catoken Token
   * @param description Description
   * @param crlperiod CRL period
   * @param crlIssueInterval CRL Issue
   * @param crlOverlapTime CRL Overlap
   * @param deltacrlperiod CRL Delta
   * @param crlpublishers CRL Publisher
   * @param keyValidators Validators
   * @param finishuser bool
   * @param extendedcaserviceinfos info
   * @param approvals approvals
   * @param includeInHealthCheck bool
   * @param aDoEnforceUniquePublicKeys bool
   * @param aDoEnforceUniqueDistinguishedName bool
   * @param aDoEnforceUniqueSubjectDNSerialnumber bool
   * @param aUseCertReqHistory bool
   * @param aUseUserStorage bool
   * @param aUseCertificateStorage bool
   * @param aAcceptRevocationNonExistingEntry bool
   * @param defaultCertprofileId ID
   */
  public CVCCAInfo(
      final int caid,
      final String encodedValidity,
      final CAToken catoken,
      final String description,
      final long crlperiod,
      final long crlIssueInterval,
      final long crlOverlapTime,
      final long deltacrlperiod,
      final Collection<Integer> crlpublishers,
      final Collection<Integer> keyValidators,
      final boolean finishuser,
      final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos,
      final Map<ApprovalRequestType, Integer> approvals,
      final boolean includeInHealthCheck,
      final boolean aDoEnforceUniquePublicKeys,
      final boolean aDoEnforceUniqueDistinguishedName,
      final boolean aDoEnforceUniqueSubjectDNSerialnumber,
      final boolean aUseCertReqHistory,
      final boolean aUseUserStorage,
      final boolean aUseCertificateStorage,
      final boolean aAcceptRevocationNonExistingEntry,
      final int defaultCertprofileId) {
    this.caid = caid;
    setEncodedValidity(encodedValidity);
    this.catoken = catoken;
    this.description = description;
    this.crlperiod = crlperiod;
    this.crlIssueInterval = crlIssueInterval;
    this.crlOverlapTime = crlOverlapTime;
    this.deltacrlperiod = deltacrlperiod;
    this.crlpublishers = crlpublishers;
    this.validators = keyValidators;
    this.finishuser = finishuser;
    this.extendedcaserviceinfos = extendedcaserviceinfos;
    setApprovals(approvals);
    this.includeInHealthCheck = includeInHealthCheck;
    this.doEnforceUniquePublicKeys = aDoEnforceUniquePublicKeys;
    this.doEnforceUniqueDistinguishedName = aDoEnforceUniqueDistinguishedName;
    this.doEnforceUniqueSubjectDNSerialnumber =
        aDoEnforceUniqueSubjectDNSerialnumber;
    this.useCertReqHistory = aUseCertReqHistory;
    this.useUserStorage = aUseUserStorage;
    this.useCertificateStorage = aUseCertificateStorage;
    this.acceptRevocationNonExistingEntry = aAcceptRevocationNonExistingEntry;
    this.defaultCertificateProfileId = defaultCertprofileId;
  }
}
