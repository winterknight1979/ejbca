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
package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a certificate but not the certificate itself.
 *
 * @version $Id: CertificateInfo.java 23611 2016-06-03 13:34:45Z jeklund $
 */
public class CertificateInfo implements Serializable {

  private static final long serialVersionUID = -1973602951994928833L;
  /** FP. */
  private String fingerprint;
  /** FP. */
  private String cafingerprint;
  /** Serial. */
  private String serno;
  /** DN. */
  private String issuerdn;
  /** DN. */
  private String subjectdn;
  /** Status. */
  private int status;
  /** Type. */
  private int type;
  /** Start. */
  private Date notBefore;
  /** Expiry. */
  private Date expiredate;
  /** Date. */
  private Date revocationdate;
  /** Reason. */
  private int revocationreason;
  /** Username. */
  private String username;
  /** Tag. */
  private String tag;
  /** Profile ID. */
  private int certificateProfileId;
  /** Profile ID. */
  private Integer endEntityProfileId;
  /** Updated. */
  private Date updateTime;
  /** ID. */
  private String subjectKeyId;
  /** Name. */
  private String subjectAltName;
  /**
   * Constructor.
   * @param aFingerprint FP
   * @param aCafingerprint FP
   * @param aSerno SN
   * @param aIssuerdn DN
   * @param aSubjectdn DN
   * @param aStatus Status
   * @param aType Type
   * @param aNotBefore Start
   * @param aExpiredate End
   * @param aRevocationdate Revoke
   * @param aRevocationreason Reason
   * @param aUsername User
   * @param aTag Tag
   * @param aCertificateProfileId ID
   * @param aEndEntityProfileId ID
   * @param aUpdateTime Time
   * @param aSubjectKeyId Key
   * @param aSubjectAltName Name
   */
  public CertificateInfo(
      final String aFingerprint,
      final String aCafingerprint,
      final String aSerno,
      final String aIssuerdn,
      final String aSubjectdn,
      final int aStatus,
      final int aType,
      final Long aNotBefore,
      final long aExpiredate,
      final long aRevocationdate,
      final int aRevocationreason,
      final String aUsername,
      final String aTag,
      final int aCertificateProfileId,
      final Integer aEndEntityProfileId,
      final long aUpdateTime,
      final String aSubjectKeyId,
      final String aSubjectAltName) {
    this.fingerprint = aFingerprint;
    this.cafingerprint = aCafingerprint;
    this.serno = aSerno;
    this.issuerdn = aIssuerdn;
    this.subjectdn = aSubjectdn;
    this.status = aStatus;
    this.type = aType;
    this.notBefore = aNotBefore == null ? null : new Date(aNotBefore);
    this.expiredate = new Date(aExpiredate);
    this.revocationdate = new Date(aRevocationdate);
    this.revocationreason = aRevocationreason;
    this.username = aUsername;
    this.tag = aTag;
    this.certificateProfileId = aCertificateProfileId;
    this.endEntityProfileId = aEndEntityProfileId;
    this.updateTime = new Date(aUpdateTime);
    this.subjectKeyId = aSubjectKeyId;
    this.subjectAltName = aSubjectAltName;
  }

  /** @return FP */
  public String getFingerprint() {
    return fingerprint;
  }

  /** @param fp FP */
  public void setFingerprint(final String fp) {
    this.fingerprint = fp;
  }

  /** @return FP */
  public String getCAFingerprint() {
    return cafingerprint;
  }

  /** @return serno */
  public BigInteger getSerialNumber() {
    return new BigInteger(serno);
  }

  /** @return DN */
  public String getSubjectDN() {
    return subjectdn;
  }

  /** @return DN */
  public String getIssuerDN() {
    return issuerdn;
  }
  /**
   * @return One of the CertificateConstants.CERT_ constants, for example
   *     CertificateConstants.CERT_ACTIVE
   */
  public int getStatus() {
    return status;
  }
  /**
   * @param s One of the CertificateConstants.CERT_ constants, for example
   *     CertificateConstants.CERT_ACTIVE
   */
  public void setStatus(final int s) {
    this.status = s;
  }

  /** @return type */
  public int getType() {
    return type;
  }

  /** @return date */
  public Date getNotBefore() {
    return notBefore;
  }

  /** @return date */
  public Date getExpireDate() {
    return expiredate;
  }

  /** @return date */
  public Date getRevocationDate() {
    return revocationdate;
  }

  /** @param d date */
  public void setRevocationDate(final Date d) {
    this.revocationdate = d;
  }

  /** @return reason */
  public int getRevocationReason() {
    return revocationreason;
  }

  /** @return tag */
  public String getTag() {
    return tag;
  }

  /** @param aTag tag */
  public void setTag(final String aTag) {
    this.tag = aTag;
  }

  /** @return ID */
  public int getCertificateProfileId() {
    return certificateProfileId;
  }

  /** @return profile */
  public int getEndEntityProfileIdOrZero() {
    return endEntityProfileId == null ? 0 : endEntityProfileId;
  }

  /** @param aCertificateProfileId ID */
  public void setCertificateProfileId(final int aCertificateProfileId) {
    this.certificateProfileId = aCertificateProfileId;
  }

  /** @return time */
  public Date getUpdateTime() {
    return updateTime;
  }

  /** @param aUpdateTime time  */
  public void setUpdateTime(final Date aUpdateTime) {
    this.updateTime = aUpdateTime;
  }

  /** @return name */
  public String getUsername() {
    return username;
  }

  /** @param aUsername name  */
  public void setUsername(final String aUsername) {
    this.username = aUsername;
  }

  /** @return ID */
  public String getSubjectKeyId() {
    return subjectKeyId;
  }

  /** @return name */
  public String getSubjectAltName() {
    return subjectAltName;
  }
}
