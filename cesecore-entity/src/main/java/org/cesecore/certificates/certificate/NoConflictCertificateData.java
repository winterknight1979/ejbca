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
import javax.persistence.ColumnResult;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.SqlResultSetMapping;
import javax.persistence.SqlResultSetMappings;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringUtil;

/**
 * Representation of a revoked throw-away certificate and related information.
 *
 * @version $Id: NoConflictCertificateData.java 28264 2018-04-09 15:56:54Z tarmo
 *     $
 */
@Entity
@Table(name = "NoConflictCertificateData")
@SqlResultSetMappings(
    value = {
      @SqlResultSetMapping(
          name = "RevokedNoConflictCertInfoSubset",
          columns = {
            @ColumnResult(name = "fingerprint"),
            @ColumnResult(name = "serialNumber"),
            @ColumnResult(name = "expireDate"),
            @ColumnResult(name = "revocationDate"),
            @ColumnResult(name = "revocationReason")
          }),
      @SqlResultSetMapping(
          name = "NoConflictCertificateInfoSubset",
          columns = {
            @ColumnResult(name = "issuerDN"),
            @ColumnResult(name = "subjectDN"),
            @ColumnResult(name = "cAFingerprint"),
            @ColumnResult(name = "status"),
            @ColumnResult(name = "type"),
            @ColumnResult(name = "serialNumber"),
            @ColumnResult(name = "notBefore"),
            @ColumnResult(name = "expireDate"),
            @ColumnResult(name = "revocationDate"),
            @ColumnResult(name = "revocationReason"),
            @ColumnResult(name = "username"),
            @ColumnResult(name = "tag"),
            @ColumnResult(name = "certificateProfileId"),
            @ColumnResult(name = "endEntityProfileId"),
            @ColumnResult(name = "updateTime"),
            @ColumnResult(name = "subjectKeyId"),
            @ColumnResult(name = "subjectAltName")
          }),
      @SqlResultSetMapping(
          name = "NoConflictCertificateInfoSubset2",
          columns = {
            @ColumnResult(name = "fingerprint"),
            @ColumnResult(name = "subjectDN"),
            @ColumnResult(name = "cAFingerprint"),
            @ColumnResult(name = "status"),
            @ColumnResult(name = "type"),
            @ColumnResult(name = "notBefore"),
            @ColumnResult(name = "expireDate"),
            @ColumnResult(name = "revocationDate"),
            @ColumnResult(name = "revocationReason"),
            @ColumnResult(name = "username"),
            @ColumnResult(name = "tag"),
            @ColumnResult(name = "certificateProfileId"),
            @ColumnResult(name = "endEntityProfileId"),
            @ColumnResult(name = "updateTime"),
            @ColumnResult(name = "subjectKeyId"),
            @ColumnResult(name = "subjectAltName")
          }),
      @SqlResultSetMapping(
          name = "NoConflictCertificateFingerprintUsernameSubset",
          columns = {
            @ColumnResult(name = "fingerprint"),
            @ColumnResult(name = "username")
          })
    })
public class NoConflictCertificateData extends BaseCertificateData
    implements Serializable {

  private static final long serialVersionUID = 1L;

  /**
   * Logger. */
  private static final Logger LOG =
      Logger.getLogger(NoConflictCertificateData.class);

  /** Param. */
  private String id;
  /** Param. */
  private String issuerDN;
  /** Param. */
  private String subjectDN;
  /** Param. */
  private String subjectAltName = null; // @since EJBCA 6.6.0
  /** Param. */
  private String fingerprint = "";
  /** Param. */
  private String cAFingerprint;
  /** Param. */
  private int status = 0;
  /** Param. */
  private int type = 0;
  /** Param. */
  private String serialNumber;
  /** Param. */
  private Long notBefore = null; // @since EJBCA 6.6.0
  /** Param. */
  private long expireDate = 0;
  /** Param. */
  private long revocationDate = 0;
  /** Param. */
  private int revocationReason = 0;
  /** Param. */
  private String base64Cert;
  /** Param. */
  private String username;
  /** Param. */
  private String tag;
  /** Param. */
  private Integer certificateProfileId;
  /** Param. */
  private Integer endEntityProfileId = null; // @since EJBCA 6.6.0
  /** Param. */
  private long updateTime = 0;
  /** Param. */
  private String subjectKeyId;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Copy Constructor.
   *
   * @param copy rtiginal
   */
  public NoConflictCertificateData(final NoConflictCertificateData copy) {
    setId(copy.getId());
    setBase64Cert(copy.getBase64Cert());
    setFingerprint(copy.getFingerprint());
    setSubjectDN(copy.getSubjectDN());
    setIssuerDN(copy.getIssuerDN());
    setSubjectAltName(copy.getSubjectAltName());
    setSerialNumber(copy.getSerialNumber());
    setUsername(copy.getUsername());
    setStatus(copy.getStatus());
    setType(copy.getType());
    setCaFingerprint(copy.getCaFingerprint());
    setNotBefore(copy.getNotBefore());
    setExpireDate(copy.getExpireDate());
    setRevocationDate(copy.getRevocationDate());
    setRevocationReason(copy.getRevocationReason());
    setUpdateTime(copy.getUpdateTime());
    setCertificateProfileId(copy.getCertificateProfileId());
    setEndEntityProfileId(copy.getEndEntityProfileId());
    setSubjectKeyId(copy.getSubjectKeyId());
    setTag(copy.getTag());
    setRowVersion(copy.getRowVersion());
    setRowProtection(copy.getRowProtection());
  }

  /** Null constructor. */
  public NoConflictCertificateData() { }

  /**
   * Generated GUID for the table entry.
   *
   * @return id
   */
  public String getId() {
    return id;
  }

  /**
   * Generated GUID for the table entry.
   *
   * @param anId ID
   */
  public void setId(final String anId) {
    this.id = anId;
  }

  @Override
  public String getFingerprint() {
    return fingerprint;
  }

  @Override
  public void setFingerprint(final String aFingerprint) {
    this.fingerprint = aFingerprint;
  }

  @Override
  public String getIssuerDN() {
    return issuerDN;
  }

  @Override
  public void setIssuerDN(final String anIssuerDN) {
    this.issuerDN = anIssuerDN;
  }

  @Override
  public String getSubjectDN() {
    return subjectDN;
  }

  /**
   * Use setSubject instead.
   *
   * @param aSubjectDN subject dn
   * @see #setSubject(String)
   */
  public void setSubjectDN(final String aSubjectDN) {
    this.subjectDN = aSubjectDN;
  }

  /**
   * @return Subject Alternative Name from the certificate if it was saved at
   *     the time of issuance.
   */
  @Transient
  public String getSubjectAltNameNeverNull() {
    final String asubjectAltName = getSubjectAltName();
    return asubjectAltName == null ? "" : asubjectAltName;
  }

  @Override
  public String getSubjectAltName() {
    return subjectAltName;
  }

  /**
   * @param aSubjectAltName name
   */
  public void setSubjectAltName(final String aSubjectAltName) {
    this.subjectAltName = aSubjectAltName;
  }

  @Override
  public String getCaFingerprint() {
    return cAFingerprint;
  }

  @Override
  public void setCaFingerprint(final String aCAFingerprint) {
    this.cAFingerprint = aCAFingerprint;
  }

  @Override
  public int getStatus() {
    return status;
  }

  @Override
  public void setStatus(final int aStatus) {
    this.status = aStatus;
  }

  @Override
  public int getType() {
    return type;
  }

  @Override
  public void setType(final int aType) {
    this.type = aType;
  }

  @Override
  public String getSerialNumber() {
    return serialNumber;
  }

  @Override
  public void setSerialNumber(final String aSerialNumber) {
    this.serialNumber = aSerialNumber;
  }

  @Override
  public Long getNotBefore() {
    return notBefore;
  }

  /**
   * @param aNotBefore start
   */
  public void setNotBefore(final Long aNotBefore) {
    this.notBefore = aNotBefore;
  }

  @Override
  public long getExpireDate() {
    return expireDate;
  }

  @Override
  public void setExpireDate(final long anExpireDate) {
    this.expireDate = anExpireDate;
  }

  @Override
  public long getRevocationDate() {
    return revocationDate;
  }

  @Override
  public void setRevocationDate(final long aRevocationDate) {
    this.revocationDate = aRevocationDate;
  }

  @Override
  public int getRevocationReason() {
    return revocationReason;
  }

  @Override
  public void setRevocationReason(final int aRevocationReason) {
    this.revocationReason = aRevocationReason;
  }

  @Override
  public String getBase64Cert() {
    return this.getZzzBase64Cert();
  }

  /**
   * The certificate itself.
   *
   * @param aBase64Cert base64 encoded certificate
   */
  public void setBase64Cert(final String aBase64Cert) {
    this.setZzzBase64Cert(aBase64Cert);
  }

  /**
   * Horrible work-around due to the fact that Oracle needs to have (LONG and)
   * CLOB values last in order to avoid ORA-24816.
   *
   * <p>Since Hibernate sorts columns by the property names, naming this
   * Z-something will apparently ensure that this column is used last.
   *
   * @return string
   * @deprecated Use {@link #getBase64Cert()} instead
   */
  @Deprecated
  public String getZzzBase64Cert() {
    return base64Cert;
  }

  /**
   * @param zzzBase64Cert string
   * @deprecated Use {@link #setBase64Cert(String)} instead
   */
  @Deprecated
  public void setZzzBase64Cert(final String zzzBase64Cert) {
    this.base64Cert = zzzBase64Cert;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public void setUsername(final String aUsername) {
    this.username = StringUtil.stripUsername(aUsername);
  }

  @Override
  public String getTag() {
    return tag;
  }

  /**
   * tag in database. This field was added for the 3.9.0 release, but is not
   * used yet.
   *
   * @param aTag tag
   */
  public void setTag(final String aTag) {
    this.tag = aTag;
  }

  @Override
  public Integer getCertificateProfileId() {
    return certificateProfileId;
  }

  @Override
  public void setCertificateProfileId(final Integer aCertificateProfileId) {
    this.certificateProfileId = aCertificateProfileId;
  }

  @Override
  public Long getUpdateTime() {
    return updateTime;
  }

  // Hibernate + Oracle ignores nullable=false so we can expect null-objects as
  // input after upgrade. TODO: Verify if still true!
  @Override
  public void setUpdateTime(final Long anUpdateTime) {
    this.updateTime = (anUpdateTime == null ? this.updateTime : anUpdateTime);
  }

  @Override
  public String getSubjectKeyId() {
    return subjectKeyId;
  }

  /**
   * The ID of the public key of the certificate.
   *
   * @param aSubjectKeyId ID
   */
  public void setSubjectKeyId(final String aSubjectKeyId) {
    this.subjectKeyId = aSubjectKeyId;
  }

  @Override
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  @Override
  public String getRowProtection() {
    return this.getZzzRowProtection();
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.setZzzRowProtection(aRowProtection);
  }

  /**
   * Horrible work-around due to the fact that Oracle needs to have (LONG and)
   * CLOB values last in order to avoid ORA-24816.
   *
   * <p>Since Hibernate sorts columns by the property names, naming this
   * Z-something will apparently ensure that this column is used last.
   *
   * @return String
   * @deprecated Use {@link #getRowProtection()} instead
   */
  @Deprecated
  public String getZzzRowProtection() {
    return rowProtection;
  }
  /**
   * @param zzzRowProtection String
   * @deprecated Use {@link #setRowProtection(String)} instead
   */
  @Deprecated
  public void setZzzRowProtection(final String zzzRowProtection) {
    this.rowProtection = zzzRowProtection;
  }

  @Override
  public void setIssuer(final String dn) {
    setIssuerDN(CertTools.stringToBCDNString(dn));
  }

  @Override
  public void setSubject(final String dn) {
    setSubjectDN(CertTools.stringToBCDNString(dn));
  }

  @Override
  public void setEndEntityProfileId(final Integer anEndEntityProfileId) {
    this.endEntityProfileId = anEndEntityProfileId;
  }

  @Override
  public Integer getEndEntityProfileId() {
    return endEntityProfileId;
  }

  // Comparators

  @Override
  public boolean equals(final Object obj) {
    if (!(obj instanceof NoConflictCertificateData)) {
      return false;
    }
    return equals((NoConflictCertificateData) obj, true);
  }

  /**
   * @param certificateData data
   * @param mode mode
   * @param strictStatus status
   * @return bool
   */
  public boolean equals(
      final NoConflictCertificateData certificateData,
      final boolean mode,
      final boolean strictStatus) {
    if (mode) {
      return equalsNonSensitive(certificateData, strictStatus);
    }
    return equals(certificateData, strictStatus);
  }

  private boolean equals(
      final NoConflictCertificateData certificateData,
      final boolean strictStatus) {
    if (!equalsNonSensitive(certificateData, strictStatus)) {
      return false;
    }
    if (this.base64Cert == null && certificateData.base64Cert == null) {
      return true; // test before shows that fingerprint is equal and then both
                   // objects must refer to same row in Base64CertData
    }
    if (this.base64Cert == null || certificateData.base64Cert == null) {
      return false; // one is null and the other not null
    }
    if (!this.base64Cert.equals(certificateData.base64Cert)) {
      return false;
    }
    return true;
  }

  private boolean equalsNonSensitive(
      final NoConflictCertificateData certificateData,
      final boolean strictStatus) {

    if (!id.equals(certificateData.id)) {
      return false;
    }
    if (!issuerDN.equals(certificateData.issuerDN)) {
      return false;
    }
    if (!subjectDN.equals(certificateData.subjectDN)) {
      return false;
    }
    if (!fingerprint.equals(certificateData.fingerprint)) {
      return false;
    }
    if (!cAFingerprint.equals(certificateData.cAFingerprint)) {
      return false;
    }
    if (!equalsStatus(certificateData, strictStatus)) {
      return false;
    }
    if (type != certificateData.type) {
      return false;
    }
    if (!serialNumber.equals(certificateData.serialNumber)) {
      return false;
    }
    if (notBefore == null) {
      if (certificateData.notBefore != null) {
        return false;
      }
    } else {
      if (!notBefore.equals(certificateData.notBefore)) {
        return false;
      }
    }
    if (expireDate != certificateData.expireDate) {
      return false;
    }
    if (revocationDate != certificateData.revocationDate) {
      return false;
    }
    if (revocationReason != certificateData.revocationReason) {
      return false;
    }
    if (!username.equals(certificateData.username)) {
      return false;
    }
    if (tag == null && certificateData.tag != null) {
      return false;
    }
    if (tag != null && !tag.equals(certificateData.tag)) {
      return false;
    }
    if (certificateProfileId == null
        && certificateData.certificateProfileId != null) {
      return false;
    }
    if (certificateProfileId != null
        && !certificateProfileId.equals(certificateData.certificateProfileId)) {
      return false;
    }
    if (endEntityProfileId == null) {
      if (certificateData.endEntityProfileId != null) {
        return false;
      }
    } else {
      if (!endEntityProfileId.equals(certificateData.endEntityProfileId)) {
        return false;
      }
    }
    if (updateTime != certificateData.updateTime) {
      return false;
    }
    if (subjectAltName == null) {
      if (certificateData.subjectAltName != null) {
        return false;
      }
    } else {
      if (!subjectAltName.equals(certificateData.subjectAltName)) {
        return false;
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    return fingerprint.hashCode() * 11;
  }

  /**
   * @param certificateData Data
   * @param inclusionMode Mode
   */
  public void updateWith(
      final NoConflictCertificateData certificateData,
      final boolean inclusionMode) {
    issuerDN = certificateData.issuerDN;
    subjectDN = certificateData.subjectDN;
    fingerprint = certificateData.fingerprint;
    cAFingerprint = certificateData.cAFingerprint;
    status = certificateData.status;
    type = certificateData.type;
    serialNumber = certificateData.serialNumber;
    expireDate = certificateData.expireDate;
    revocationDate = certificateData.revocationDate;
    revocationReason = certificateData.revocationReason;
    setUsername(certificateData.username);
    tag = certificateData.tag;
    certificateProfileId = certificateData.certificateProfileId;
    updateTime = certificateData.updateTime;
    base64Cert = inclusionMode ? null : certificateData.base64Cert;
    id = certificateData.id;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final int cap = 3000;
    final ProtectionStringBuilder build = new ProtectionStringBuilder(cap);
    // What is important to protect here is the data that we define, id, name
    // and certificate profile data
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getFingerprint()).append(getIssuerDN());
    if (version >= 3) {
      // From version 3 for EJBCA 6.7 we always use empty String here to allow
      // future migration between databases when this value is unset
      build.append(getSubjectDnNeverNull());
    } else {
      build.append(getSubjectDN());
    }
    build
        .append(getCaFingerprint())
        .append(getStatus())
        .append(getType())
        .append(getSerialNumber())
        .append(getExpireDate())
        .append(getRevocationDate())
        .append(getRevocationReason())
        .append(getBase64Cert())
        .append(getUsername())
        .append(getTag())
        .append(getCertificateProfileId())
        .append(getUpdateTime())
        .append(getSubjectKeyId());
    if (version >= 2) {
      // In version 2 for EJBCA 6.6 the following columns where added
      build.append(String.valueOf(getNotBefore()));
      build.append(String.valueOf(getEndEntityProfileId()));
      if (version >= 3) {
        // From version 3 for EJBCA 6.7 we always use empty String here to allow
        // future migration between databases when this value is unset
        build.append(getSubjectAltNameNeverNull());
      } else {
        build.append(String.valueOf(getSubjectAltName()));
      }
    }
    if (LOG.isDebugEnabled()) {
      // Some profiling
      if (build.length() > cap) {
        LOG.debug(
            "CertificateData.getProtectString gives size: " + build.length());
      }
    }
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    final int version = 3;
    return version;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return getFingerprint();
  }

  //
  // End Database integrity protection methods
  //
}
