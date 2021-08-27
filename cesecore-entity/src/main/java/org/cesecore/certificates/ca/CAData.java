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
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreRuntimeException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.SecureXMLDecoder;

/**
 * Representation of a CA instance.
 *
 * @version $Id: CAData.java 34163 2020-01-02 15:00:17Z samuellb $
 */
@Entity
@Table(name = "CAData")
public class CAData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CAData.class);

  /** ID. */
  private Integer cAId;
  /** Name. */
  private String name;
  /** DN. */
  private String subjectDN;
  /** Status. */
  private int status = 0; // not null, we need a default
  /** Time. */
  private long expireTime = 0; // not null, we need a default
  /** Time. */
  private long updateTime = 0; // not null, we need a default
  /** Data. */
  private String data;
  /** Version. */
  private int rowVersion = 0; // not null, we need a default
  /** Protect. */
  private String rowProtection;

  /**
   * @param subjectdn DN
   * @return ID
   */
  public static Integer calculateCAId(final String subjectdn) {
    return Integer.valueOf(subjectdn.hashCode());
  }

  /**
   * Entity Bean holding data of a CA.
   *
   * @param subjectdn DN
   * @param aName of CA
   * @param aStatus initial status
   * @param ca CA to store
   */
  public CAData(
      final String subjectdn,
      final String aName,
      final int aStatus,
      final CA ca) {
    setCaId(calculateCAId(subjectdn));
    setName(aName);
    setSubjectDN(subjectdn);
    if (ca.getCACertificate() != null) {
      final Certificate cacert = ca.getCACertificate();
      setExpireTime(CertTools.getNotAfter(cacert).getTime());
      ca.setExpireTime(CertTools.getNotAfter(cacert));
    }
    // Set status, because it can occur in the ca object as well, but we think
    // the one passed as argument here is what
    // is desired primarily, so make sure we set that
    ca.setStatus(aStatus);
    setCA(ca);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created CA " + aName);
    }
  }

  /** Default. */
  public CAData() { }

  /**
   * @return ID
   */
  // @Id @Column
  public Integer getCaId() {
    return cAId;
  }

  /**
   * @param aCAId ID
   */
  public final void setCaId(final Integer aCAId) {
    this.cAId = aCAId;
  }

  /**
   * @return name
   */
  // @Column
  public String getName() {
    return name;
  }

  /**
   * @param aName Name
   */
  public void setName(final String aName) {
    this.name = aName;
  }


  /**
   * @return DN
   */
  // @Column
  public String getSubjectDN() {
    return subjectDN;
  }

  /**
   * @param aSubjectDN DN
   */
  public void setSubjectDN(final String aSubjectDN) {
    this.subjectDN = aSubjectDN;
  }

  /**
   * @return Status
   */
  // @Column
  public int getStatus() {
    return status;
  }

  /**
   * @param aStatus Status
   */
  public void setStatus(final int aStatus) {
    this.status = aStatus;
  }

  /**
   * @return Time
   */
  // @Column
  public long getExpireTime() {
    return expireTime;
  }

  /**
   * @param anExpireTime time
   */
  public void setExpireTime(final long anExpireTime) {
    this.expireTime = anExpireTime;
  }

  /**
   * When was this CA updated in the database.
   *
   * @return time
   */
  // @Column
  public long getUpdateTime() {
    return updateTime;
  }

  /**
   * @param anUpdateTime time
   */
  public void setUpdateTime(final long anUpdateTime) {
    this.updateTime = anUpdateTime;
  }

  /**
   * @return Data
   */
  // @Column @Lob
  public String getData() {
    return data;
  }

  /**
   * @param theData Data
   */
  public void setData(final String theData) {
    this.data = theData;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  /**
   * @return Date
   */
  @Transient
  public Date getUpdateTimeAsDate() {
    return new Date(getUpdateTime());
  }

  /**
   * @return a CA in the form it was saved in the database + regular
   *     UpgradableHashMap upgrade-on-load
   */
  @Transient
  public CA getCA() {
    final LinkedHashMap<Object, Object> dataMap = getDataMap();
    CA ca = null;
    switch (((Integer) (dataMap.get(CA.CATYPE))).intValue()) {
      case CAInfo.CATYPE_X509:
        ca =
            new X509CA(
                dataMap,
                getCaId().intValue(),
                getSubjectDN(),
                getName(),
                getStatus(),
                getUpdateTimeAsDate(),
                new Date(getExpireTime()));
        break;
      case CAInfo.CATYPE_CVC:
        ca =
            CvcCA.getInstance(
                dataMap,
                getCaId().intValue(),
                getSubjectDN(),
                getName(),
                getStatus(),
                getUpdateTimeAsDate(),
                new Date(getExpireTime()));
        break;
      default: // no-op
          break;
    }
    return ca;
  }

  /**
   * Method that converts the CA object to storage representation.
   *
   * @param ca CA
   */
  @SuppressWarnings({"unchecked"})
  @Transient
  public final void setCA(final CA ca) {
    setDataMap((LinkedHashMap<Object, Object>) ca.saveData());
    setUpdateTime(System.currentTimeMillis());
    // We have to update status as well, because it is kept in it's own database
    // column, but only do that if it was actually provided in the request
    if (ca.getStatus() > 0) {
      setStatus(ca.getStatus());
    }
    setName(ca.getName());
    setSubjectDN(ca.getSubjectDN());
    // set expire time, perhaps we have updated the CA certificate
    final Certificate cacert = ca.getCACertificate();
    if (cacert != null) {
      setExpireTime(CertTools.getNotAfter(cacert).getTime());
    }
  }

  /**
   * @return Map
   */
  @Transient
  public LinkedHashMap<Object, Object> getDataMap() {
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new java.io.ByteArrayInputStream(
                getData().getBytes(StandardCharsets.UTF_8)))) {
      final Map<?, ?> h = (Map<?, ?>) decoder.readObject();
      // Handle Base64 encoded string values
      @SuppressWarnings("unchecked")
      final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
      return dataMap;
    } catch (IOException e) {
      final String msg =
          "Failed to parse data map for CA '"
              + getName()
              + "': "
              + e.getMessage();
      if (LOG.isDebugEnabled()) {
        LOG.debug(msg + ". Data:\n" + getData());
      }
      throw new IllegalStateException(msg, e);
    }
  }

  /**
   * @param dataMap Map
   */
  @Transient
  @SuppressWarnings({"rawtypes", "unchecked"})
  public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
    try {
      // We must base64 encode string for UTF safety
      final LinkedHashMap<?, ?> a = new Base64PutHashMap();
      a.putAll((LinkedHashMap) dataMap);
      final java.io.ByteArrayOutputStream baos =
          new java.io.ByteArrayOutputStream();
      final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
      encoder.writeObject(a);
      encoder.close();
      final String aData = baos.toString("UTF8");
      if (LOG.isDebugEnabled()) {
        LOG.debug("Saving CA data with length: " + aData.length() + " for CA.");
      }
      setData(aData);
      setUpdateTime(System.currentTimeMillis());
    } catch (UnsupportedEncodingException e) {
      throw new CesecoreRuntimeException(e);
    }
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  public String getProtectString(final int version) {
    final int capacity = 8000;
    final ProtectionStringBuilder build = new ProtectionStringBuilder(capacity);
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getCaId())
        .append(getName())
        .append(getSubjectDN())
        .append(getStatus())
        .append(getExpireTime())
        .append(getUpdateTime())
        .append(getData());
    if (LOG.isDebugEnabled() && build.length() > capacity) {
        LOG.debug("CAData.getProtectString gives size: " + build.length());

    }
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 1;
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
    return getCaId().toString();
  }
  //
  // End Database integrity protection methods
  //

}
