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

package org.cesecore.keybind;

import java.beans.XMLEncoder;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;

/**
 * Database representation of an InternalKeyBinding.
 *
 * @version $Id: InternalKeyBindingData.java 34163 2020-01-02 15:00:17Z samuellb
 *     $
 */
@Entity
@Table(name = "InternalKeyBindingData")
public class InternalKeyBindingData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(InternalKeyBindingData.class);

  /** Param. */
  private int
      id; // Internal and static over time representation when referencing this
          // object
  /** Param. */
  private String name; // A human friendly representation of this object

  /** Param. */
  private String
      status; // The status as a String constant of InternalKeyBindingStatus
  /** Param. */
  private String keyBindingType; // Mapped to implementation class
  /** Param. */
  private String
      certificateId; // Reference to a Certificate currently in use by the
                     // implementation
  /** Param. */
  private int
      cryptoTokenId; // Reference to a CryptoToken currently in use by the
                     // implementation
  /** Param. */
  private String
      keyPairAlias; // Reference to an alias in the CryptoToken currently in use
                    // by the implementation
  /** Param. */
  private String
      rawData; // Raw data like a with implementation specific details and
               // configuration
  /** Param. */
  private long lastUpdate =
      0; // Last update to database, Unix epoch milliseconds
  /** Param. */
  private int rowVersion = 0; // JPA Optimistic locking requirement
  /** Param. */
  private String rowProtection; // Row integrity protection

  /**
   * @param anId ID
   * @param aNname Name
   * @param aStatus Status
   * @param aKeyBindingType Type
   * @param aCertificateId ID
   * @param aCryptoTokenId ID
   * @param aKeyPairAlias Alais
   * @param dataMap Map
   */
  public InternalKeyBindingData(
      final int anId,
      final String aNname,
      final InternalKeyBindingStatus aStatus,
      final String aKeyBindingType,
      final String aCertificateId,
      final int aCryptoTokenId,
      final String aKeyPairAlias,
      final LinkedHashMap<Object, Object> dataMap) {
    setId(anId);
    setName(aNname);
    setStatusEnum(aStatus);
    setKeyBindingType(aKeyBindingType);
    if (aCertificateId != null) {
      setCertificateId(aCertificateId.toLowerCase(Locale.ENGLISH));
    } else {
      setCertificateId(null);
    }
    setCryptoTokenId(aCryptoTokenId);
    setKeyPairAlias(aKeyPairAlias);
    setDataMap(dataMap);
    setLastUpdate(System.currentTimeMillis());
  }

  /** Null constructor. */
  public InternalKeyBindingData() { }

  /**
   * @return ID
   */
  // @Id @Column
  public int getId() {
    return id;
  }

  /**
   * @param anId ID
   */
  public void setId(final int anId) {
    this.id = anId;
  }

  /**
   * @return Name
   */
  // @Column
  public String getName() {
    return name;
  }

  /**
   * @param aName name
   */
  public void setName(final String aName) {
    this.name = aName;
  }

  // @Column
  /**
   * Use getStatusEnum() instead.
   *
   * @return status
   */
  public String getStatus() {
    return status;
  }
  /**
   * Use setStatusEnum(..) instead.
   *
   * @param aStatus status
   */
  public void setStatus(final String aStatus) {
    this.status = aStatus;
  }

  /**
   * @return type
   */
  // @Column
  public String getKeyBindingType() {
    return keyBindingType;
  }

  /**
   * @param aKeyBindingType Type
   */
  public void setKeyBindingType(final String aKeyBindingType) {
    this.keyBindingType = aKeyBindingType;
  }

  /**
   * @return ID
   */
  // @Column
  public String getCertificateId() {
    return certificateId;
  }

  /**
   * @param aCertificateId ID
   */
  public void setCertificateId(final String aCertificateId) {
    if (aCertificateId != null) {
      this.certificateId = aCertificateId.toLowerCase(Locale.ENGLISH);
    } else {
      this.certificateId = null;
    }
  }
  /**
   * @return ID
   */
  // @Column
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }

  /**
   * @param aCryptoTokenId ID
   */
  public void setCryptoTokenId(final int aCryptoTokenId) {
    this.cryptoTokenId = aCryptoTokenId;
  }

  /**
   * @return alias
   */
  // @Column
  public String getKeyPairAlias() {
    return keyPairAlias;
  }

  /**
   * @param aKeyPairAlias Alias
   */
  public void setKeyPairAlias(final String aKeyPairAlias) {
    this.keyPairAlias = aKeyPairAlias;
  }

  /**
   * @return time
   */
  // @Column
  public long getLastUpdate() {
    return lastUpdate;
  }

  /**
   * @param theLastUpdate time
   */
  public void setLastUpdate(final long theLastUpdate) {
    this.lastUpdate = theLastUpdate;
  }

  // @Column @Lob
  /**
   * Should not be invoked directly. Use getDataMap() instead.
   *
   * @return data
   */
  public String getRawData() {
    return rawData;
  }
  /**
   * Should not be invoked directly. Use setDataMap(..) instead.
   *
   * @param theRawData data
   */
  public void setRawData(final String theRawData) {
    this.rawData = theRawData;
  }

  // @Version @Column
  /**
   * @return version
   */
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

  //
  // Start Database integrity protection methods
  //
  @Transient
  @Override
  public String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder(1024);
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getId())
        .append(getName())
        .append(getStatus())
        .append(getKeyBindingType());
    build
        .append(getCertificateId())
        .append(String.valueOf(getCryptoTokenId()))
        .append(getKeyPairAlias());
    build.append(getRawData()).append(String.valueOf(getLastUpdate()));
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
    return String.valueOf(getId());
  }
  //
  // End Database integrity protection methods
  //

  /**
   * @return map
   */
  @Transient
  @SuppressWarnings("unchecked")
  public LinkedHashMap<Object, Object> getDataMap() {
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new java.io.ByteArrayInputStream(
                getRawData().getBytes(StandardCharsets.UTF_8)))) {
      final Map<?, ?> h = (Map<?, ?>) decoder.readObject();
      // Handle Base64 encoded string values
      final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
      return dataMap;
    } catch (IOException e) {
      final String msg =
          "Failed to parse InternalKeyBindingData data map in database: "
              + e.getMessage();
      if (LOG.isDebugEnabled()) {
        LOG.debug(msg + ". Data:\n" + getRawData());
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
    // We must base64 encode string for UTF safety
    final LinkedHashMap<?, ?> a = new Base64PutHashMap();
    a.putAll((LinkedHashMap) dataMap);
    final java.io.ByteArrayOutputStream baos =
        new java.io.ByteArrayOutputStream();
    try {
      try (XMLEncoder encoder = new XMLEncoder(baos)) {
        encoder.writeObject(a);
      }
      final String data = baos.toString("UTF8");
      setRawData(data);
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * @return Status
   */
  @Transient
  public InternalKeyBindingStatus getStatusEnum() {
    return InternalKeyBindingStatus.valueOf(getStatus());
  }

  /**
   * @param aStatus Status
   */
  @Transient
  public void setStatusEnum(final InternalKeyBindingStatus aStatus) {
    setStatus(aStatus.name());
  }
}
