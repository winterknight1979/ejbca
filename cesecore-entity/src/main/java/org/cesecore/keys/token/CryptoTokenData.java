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
package org.cesecore.keys.token;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Properties;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;

/**
 * Database representation of a CryptoToken.
 *
 * @version $Id: CryptoTokenData.java 17625 2013-09-20 07:12:06Z netmackan $
 */
@Entity
@Table(name = "CryptoTokenData")
public class CryptoTokenData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private int
      id; // Internal and static over time representation when referencing this
          // token
  /** Param. */
  private String tokenName; // The name the creator has given to token
  /** Param. */
  private String tokenType; // Mapped to implementation class
  /** Param. */
  private long lastUpdate = 0; // Last update to database
  /** Param. */
  private String tokenProps; // Properties of the token
  /** Param. */
  private String tokenData; // Raw data like a soft keystore
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * @param anId ID
   * @param aTokenName Name
   * @param aTokenType Type
   * @param theLastUpdate Time
   * @param tokenProperties Props
   * @param tokenDataAsBytes Data
   */
  public CryptoTokenData(
      final int anId,
      final String aTokenName,
      final String aTokenType,
      final long theLastUpdate,
      final Properties tokenProperties,
      final byte[] tokenDataAsBytes) {
    setId(anId);
    setTokenName(aTokenName);
    setTokenType(aTokenType);
    setLastUpdate(theLastUpdate);
    setTokenProperties(tokenProperties);
    setTokenDataAsBytes(tokenDataAsBytes);
  }

  /** Null constructor. */
  public CryptoTokenData() { }

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
   * @return name
   */
  // @Column
  public String getTokenName() {
    return tokenName;
  }

  /**
   * @param aTokenName name
   */
  public void setTokenName(final String aTokenName) {
    this.tokenName = aTokenName;
  }

  /**
   * @return type
   */
  // @Column
  public String getTokenType() {
    return tokenType;
  }

  /**
   * @param aTokenType type
   */
  public void setTokenType(final String aTokenType) {
    this.tokenType = aTokenType;
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

  /**
   * @return props
   */
  // @Column @Lob
  public String getTokenProps() {
    return tokenProps;
  }

  /**
   * @param theTokenProps props
   */
  public void setTokenProps(final String theTokenProps) {
    this.tokenProps = theTokenProps;
  }

  /**
   * @return data
   */
  // @Column @Lob
  public String getTokenData() {
    return tokenData;
  }

  /**
   * @param theTokenData data
   */
  public void setTokenData(final String theTokenData) {
    this.tokenData = theTokenData;
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

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  public String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getId())
        .append(getTokenName())
        .append(getTokenType())
        .append(getLastUpdate())
        .append(getTokenProps())
        .append(getTokenData()) /*.append(getCertRefs())*/;
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
   * @return properties
   */
  @Transient
  public Properties getTokenProperties() {
    final Properties props = new Properties();
    try {
      props.load(
          new ByteArrayInputStream(
              Base64.decode(getTokenProps().getBytes("UTF8"))));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return props;
  }

  /**
   * @param props properties
   */
  @Transient
  public void setTokenProperties(final Properties props) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      props.store(baos, null);
      setTokenProps(
          new String(Base64.encode(baos.toByteArray(), false), "UTF8"));
      baos.close();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @return data
   */
  @Transient
  public byte[] getTokenDataAsBytes() {
    try {
      final String data = getTokenData();
      if (data == null || data.length() == 0) {
        return new byte[0];
      }
      return Base64.decode(data.getBytes("UTF8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @param odata data
   */
  @Transient
  public void setTokenDataAsBytes(final byte[] odata) {
    byte[] data;
    if (odata == null) {
      data = new byte[0];
    } else {
        data = odata;
    }
    try {
      setTokenData(new String(Base64.encode(data, false), "UTF8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}
