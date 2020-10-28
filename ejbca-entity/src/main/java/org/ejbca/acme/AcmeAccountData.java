/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.acme;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
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

/** @version $Id: AcmeAccountData.java 25919 2017-05-30 17:09:24Z jeklund $ */
@Entity
@Table(name = "AcmeAccountData")
public class AcmeAccountData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(AcmeAccountData.class);

  /** Param. */
  private String accountId;
  /** Param. */
  private String currentKeyId;
  /** Param. */
  private String rawData;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /** Null constructor. */
  public AcmeAccountData() { }

  /**
   * @param anaccountId account
   * @param acurrentKeyId key
   * @param dataMap map
   */
  public AcmeAccountData(
      final String anaccountId,
      final String acurrentKeyId,
      final LinkedHashMap<Object, Object> dataMap) {
    setAccountId(anaccountId);
    setCurrentKeyId(acurrentKeyId);
    setDataMap(dataMap);
  }

  /**
   * @return ID
   */
  // @Column
  public String getAccountId() {
    return accountId;
  }

  /**
   * @param theaccountId ID
   */
  public void setAccountId(final String theaccountId) {
    this.accountId = theaccountId;
  }

  /**
   * @return ID
   */
  // @Column
  public String getCurrentKeyId() {
    return currentKeyId;
  }

  /**
   * @param thecurrentKeyId ID
   */
  public void setCurrentKeyId(final String thecurrentKeyId) {
    this.currentKeyId = thecurrentKeyId;
  }

  /**
   * @return data
   */
  // @Column @Lob
  public String getRawData() {
    return rawData;
  }

  /**
   * @param therawData data
   */
  public void setRawData(final String therawData) {
    this.rawData = therawData;
  }

  /**
   * @return map
   */
  @Transient
  @SuppressWarnings("unchecked")
  public LinkedHashMap<Object, Object> getDataMap() {
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new ByteArrayInputStream(
                getRawData().getBytes(StandardCharsets.UTF_8))); ) {
      // Handle Base64 encoded string values
      return new Base64GetHashMap((Map<?, ?>) decoder.readObject());
    } catch (IOException e) {
      final String msg =
          "Failed to parse AcmeAccountData data map in database: "
              + e.getMessage();
      if (LOG.isDebugEnabled()) {
        LOG.debug(msg + ". Data:\n" + getRawData());
      }
      throw new IllegalStateException(msg, e);
    }
  }

  /**
   * @param dataMap data
   */
  @Transient
  public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
    // We must base64 encode string for UTF safety
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (XMLEncoder encoder = new XMLEncoder(baos); ) {
      encoder.writeObject(new Base64PutHashMap(dataMap));
    }
    setRawData(new String(baos.toByteArray(), StandardCharsets.UTF_8));
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String arowProtection) {
    this.rowProtection = arowProtection;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking so we will not include that in the
    // database protection
    return new ProtectionStringBuilder()
        .append(getAccountId())
        .append(getCurrentKeyId())
        .append(getRawData())
        .toString();
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
    return getAccountId();
  }

  //
  // End Database integrity protection methods
  //
}
