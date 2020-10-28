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
import javax.persistence.Id;
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

/** @version $Id: AcmeOrderData.java 25919 2017-05-30 17:09:24Z tarmor $ */
@Entity
@Table(name = "AcmeOrderData")
public class AcmeOrderData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(AcmeOrderData.class);

  /** Param. */
  @Id private String orderId;

  /** Param. */
  private String accountId;
  /** Param. */
  private String fingerprint;
  /** Param. */
  private String status;
  /** Param. */
  private String rawData;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /** Null constructor. */
  public AcmeOrderData() { }

  /**
   * @param anorderId Order
   * @param anaccountId Account
   * @param afingerprint FP
   * @param astatus Status
   * @param dataMap Data
   */
  public AcmeOrderData(
      final String anorderId,
      final String anaccountId,
      final String afingerprint,
      final String astatus,
      final LinkedHashMap<Object, Object> dataMap) {
    this.orderId = anorderId;
    this.accountId = anaccountId;
    this.fingerprint = afingerprint;
    this.status = astatus;
    setDataMap(dataMap);
  }

  /**
   * @return ID
   */
  public String getOrderId() {
    return orderId;
  }

  /**
   * @param anorderId ID
   */
  public void setOrderId(final String anorderId) {
    this.orderId = anorderId;
  }

  /**
   * @return ID
   */
  public String getAccountId() {
    return accountId;
  }

  /**
   * @param anaccountId ID
   */
  public void setAccountId(final String anaccountId) {
    this.accountId = anaccountId;
  }

  /**
   * @return FP
   */
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @param afingerprint FP
   */
  public void setFingerprint(final String afingerprint) {
    this.fingerprint = afingerprint;
  }

  /**
   * @return status
   */
  public String getStatus() {
    return status;
  }

  /**
   * @param astatus status
   */
  public void setStatus(final String astatus) {
    this.status = astatus;
  }

  /**
   * @return data
   */
  public String getRawData() {
    return rawData;
  }

  /**
   * @param therawData map
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
                getRawData().getBytes(StandardCharsets.UTF_8)))) {
      // Handle Base64 encoded string values
      return new Base64GetHashMap((Map<?, ?>) decoder.readObject());
    } catch (IOException e) {
      final String msg =
          "Failed to parse AcmeOrderData data map in database: "
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
  public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
    // We must base64 encode string for UTF safety
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (XMLEncoder encoder = new XMLEncoder(baos)) {
      encoder.writeObject(new Base64PutHashMap(dataMap));
    }
    setRawData(new String(baos.toByteArray(), StandardCharsets.UTF_8));
  }

  /**
   * @return version
   */
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

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
        .append(getOrderId())
        .append(getAccountId())
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
