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

package org.ejbca.acme;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.Version;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Storage representation of a used up ACME protocol Replay-Nonce.
 *
 * @version $Id: AcmeNonceData.java 29587 2018-08-07 15:25:52Z mikekushner $
 */
@Entity
@Table(name = "AcmeNonceData")
public class AcmeNonceData extends ProtectedData implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Param. */
  private String nonce;
  /** Param. */
  private long timeExpires;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /** Null. */
  public AcmeNonceData() { }

  /**
   * @param anonce nonce
   * @param thetimeExpires expiry
   */
  public AcmeNonceData(final String anonce, final long thetimeExpires) {
    this.setNonce(anonce);
    this.setTimeExpires(thetimeExpires);
  }

  /**
   * @return nonce
   */
  // @Column
  public String getNonce() {
    return nonce;
  }

  /**
   * @param anonce nonce
   */
  public void setNonce(final String anonce) {
    this.nonce = anonce;
  }

  /**
   * @return time
   */
  // @Column
  public long getTimeExpires() {
    return timeExpires;
  }

  /**
   * @param atimeExpires time
   */
  public void setTimeExpires(final long atimeExpires) {
    this.timeExpires = atimeExpires;
  }

  /**
   * @return version
   */
  // @Column
  @Version
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column
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
        .append(getNonce())
        .append(getTimeExpires())
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
    return getNonce();
  }

  //
  // End Database integrity protection methods
  //
}
