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

package org.cesecore.authorization.cache;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * AccessTreeUpdateData holds a counter, i.e. sequence for when the access rules
 * have been changed. Especially in a cluster this is used in order to avoid
 * rebuilding the internal access tree unless it has changed. I.e. this is for
 * efficiency reasons, since building to complete access tree requires multiple
 * database accesses and some processing.
 *
 * @version $Id: AccessTreeUpdateData.java 25311 2017-02-21 19:07:00Z jeklund $
 */
@Entity
@Table(name = "AuthorizationTreeUpdateData")
public class AccessTreeUpdateData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 778158550351189295L;

  /** Data. */
  public static final Integer AUTHORIZATIONTREEUPDATEDATA = Integer.valueOf(1);
  /** Marker. */
  public static final Integer NEW_AUTHORIZATION_PATTERN_MARKER =
          Integer.valueOf(2);
  /** Default. */
  public static final int DEFAULTACCESSTREEUPDATENUMBER = 0;

  /** Key. */
  private Integer primaryKey;
  /** Number. */
  private int accessTreeUpdateNumber;
  /** Version. */
  private int rowVersion = 0;
  /** Protction. */
  private String rowProtection;

  /**
   * Constructor.
   */
  public AccessTreeUpdateData() {
    setPrimaryKey(AUTHORIZATIONTREEUPDATEDATA);
    setAccessTreeUpdateNumber(DEFAULTACCESSTREEUPDATENUMBER);
  }

  /**
   * @return key
   */
  // @Id @Column
  public Integer getPrimaryKey() {
    return primaryKey;
  }

  /**
   * @param primKey Key
   */
  public final void setPrimaryKey(final Integer primKey) {
    this.primaryKey = primKey;
  }

  /**
   * Method returning the newest authorizationtreeupdatenumber. Should be used
   * after each time the authorization tree is built.
   *
   * @return the newest accessruleset number.
   */
  // @Column
  public int getAccessTreeUpdateNumber() {
    return accessTreeUpdateNumber;
  }

  /**
   * @param anAccessTreeUpdateNumber No
   */
  public void setAccessTreeUpdateNumber(final int anAccessTreeUpdateNumber) {
    this.accessTreeUpdateNumber = anAccessTreeUpdateNumber;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion Version
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
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getPrimaryKey()).append(getAccessTreeUpdateNumber());
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
    return String.valueOf(getPrimaryKey());
  }
  //
  // End Database integrity protection methods
  //

}
