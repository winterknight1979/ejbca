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

package org.cesecore.roles.member;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.CompareToBuilder;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Entity bean for Role members. Does not correspond to a physical entity, but
 * rather to an individual credential linked to an entity. The same individuals
 * may share the same credential (such as belonging to the same organization, or
 * sharing an account, while one individual may have access to several
 * credentials (such as a user using several different certificates for
 * identification depending on location).
 *
 * <p>Each member is linked to a Role, though not intrinsically so via foreign
 * keys
 *
 * @version $Id: RoleMemberData.java 25634 2017-04-03 12:02:08Z jeklund $
 */
@Entity
@Table(name = "RoleMemberData")
public class RoleMemberData extends ProtectedData
    implements Serializable, Comparable<RoleMemberData> {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private int primaryKey;

  /** Param. */
  private String tokenType;
  /** Param. */
  private int tokenIssuerId;
  /** Param. */
  private int tokenMatchKey;
  /** Param. */
  private int tokenMatchOperator;
  /** Param. */
  private String tokenMatchValueColumn;
  /** Param. */
  private int roleId;
  /** Param. */
  private String descriptionColumn;

  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /** Null constructor. */
  public RoleMemberData()  { }

  /**
   * Construct the object from RoleMember value object.
   *
   * @param roleMember member
   */
  public RoleMemberData(final RoleMember roleMember) {
    setPrimaryKey(roleMember.getId());
    updateValuesFromValueObject(roleMember);
  }

  /**
   * Slightly more verbose constructor used for upgrades.
   *
   * @param aPrimaryKey the primary key for this object. It's required to check
   *     the database for any objects with the same key, otherwise that object
   *     will be overridden
   * @param aTokenType a string which defined the implementation of
   *     AcceessMatchValue used by this member
   * @param aTokenIssuerId the issuer of token if relevant or 0
   *     (RoleMember.NO_ISSUER) otherwise
   * @param aTokenMatchKey the integer value determining how to interpret the
   *     tokenMatchValue, defined in a class that inherits the interface
   *     AcceessMatchValue
   * @param aTokenMatchOperator how to perform the match. 0
   *     (AccessMatchType.UNUSED.getNumericValue())to let the determine this
   *     from tokenSubType.
   * @param tokenMatchValue the actual value with which to match
   * @param aRoleId the ID of the role to which this member
   * belongs. May be null.
   * @param description a human readable description of this role member. Null
   *     will be treated as an empty String.
   */
  public RoleMemberData(
      final int aPrimaryKey,
      final String aTokenType,
      final int aTokenIssuerId,
      final int aTokenMatchKey,
      final int aTokenMatchOperator,
      final String tokenMatchValue,
      final int aRoleId,
      final String description) {
    this.primaryKey = aPrimaryKey;
    this.tokenType = aTokenType;
    this.tokenIssuerId = aTokenIssuerId;
    this.tokenMatchKey = aTokenMatchKey;
    this.tokenMatchOperator = aTokenMatchOperator;
    this.tokenMatchValueColumn = tokenMatchValue;
    this.roleId = aRoleId;
    this.setDescription(description);
  }

  /** @return the primary key of this entity bean, a pseudo-random integer */
  public int getPrimaryKey() {
    return primaryKey;
  }

  /**
   * @param aPrimaryKey PK
   */
  public void setPrimaryKey(final int aPrimaryKey) {
    this.primaryKey = aPrimaryKey;
  }

  /**
   * @return the authentication token type that this member identifies to (such
   *     as X509CertificateAuthenticationToken)
   */
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
   * @return issuer identifier of this token or 0 (RoleMember.NO_ISSUER) if this
   *     is not relevant for this token type
   */
  public int getTokenIssuerId() {
    return tokenIssuerId;
  }

  /**
   * @param aTokenIssuerId ID
   */
  public void setTokenIssuerId(final int aTokenIssuerId) {
    this.tokenIssuerId = aTokenIssuerId;
  }

  /**
   * @return the match value type with to match, i.e. CN, serial number, or
   *     username
   */
  public int getTokenMatchKey() {
    return tokenMatchKey;
  }

  /**
   * @param aTokenMatchKey key
   */
  public void setTokenMatchKey(final int aTokenMatchKey) {
    this.tokenMatchKey = aTokenMatchKey;
  }

  /** @return what kind of operator to apply to the match value */
  public int getTokenMatchOperator() {
    return tokenMatchOperator;
  }

  /**
   * @param aTokenMatchOperator Op
   */
  public void setTokenMatchOperator(final int aTokenMatchOperator) {
    this.tokenMatchOperator = aTokenMatchOperator;
  }

  // @Column(name="tokenMatchValue")
  /** @return column
 * @deprecated (Only for database mapping) {@link #getTokenMatchValue()} */
  @Deprecated
  public String getTokenMatchValueColumn() {
    return tokenMatchValueColumn;
  }


  /**
   * @param aTokenMatchValueColumn column
 * @deprecated (Only for database mapping) {@link #setTokenMatchValue(String)}
   */
  @Deprecated
  public void setTokenMatchValueColumn(final String aTokenMatchValueColumn) {
    this.tokenMatchValueColumn = aTokenMatchValueColumn;
  }

  /** @return the actual value with which we match (never returns null) */
  @Transient
  public String getTokenMatchValue() {
    return StringUtils.defaultIfEmpty(getTokenMatchValueColumn(), "");
  }

  /**
   * @param tokenMatchValue value
   */
  @Transient
  public void setTokenMatchValue(final String tokenMatchValue) {
    this.setTokenMatchValueColumn(
        StringUtils.defaultIfEmpty(tokenMatchValue, null));
  }

  /**
   * @return the role to which this member belongs or 0 if it is not assigned to
   *     a role.
   */
  public int getRoleId() {
    return roleId;
  }

  /**
   * @param aRoleId ID
   */
  public void setRoleId(final int aRoleId) {
    this.roleId = aRoleId;
  }

  // @Column(name="description")
  /** @return column
 * @deprecated (Only for database mapping) {@link #getDescription()} */
  @Deprecated
  public String getDescriptionColumn() {
    return descriptionColumn;
  }


  /** @param aDescriptionColumn column
 * @deprecated (Only for database mapping) {@link #setDescription(String)}.
   */
  @Deprecated
  public void setDescriptionColumn(final String aDescriptionColumn) {
    this.descriptionColumn = aDescriptionColumn;
  }


  /** @return a human readable description of the role member */
  @Transient
  public String getDescription() {
    return StringUtils.defaultIfEmpty(getDescriptionColumn(), "");
  }

  /**
   * @param description desc
   */
  @Transient
  public void setDescription(final String description) {
    this.setDescriptionColumn(StringUtils.defaultIfEmpty(description, null));
  }

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

  /** @return the row integrity protection String */
  public String getRowProtection() {
    return getZzzRowProtection();
  }

  /**
   *  @param aRowProtection protection
   */
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
   * @return string
   * @deprecated Use {@link #getRowProtection()} instead
   */
  @Deprecated
  public String getZzzRowProtection() {
    return rowProtection;
  }
  /**
   * @param zzzRowProtection string
   * @deprecated Use {@link #setRowProtection(String)} instead
   */
  @Deprecated
  public void setZzzRowProtection(final String zzzRowProtection) {
    this.rowProtection = zzzRowProtection;
  }

  // Start Database integrity protection methods
  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getPrimaryKey())
        .append(getTokenType())
        .append(getTokenIssuerId())
        .append(getTokenMatchKey())
        .append(getTokenMatchOperator())
        .append(getTokenMatchValue())
        .append(getRoleId())
        .append(getDescription());
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

  @Override
  public int compareTo(final RoleMemberData o) {
    return new CompareToBuilder()
        .append(this.tokenType, o.tokenType)
        .append(this.tokenIssuerId, o.tokenIssuerId)
        .append(this.tokenMatchKey, o.tokenMatchKey)
        .append(this.tokenMatchOperator, o.tokenMatchOperator)
        .append(this.tokenMatchValueColumn, o.tokenMatchValueColumn)
        .toComparison();
  }

  /**
   * @return member
   */
  @Transient
  public RoleMember asValueObject() {
    return new RoleMember(
        primaryKey,
        tokenType,
        tokenIssuerId,
        tokenMatchKey,
        tokenMatchOperator,
        getTokenMatchValue(),
        roleId,
        getDescription());
  }

  /**
   * Sets all fields except the ID.
   *
   * @param roleMember member
   */
  @Transient
  public void updateValuesFromValueObject(final RoleMember roleMember) {
    setTokenType(roleMember.getTokenType());
    setTokenIssuerId(roleMember.getTokenIssuerId());
    setTokenMatchKey(roleMember.getTokenMatchKey());
    setTokenMatchOperator(roleMember.getTokenMatchOperator());
    setTokenMatchValue(roleMember.getTokenMatchValue());
    setRoleId(roleMember.getRoleId());
    setDescription(roleMember.getDescription());
  }
}
