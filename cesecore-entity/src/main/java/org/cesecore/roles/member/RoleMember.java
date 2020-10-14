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
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.roles.Role;

/**
 * Value object for the RoleMemberData entity bean, so that we don't have to
 * pass information like row protection remotely.
 *
 * @version $Id: RoleMember.java 25626 2017-03-30 17:09:50Z jeklund $
 */
public class RoleMember implements Serializable {

      /** Config. */
  public static final int ROLE_MEMBER_ID_UNASSIGNED = 0;
  /** Config. */
  public static final int NO_ROLE = Role.ROLE_ID_UNASSIGNED;
  /** Config. */
  public static final int NO_ISSUER = 0;

  private static final long serialVersionUID = 1L;
  /** Param. */
  private int id;
  /** Param. */
  private String tokenType;
  /** Param. */
  private int tokenIssuerId;
  /** Param. */
  private int tokenMatchKey;
  /** Param. */
  private int tokenMatchOperator;
  /** Param. */
  private String tokenMatchValue;
  /** Param. */
  private int roleId;
  /** Param. */
  private String description;

  /**
   * Constructor for a new RoleMember. Will by default be constructed with the
   * primary key 0, which means that this object hasn't been persisted yet. In
   * that case, the primary key will be set by the CRUD bean.
   *
   * @param aTokenType Type
   * @param aTokenIssuerId the issuer identifier of this token or 0 if not
   *     relevant
   * @param aTokenMatchKey Key
   * @param aTokenMatchOperator Operator
   * @param aTokenMatchValue the actual value with which to match
   * @param aRoleId roleId the ID of the role to which this member belongs. May
   *     be null.
   * @param aDescription a human readable description of this role member.
   */
  public RoleMember(
      final String aTokenType,
      final int aTokenIssuerId,
      final int aTokenMatchKey,
      final int aTokenMatchOperator,
      final String aTokenMatchValue,
      final int aRoleId,
      final String aDescription) {
    this(
        ROLE_MEMBER_ID_UNASSIGNED,
        aTokenType,
        aTokenIssuerId,
        aTokenMatchKey,
        aTokenMatchOperator,
        aTokenMatchValue,
        aRoleId,
        aDescription);
  }

  /**
   * Constructor for a new RoleMember. Will by default be constructed with the
   * primary key 0, which means that this object hasn't been persisted yet. In
   * that case, the primary key will be set by the CRUD bean.
   *
   * @param anId ID
   * @param aTokenType Type
   * @param aTokenIssuerId the issuer identifier of this token or 0 if not
   *     relevant
   * @param aTokenMatchKey Key
   * @param aTokenMatchOperator Operator
   * @param aTokenMatchValue the actual value with which to match
   * @param aRoleId roleId the ID of the role to which this member belongs. May
   *     be null.
   * @param aDescription a human readable description of this role member.
   */
  public RoleMember(
      final int anId,
      final String aTokenType,
      final int aTokenIssuerId,
      final int aTokenMatchKey,
      final int aTokenMatchOperator,
      final String aTokenMatchValue,
      final int aRoleId,
      final String aDescription) {
    this.id = anId;
    this.tokenType = aTokenType;
    this.tokenIssuerId = aTokenIssuerId;
    this.tokenMatchKey = aTokenMatchKey;
    this.tokenMatchOperator = aTokenMatchOperator;
    this.tokenMatchValue = aTokenMatchValue;
    this.roleId = aRoleId;
    this.description = aDescription;
  }

  /**
   * Copy constructor.
   *
   * @param roleMember original
   */
  public RoleMember(final RoleMember roleMember) {
    this.id = roleMember.id;
    this.tokenType = roleMember.tokenType;
    this.tokenIssuerId = roleMember.tokenIssuerId;
    this.tokenMatchKey = roleMember.tokenMatchKey;
    this.tokenMatchOperator = roleMember.tokenMatchOperator;
    this.tokenMatchValue = roleMember.tokenMatchValue;
    this.roleId = roleMember.roleId;
    this.description = roleMember.description;
  }

  /**
   * @return ID
   */
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
   * @return type
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
   * @return ID
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
   * @return type
   */
  public AccessMatchType getAccessMatchType() {
    return AccessMatchType.matchFromDatabase(tokenMatchOperator);
  }

  /**
   * @return key
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

  /**
   * @return op
   */
  public int getTokenMatchOperator() {
    return tokenMatchOperator;
  }

  /**
   * @param aTokenMatchOperator op
   */
  public void setTokenMatchOperator(final int aTokenMatchOperator) {
    this.tokenMatchOperator = aTokenMatchOperator;
  }

  /**
   * @return value
   */
  public String getTokenMatchValue() {
    return tokenMatchValue;
  }

  /**
   * @param aTokenMatchValue value
   */
  public void setTokenMatchValue(final String aTokenMatchValue) {
    this.tokenMatchValue = aTokenMatchValue;
  }


  /**
   * @return id
   */
  public int getRoleId() {
    return roleId;
  }

  /**
   * @param aRoleId id
   */
  public void setRoleId(final int aRoleId) {
    this.roleId = aRoleId;
  }

  /**
   * @return desc
   */
  public String getDescription() {
    return description;
  }

  /**
   * @param aDescription desc
   */
  public void setDescription(final String aDescription) {
    this.description = aDescription;
  }
}
