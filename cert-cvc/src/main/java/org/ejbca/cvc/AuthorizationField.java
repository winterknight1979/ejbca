/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import org.ejbca.cvc.util.StringConverter;

/**
 * Represents field 'Roles and access rights' i CVC.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class AuthorizationField extends AbstractDataField {

  private static final long serialVersionUID = -5478250843535697147L;

  /** Param. */
  private AuthorizationRole role;
  /** Param. */
  private AccessRights rights;

  AuthorizationField() {
    super(CVCTagEnum.ROLE_AND_ACCESS_RIGHTS);
  }

  /**
   * Constructor taking an AuthorizationRole and an AccessRight. The parameters
   * should be of matching types (e.g. AuthorizationRoleAuthTermEnum and
   * AccessRightAuthTerm)
   *
   * @param arole role
   * @param arights rights
   */
  AuthorizationField(final AuthorizationRole arole, final
          AccessRights arights) {
    this();
    this.role = arole;
    this.rights = arights;
  }

  AuthorizationField(
      final AuthorizationRoleEnum arole, final AccessRightEnum arights) {
    this((AuthorizationRole) arole, (AccessRights) arights);
  }

  /**
   * Constructor for decoding DER-encoded data. The fixEnumTypes method must be
   * called as soon as the OID is known (CVCObjectIdentifiers.id_EAC_ePassport,
   * etc.)
   *
   * @param data data
   */
  AuthorizationField(final byte[] data) {
    this();
    if (data.length < 1) {
      throw new IllegalArgumentException(
          "byte array length must be at least 1");
    }
    this.role = new AuthorizationRoleRawValue(data[0]);
    this.rights = new AccessRightsRawValue(data);
  }

  /**
   * Returns role.
 * @return  enum
   *
   * @throws UnsupportedOperationException if the rights is of authentication or
   *     signing terminal type.
   * @deprecated Use {@link #getAuthRole()} instead
   */
  @Deprecated
  public AuthorizationRoleEnum getRole() {
    if (!(role instanceof AuthorizationRoleEnum)) {
      throw new UnsupportedOperationException(
          "Attempted to use deprecated getRole method with in an AT or ST"
              + " certificate chain. It handles IS only.");
    }
    return (AuthorizationRoleEnum) this.role;
  }

  /**
   * Returns the role. The return value is one of the AuthorizationRole* types.
 * @return Role
   *
   * @see AuthorizationRoleEnum
   * @see AuthorizationRoleAuthTermEnum
   * @see AuthorizationRoleSignTermEnum
   */
  public AuthorizationRole getAuthRole() {
    return this.role;
  }

  /**
   * Returns access rights.
 * @return  enum
   *
   * @throws UnsupportedOperationException if the rights is of authentication or
   *     signing terminal type.
   * @deprecated Use {@link #getAccessRights()} instead
   */
  @Deprecated
  public AccessRightEnum getAccessRight() {
    if (!(rights instanceof AccessRightEnum)) {
      throw new UnsupportedOperationException(
          "Attempted to use deprecated getAccessRight method with an AT or ST"
              + " certificate chain. It handles IS only.");
    }
    return (AccessRightEnum) this.rights;
  }

  /**
   * Returns access rights. The return value is one of the AccessRight* types.
 * @return  rights
   *
   * @see AccessRightEnum
   * @see AccessRightAuthTerm
   * @see AccessRightSignTermEnum
   */
  public AccessRights getAccessRights() {
    return this.rights;
  }

  @Override
  protected byte[] getEncoded() {
    byte[] encoded = rights.getEncoded();
    encoded[0] |= role.getValue();
    return encoded;
  }

  @Override
  protected String valueAsText() {
    return StringConverter.byteToHex(getEncoded()) + ": " + role + "/" + rights;
  }

  /** Translates a byte to AuthorizationRole.
 * @param oid OID
 * @param b  Byte
 * @return Role */
  private static AuthorizationRole getRoleFromByte(
      final OIDField oid, final byte b) {
    final int mask = 0xc0;
    byte testVal = (byte) (b & mask);

    AuthorizationRole[] values;
    if (CVCObjectIdentifiers.ID_EAC_PASSPORT.equals(oid)) {
      values = AuthorizationRoleEnum.values();
    } else if (CVCObjectIdentifiers.ID_EAC_ROLES_ST.equals(oid)) {
      values = AuthorizationRoleSignTermEnum.values();
    } else if (CVCObjectIdentifiers.ID_EAC_ROLES_AT.equals(oid)) {
      values = AuthorizationRoleAuthTermEnum.values();
    } else {
      return new AuthorizationRoleRawValue(b);
    }

    AuthorizationRole foundRole = null;
    for (AuthorizationRole aRole : values) {
      if (testVal == aRole.getValue()) {
        foundRole = aRole;
        break;
      }
    }
    return foundRole;
  }

  /** Translates a byte array to AccessRights.
 * @param oid OID
 * @param data Dats=a
 * @return Rights */
  private static AccessRights getRightsFromBytes(
      final OIDField oid, final byte[] data) {
    final int mask = 0x03;
    if (CVCObjectIdentifiers.ID_EAC_PASSPORT.equals(oid)) {
      if (data.length != 1) {
        throw new IllegalArgumentException(
            "byte array length must be 1, was " + data.length);
      }
      byte testVal = (byte) (data[0] & mask);
      AccessRightEnum foundRight = null;
      for (AccessRightEnum right : AccessRightEnum.values()) {
        if (testVal == right.getValue()) {
          foundRight = right;
          break;
        }
      }
      return foundRight;
    } else if (CVCObjectIdentifiers.ID_EAC_ROLES_ST.equals(oid)) {
      if (data.length != 1) {
        throw new IllegalArgumentException(
            "byte array length must be 1, was " + data.length);
      }
      byte testVal = (byte) (data[0] & mask);
      AccessRightSignTermEnum foundRight = null;
      for (AccessRightSignTermEnum right : AccessRightSignTermEnum.values()) {
        if (testVal == right.getValue()) {
          foundRight = right;
          break;
        }
      }
      return foundRight;
    }
    final int len = 5;
    if (CVCObjectIdentifiers.ID_EAC_ROLES_AT.equals(oid)) {
      if (data.length != len) {
        throw new IllegalArgumentException(
            "byte array length must be 5, was " + data.length);
      }
      return new AccessRightAuthTerm(data);
    } else {
      return new AccessRightsRawValue(data);
    }
  }

  /**
   * Re-creates the role/rights objects as the correct classes. This is
   * necessary when deserializing from binary data.
   * @param oid OID
   */
  void fixEnumTypes(final OIDField oid) {
    role = getRoleFromByte(oid, role.getValue());
    rights = getRightsFromBytes(oid, rights.getEncoded());
  }
}
