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
package org.ejbca.ra;

import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.roles.member.RoleMember;

/**
 * @version $Id: RaRoleMemberGUIInfo.java 25581 2017-03-22 14:34:02Z samuellb $
 */
public final class RaRoleMemberGUIInfo {

      /** Param. */
  private final RoleMember roleMember;
  /** Param. */
  private final String caName;
  /** Param. */
  private final String roleName;
  /** Param. */
  private final String roleNamespace;
  /** Param. */
  private final String tokenTypeText;
  /** Param. */
  private final boolean tokenMatchValueIsLink;

  /**
   * @param aroleMember member
   * @param acaName name
   * @param aroleName Name
   * @param aroleNamespace Name
   * @param atokenTypeText type
   */
  public RaRoleMemberGUIInfo(
      final RoleMember aroleMember,
      final String acaName,
      final String aroleName,
      final String aroleNamespace,
      final String atokenTypeText) {
    this.roleMember = aroleMember;
    this.caName = acaName;
    this.roleName = aroleName;
    this.roleNamespace = aroleNamespace;
    this.tokenTypeText = atokenTypeText;
    this.tokenMatchValueIsLink =
        X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(
                aroleMember.getTokenType())
            && aroleMember.getTokenMatchKey()
                == X500PrincipalAccessMatchValue.WITH_SERIALNUMBER
                    .getNumericValue();
  }

  /**
   * @return role
   */
  public RoleMember getRoleMember() {
    return roleMember;
  }

  /**
   * @return name
   */
  public String getCaName() {
    return caName;
  }

  /**
   * @return name
   */
  public String getRoleName() {
    return roleName;
  }

  /**
   * @return name
   */
  public String getRoleNamespace() {
    return roleNamespace;
  }

  /**
   * @return name
   */
  public String getTokenTypeText() {
    return tokenTypeText;
  }

  /**
   * @return bool
   */
  public boolean getTokenMatchValueIsLink() {
    return tokenMatchValueIsLink;
  }
}
