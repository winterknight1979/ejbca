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

package org.ejbca.core.model.hardtoken;

import java.io.Serializable;

/**
 * This is a value class containing the data relating to a hard token issuer
 * sent between server and clients.
 *
 * @version $Id: HardTokenIssuerInformation.java 22117 2015-10-29 10:53:42Z
 *     mikekushner $
 */
public class HardTokenIssuerInformation
    implements Serializable, Comparable<HardTokenIssuerInformation> {

  private static final long serialVersionUID = 4736415526364602434L;

  /** ID. */
  private int hardtokenissuerid;
  /** Alias. */
  private String alias;
  /** ID. */
  private int roleDataId;
  /**
   * Issuer.
   */
  private HardTokenIssuer hardtokenissuer;

  /**
   * @param aHardtokenissuerid ID
   * @param anAlias Alias
   * @param aRoleDataId Role
   * @param aHardtokenissuer Issuer
   */
  public HardTokenIssuerInformation(
      final int aHardtokenissuerid,
      final String anAlias,
      final int aRoleDataId,
      final HardTokenIssuer aHardtokenissuer) {
    this.hardtokenissuerid = aHardtokenissuerid;
    this.alias = anAlias;
    this.roleDataId = aRoleDataId;
    this.hardtokenissuer = aHardtokenissuer;
  }

  /**
   * @return ID
   */
  public int getHardTokenIssuerId() {
    return this.hardtokenissuerid;
  }

  /**
   * @param aHardtokenissuerid ID
   */
  public void setHardTokenIssuerId(final int aHardtokenissuerid) {
    this.hardtokenissuerid = aHardtokenissuerid;
  }

  /**
   * @return alias
   */
  public String getAlias() {
    return this.alias;
  }

  /**
   * @param anAlias alias
   */
  public void setAlias(final String anAlias) {
    this.alias = anAlias;
  }

  /**
   * @return ID
   */
  public int getRoleDataId() {
    return this.roleDataId;
  }

  /**
   * @param aRoleDataId ID
   */
  public void roleDataId(final int aRoleDataId) {
    this.roleDataId = aRoleDataId;
  }

  /**
   * @return Issuer
   */
  public HardTokenIssuer getHardTokenIssuer() {
    return this.hardtokenissuer;
  }

  /**
   * @param aHardtokenissuer issuer
   */
  public void setHardTokenIssuer(final HardTokenIssuer aHardtokenissuer) {
    this.hardtokenissuer = aHardtokenissuer;
  }

  /**
   * @param obj object
   * @return comparison
   */
  public int compareTo(final HardTokenIssuerInformation obj) {
    return this.alias.compareTo(obj.getAlias());
  }
}
