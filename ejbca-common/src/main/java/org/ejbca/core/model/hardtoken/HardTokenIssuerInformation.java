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

/*
 * HardTokenIssuerData.java
 *
 * Created on den 19 januari 2003, 13:11
 */

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

  private int hardtokenissuerid;
  private String alias;
  private int roleDataId;
  private HardTokenIssuer hardtokenissuer;

  public HardTokenIssuerInformation(
      final int hardtokenissuerid,
      final String alias,
      final int roleDataId,
      final HardTokenIssuer hardtokenissuer) {
    this.hardtokenissuerid = hardtokenissuerid;
    this.alias = alias;
    this.roleDataId = roleDataId;
    this.hardtokenissuer = hardtokenissuer;
  }

  public int getHardTokenIssuerId() {
    return this.hardtokenissuerid;
  }

  public void setHardTokenIssuerId(final int hardtokenissuerid) {
    this.hardtokenissuerid = hardtokenissuerid;
  }

  public String getAlias() {
    return this.alias;
  }

  public void setAlias(final String alias) {
    this.alias = alias;
  }

  public int getRoleDataId() {
    return this.roleDataId;
  }

  public void roleDataId(final int roleDataId) {
    this.roleDataId = roleDataId;
  }

  public HardTokenIssuer getHardTokenIssuer() {
    return this.hardtokenissuer;
  }

  public void setHardTokenIssuer(final HardTokenIssuer hardtokenissuer) {
    this.hardtokenissuer = hardtokenissuer;
  }

  public int compareTo(final HardTokenIssuerInformation obj) {
    return this.alias.compareTo(obj.getAlias());
  }
}
