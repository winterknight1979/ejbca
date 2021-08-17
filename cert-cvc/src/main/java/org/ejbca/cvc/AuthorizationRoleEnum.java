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

/**
 * Definitions of roles in CVC.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public enum AuthorizationRoleEnum implements AuthorizationRole {
    /** Param. */
  CVCA(0xC0),
    /** Param. */
  DV_D(0x80),
    /** Param. */
  DV_F(0x40),
    /** Param. */
  IS(0x00);

    /** Param. */
  private byte value;

  /**
   * @param avalue val
   */
  AuthorizationRoleEnum(final int avalue) {
    this.value = (byte) avalue;
  }

  /**
   * Returns the value as a bitmap.
   *
   * @return value
   */
  @Override
  public byte getValue() {
    return value;
  }

  @Override
  public boolean isCVCA() {
    return this == CVCA;
  }

  @Override
  public boolean isDV() {
    return this == DV_D || this == DV_F;
  }

  @Override
  public boolean isDomesticDV() {
    return this == DV_D;
  }

  @Override
  public boolean isForeignDV() {
    return this == DV_F;
  }

  @Override
  public boolean isAccreditationBodyDV() {
    return false;
  }

  @Override
  public boolean isCertificationServiceProviderDV() {
    return false;
  }

  @Override
  public boolean isIS() {
    return this == IS;
  }

  @Override
  public boolean isAuthenticationTerminal() {
    return false;
  }

  @Override
  public boolean isSignatureTerminal() {
    return false;
  }

  // Used by e.g. AuthorizationField.valueAsText()
  @Override
  public String toString() {
    switch (this) {
      case CVCA:
        return "CVCA";
      case DV_D:
        return "DV-domestic";
      case DV_F:
        return "DV-foreign";
      case IS:
        return "IS";
      default: break;
    }
    throw new IllegalStateException("Enum case not handled");
  }
}
