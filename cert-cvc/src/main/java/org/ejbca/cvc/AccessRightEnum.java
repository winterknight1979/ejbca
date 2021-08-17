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
 * Represents Access Rights for Authentication Terminals. Use with OID
 * CVCObjectIdentifiers.id_EAC_AuthTerm. Described in the EAC 1.11 spec page 36.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public enum AccessRightEnum implements AccessRights {
      /** Param. */
  READ_ACCESS_NONE(0x00),
  /** Param. */
  READ_ACCESS_DG3(0x01),
  /** Param. */
  READ_ACCESS_DG4(0x02),
  /** Param. */
  READ_ACCESS_DG3_AND_DG4(0x03);
  // bit 0x4 and 0x8 are Reserved for Future Use

  /** Param. */
  private byte value;

  AccessRightEnum(final int avalue) {
    this.value = (byte) avalue;
  }

  /**
   * Returns the tag as a bitmap.
   *
   * @return value
   */
  public byte getValue() {
    return value;
  }

  /**
   * @return bool
   */
  public boolean hasDG3() {
    return (this.value & READ_ACCESS_DG3.value) != 0;
  }

  /**   *
   * @return bool
   */
  public boolean hasDG4() {
    return (this.value & READ_ACCESS_DG4.value) != 0;
  }

  @Override
  public byte[] getEncoded() {
    return new byte[] {value};
  }

  @Override
  public String toString() {
    switch (this) {
      case READ_ACCESS_DG3_AND_DG4:
        return "DG3+DG4";
      case READ_ACCESS_DG4:
        return "DG4";
      case READ_ACCESS_DG3:
        return "DG3";
      case READ_ACCESS_NONE:
        return "none";
      default: break;
    }
    throw new IllegalStateException("Enum case not handled");
  }
}
