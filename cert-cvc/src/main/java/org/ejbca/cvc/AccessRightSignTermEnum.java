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
 * Represents Access Rights for Inspection Systems. Use with OID
 * CVCObjectIdentifiers.id_EAC_ST. Described in the EAC 2.1 spec part 3 page 70.
 *
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 */
public enum AccessRightSignTermEnum implements AccessRights {
    /** PAram. */
  ACCESS_NONE(0x00),
    /** PAram. */
  ACCESS_SIGN(0x01),
    /** PAram. */
  ACCESS_QUALSIGN(0x02),
    /** PAram. */
  ACCESS_SIGN_AND_QUALSIGN(0x03);
  // bit 0x4 and 0x8 are Reserved for Future Use

    /** PAram. */
  private byte value;

  AccessRightSignTermEnum(final int avalue) {
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
   *
   * @return bool
   */
  public boolean allowsSignature() {
    return (this.value & ACCESS_SIGN.value) != 0;
  }

  /**   *
   * @return BOOl
   */
  public boolean allowsQualifiedSignature() {
    return (this.value & ACCESS_QUALSIGN.value) != 0;
  }

  @Override
  public byte[] getEncoded() {
    return new byte[] {value};
  }

  @Override
  public String toString() {
    switch (this) {
      case ACCESS_SIGN:
        return "Signature";
      case ACCESS_QUALSIGN:
        return "Qualified_Signature";
      case ACCESS_SIGN_AND_QUALSIGN:
        return "Signature_and_Qualified_Signature";
      case ACCESS_NONE:
        return "none";
      default: break;
    }
    throw new IllegalStateException("Enum case not handled");
  }
}
