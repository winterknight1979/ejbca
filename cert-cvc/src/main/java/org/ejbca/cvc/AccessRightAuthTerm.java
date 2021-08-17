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

import java.io.Serializable;
import org.ejbca.cvc.util.StringConverterUtil;

/**
 * Represents Access Rights for Inspection Systems. Use with OID
 * CVCObjectIdentifiers.id_EAC_AT. Described in the EAC 2.1 spec part 3 page 69.
 *
 * @author Samuel Lidén Borell, PrimeKey Solutions AB
 * @version $Id$
 */
public class AccessRightAuthTerm implements AccessRights, Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private static final int MAX_BIT = 37;

  // Write access
  /** Param. */
  public static final int BIT_WRITE_DG17 = 37;
  /** Param. */
  public static final int BIT_WRITE_DG18 = 36;
  /** Param. */
  public static final int BIT_WRITE_DG19 = 35;
  /** Param. */
  public static final int BIT_WRITE_DG20 = 34;
  /** Param. */
  public static final int BIT_WRITE_DG21 = 33;

  // Read access
  /** Param. */
  public static final int BIT_READ_DG21 = 28;
  /** Param. */
  public static final int BIT_READ_DG20 = 27;
  /** Param. */
  public static final int BIT_READ_DG19 = 26;
  /** Param. */
  public static final int BIT_READ_DG18 = 25;
  /** Param. */
  public static final int BIT_READ_DG17 = 24;
  /** Param. */
  public static final int BIT_READ_DG16 = 23;
  /** Param. */
  public static final int BIT_READ_DG15 = 22;
  /** Param. */
  public static final int BIT_READ_DG14 = 21;
  /** Param. */
  public static final int BIT_READ_DG13 = 20;
  /** Param. */
  public static final int BIT_READ_DG12 = 19;
  /** Param. */
  public static final int BIT_READ_DG11 = 18;
  /** Param. */
  public static final int BIT_READ_DG10 = 17;
  /** Param. */
  public static final int BIT_READ_DG9 = 16;
  /** Param. */
  public static final int BIT_READ_DG8 = 15;
  /** Param. */
  public static final int BIT_READ_DG7 = 14;
  /** Param. */
  public static final int BIT_READ_DG6 = 13;
  /** Param. */
  public static final int BIT_READ_DG5 = 12;
  /** Param. */
  public static final int BIT_READ_DG4 = 11;
  /** Param. */
  public static final int BIT_READ_DG3 = 10;
  /** Param. */
  public static final int BIT_READ_DG2 = 9;
  /** Param. */
  public static final int BIT_READ_DG1 = 8;

  // Special functions
  /** Param. */
  public static final int BIT_INSTALL_QUALIFIED_CERT = 7;
  /** Param. */
  public static final int BIT_INSTALL_CERT = 6;
  /** Param. */
  public static final int BIT_PIN_MANAGEMENT = 5;
  /** Param. */
  public static final int BIT_CAN_ALLOWED = 4;
  /** Param. */
  public static final int BIT_PRIVILEGED_TERMINAL = 3;
  /** Param. */
  public static final int BIT_RESTRICTED_IDENTIFICATION = 2;
  /** Param. */
  public static final int BIT_COMMUNITY_ID_VERIFICATION = 1;
  /** Param. */
  public static final int BIT_AGE_VERIFICATION = 0;

  /** Param. */
  private final byte[] bytes;
  /** Param. */
  private final int len = 5;

  /** Constructor. */
  public AccessRightAuthTerm() {
    this.bytes = new byte[len];
  }

  /**
   * @param abytes bytes
   */
  public AccessRightAuthTerm(final byte[] abytes) {
    if (abytes.length != len) {
      throw new IllegalArgumentException(
          "byte array length must be 5, was " + abytes.length);
    }
    final int mask = 0xc0;
    this.bytes = abytes.clone();
    this.bytes[0] &= ~mask; // Clear role bits
  }

  /**
   * @param bitNumber NUM
   * @return FLAG
   */
  public boolean getFlag(final int bitNumber) {
    if (bitNumber < 0 || bitNumber > MAX_BIT) {
      throw new ArrayIndexOutOfBoundsException(bitNumber);
    }
    final int shift = 3;
    final int mask = 0x7;
    int byteindex = bytes.length - 1 - (bitNumber >> shift);
    int bit = (bytes[byteindex] >> (bitNumber & mask)) & 1;
    return bit == 1;
  }

  /**
   * @param bitNumber num
   * @param state state
   */
  public void setFlag(final int bitNumber, final boolean state) {
    if (bitNumber < 0 || bitNumber > MAX_BIT) {
      throw new ArrayIndexOutOfBoundsException(bitNumber);
    }
    final int shift = 3;
    int byteindex = bytes.length - 1 - (bitNumber >> shift);
    final int mask = 0x7;
    int bit = 1 << (bitNumber & mask);
    bytes[byteindex] &= ~bit; // clear bit
    bytes[byteindex] |= state ? bit : 0; // set bit
  }

  @Override
  public byte[] getEncoded() {
    return bytes.clone();
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i <= MAX_BIT; i++) {
      if (getFlag(i)) {
        sb.append(flagToString(i));
        sb.append(", ");
      }
    }
    if (sb.length() > 0) {
      sb.delete(sb.length() - 2, sb.length());
    }
    return sb.toString();
  }

  private static String flagToString(final int flag) {
    if (flag < 0 || flag > MAX_BIT) {
      throw new ArrayIndexOutOfBoundsException(flag);
    }
    // Data groups
    if (flag >= BIT_WRITE_DG21) {
      final int offset = 21;
      return "W-DG" + (offset + BIT_WRITE_DG21 - flag);
    }
    if (flag > BIT_READ_DG21) {
      return "RFU-" + flag;
    } // reserved for future use
    if (flag >= BIT_READ_DG1) {
      return "R-DG" + (flag - BIT_READ_DG1 + 1);
    }
    // Special functions
    return flagSwitch(flag);
  }

/**
 * @param flag flag
 * @return val
 * @throws IllegalStateException fail
 */
private static String flagSwitch(final int flag) throws IllegalStateException {
    switch (flag) {
      case BIT_INSTALL_QUALIFIED_CERT:
        return "Install Qualified Certificate";
      case BIT_INSTALL_CERT:
        return "Install Certificate";
      case BIT_PIN_MANAGEMENT:
        return "PIN Management";
      case BIT_CAN_ALLOWED:
        return "CAN Allowed";
      case BIT_PRIVILEGED_TERMINAL:
        return "Privileged Terminal";
      case BIT_RESTRICTED_IDENTIFICATION:
        return "Restricted Identification";
      case BIT_COMMUNITY_ID_VERIFICATION:
        return "Community ID Verification";
      case BIT_AGE_VERIFICATION:
        return "Age Verification";
      default:
        throw new IllegalStateException();
    }
}

  @Override
  public String name() {
    return "ACCESS_RIGHT_AT_" + StringConverterUtil.byteToHex(bytes);
  }
}
