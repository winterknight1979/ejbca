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
 * Definitions of the applications specific tags in CV-certificates.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public enum CVCTagEnum {

  // Certificate fields
      /** Param. */
  CV_CERTIFICATE(0x7F21, true),
  /** Param. */
  CERTIFICATE_BODY(0x7F4E, true),
  /** Param. */
  PROFILE_IDENTIFIER(0x5F29),
  /** Param. */
  PUBLIC_KEY(0x7F49, true),
  /** Param. */
  HOLDER_REFERENCE(0x5F20),
  /** Param. */
  HOLDER_AUTH_TEMPLATE(0x7F4C, true),
  /** Param. */
  EFFECTIVE_DATE(0x5F25),
  /** Param. */
  EXPIRATION_DATE(0x5F24),
  /** Param. */
  SIGNATURE(0x5F37),

  /** Param. */
  OID(0x06),
  /** Param. */
  CA_REFERENCE(0x42),
  /** Param. */
  REQ_AUTHENTICATION(0x67, true),

  // Field for Holder Authorization Template (actually, it's "Arbitrary data"
  // according to the spec)
  /** Param. */
  ROLE_AND_ACCESS_RIGHTS(0x53),

  // Fields for Public Key
  /** Param. */
  MODULUS(0x81),
  /** Param. */
  EXPONENT(0x82),
  // Only for EC
  /** Param. */
  COEFFICIENT_A(0x82), // Note: this has the same value as EXPONENT...
  /** Param. */
  COEFFICIENT_B(0x83),
  /** Param. */
  BASE_POINT_G(0x84),
  /** Param. */
  BASE_POINT_R_ORDER(0x85),
  /** Param. */
  PUBLIC_POINT_Y(0x86),
  /** Param. */
  COFACTOR_F(0x87),

  // Certificate Extensions
  /** Param. */
  CERTIFICATE_EXTENSIONS(0x65, true),
  /** Param. */
  DISCRETIONARY_DATA_TEMPLATE(
      0x73, true), // each extension consists of a pair of
  // OID and ARBITRARY_DATA
  /** Param. */
  ARBITRARY_DATA(0x53); // same value as ROLE_AND_ACCESS_RIGHTS above

      /** Param. */
  private int value;
  /** Param. */
  private boolean isSequence;

  /**
   * @param avalue bool
   */
  CVCTagEnum(final int avalue) {
    this(avalue, false);
  }

  /**
   * @param avalue val
   * @param aisSequence bool
   */
  CVCTagEnum(final int avalue, final boolean aisSequence) {
    this.value = avalue;
    this.isSequence = aisSequence;
  }

  /**
   * Returns the value of the tag.
   *
   * @return val
   */
  public int getValue() {
    return value;
  }

  /**
   * Returns flag indicating if this field is a Sequence.
   *
   * @return bool
   */
  public boolean isSequence() {
    // According to ITU-T X.690: if bit 6 in the first of two bytes
    // is 0 then the encoding is 'primitive'.
    // Note: this doesn't work here because REQ_AUTHENTICATION has a value of
    // 0x67!
    // return ((value >>> 8) & 0x20) != 0;
    return isSequence;
  }
}
