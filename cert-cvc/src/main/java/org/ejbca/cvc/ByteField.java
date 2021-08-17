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

import java.math.BigInteger;
import org.ejbca.cvc.util.StringConverterUtil;

/**
 * Generic field representing binary data (or Octet String).
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class ByteField extends AbstractDataField {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private byte[] data;
  /** Param. */
  private boolean showBitLength = false;

  /**
   * Constructor taking tag.
   *
   * @param tag tag
   */
  ByteField(final CVCTagEnum tag) {
    super(tag);
  }

  /**
   * Constructor taking tag and data .
   *
   * @param tag tag
   * @param adata data
   */
  ByteField(final CVCTagEnum tag, final byte[] adata) {
    this(tag, adata, false);
  }

  /**
   * Constructor taking tag, data and flag indicating if data length should be
   * shown in valueAsText().
   *
   * @param tag tag
   * @param adata data
   * @param ashowBitLength len
   */
  ByteField(
      final CVCTagEnum tag, final byte[] adata, final boolean ashowBitLength) {
    super(tag);
    this.data = adata;
    this.showBitLength = ashowBitLength;
  }

  /**
   * Returns flag for 'showBitLen'.
   *
   * @return bool
   */
  public boolean isShowBitLength() {
    return showBitLength;
  }

  /**
   * Sets flag 'showBitLen'.
   *
   * @param ashowBitLength - if true then
   * valueAsText() will add an entry showing
   *     the length in bits
   */
  public void setShowBitLength(final boolean ashowBitLength) {
    this.showBitLength = ashowBitLength;
  }

  /**
   * Returns the data.
   *
   * @return data
   */
  public byte[] getData() {
    return data;
  }

  @Override
  protected byte[] getEncoded() {
    return data;
  }

  @Override
  protected String valueAsText() {
    String lenInfo = "";
    // Check if length in bits should be shown
    if (showBitLength) {
      int bitLength = 0;
      if (data != null) {
        BigInteger big = new BigInteger(1, data);
        bitLength = big.bitLength();
      }
      lenInfo = "[" + bitLength + "]  ";
    }
    return lenInfo + StringConverterUtil.byteToHex(data);
  }
}
