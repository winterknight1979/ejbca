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
 * Base class for Certificate Authority/Holder Reference. Since the only
 * difference between these two is the tag we can reuse code for them.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public abstract class ReferenceField extends AbstractDataField {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private String country = null;
  /** Param. */
  private String mnemonic = null;
  /** Param. */
  private String sequence = null;

  /**
   * Constructs a new instance from separate fields.
 * @param tag tag.
   *
   * @param acountry - CountryCode according to ISO 3166-1 ALPHA-2
   *     (2 characters)
   * @param amnemonic - Holder Mnemonic (up to 9 characters)
   * @param seq - Sequence Number (exactly 5 alphanumeric characters)
   */
  public ReferenceField(
      final CVCTagEnum tag,
      final String acountry,
      final String amnemonic,
      final String seq) {
    super(tag);
      final int mLen = 9;
      final int len = 5;

    if (acountry.length() != 2) {
      throw new IllegalArgumentException(
          "Country code length must be 2, was " + acountry.length());
    }
    if (!isValidCountry(acountry)) {
      throw new IllegalArgumentException("Unknown country code: " + acountry);
    }
    if (amnemonic.length() == 0) {
      throw new IllegalArgumentException(
          "Holder mnemonic too short, must have at least one character");
    }
    if (amnemonic.length() > mLen) {
      throw new IllegalArgumentException(
          "Holder mnemonic too long, max=9, was " + amnemonic.length());
    }
    if (seq.length() != len) {
      throw new IllegalArgumentException(
          "Sequence number must have length 5, was " + seq.length());
    }
    for (int i = 0; i < seq.length(); i++) {
      // Validate character types
      char c = seq.charAt(i);
      if (!Character.isLetterOrDigit(c)) {
        throw new IllegalArgumentException(
            "Sequence number can only contain alphanumerics: " + seq);
      }
    }

    this.country = acountry;
    this.mnemonic = amnemonic;
    this.sequence = seq;
  }

  /**
   * Constructs a new instance by parsing DER-encoded data.
   *
   * @param tag Tag
   * @param data Data
   */
  protected ReferenceField(final CVCTagEnum tag, final byte[] data) {
    super(tag);
    final int offset = 5;
    String dataStr = new String(data);
    this.country = dataStr.substring(0, 2); // Has always length = 2
    this.mnemonic = dataStr.substring(2, dataStr.length() - offset);
    this.sequence = dataStr.substring(dataStr.length() - offset); // Has always
    // length = 5
  }

  /**
   * Returns the value as a concatenation of country, mnemonic and sequence.
   *
   * @return value
   */
  public String getConcatenated() {
    return country + mnemonic + sequence;
  }

  /**
   * Returns country.
   *
   * @return country
   */
  public String getCountry() {
    return country;
  }

  /**
   * Returns mnemonic.
   *
   * @return mnem
   */
  public String getMnemonic() {
    return mnemonic;
  }

  /**
   * Returns sequence.
   *
   * @return seq
   */
  public String getSequence() {
    return sequence;
  }

  @Override
  protected byte[] getEncoded() {
    return getConcatenated().getBytes();
  }

  private boolean okChar(final char c) {
    return c >= 'A' && c <= 'Z';
  }

  // Validates country code according to ISO 3166. AR: Not anymore :-) Testing
  // needs "unusual" countries
  private boolean isValidCountry(final String countryCode) {
    return okChar(countryCode.charAt(0)) && okChar(countryCode.charAt(1));
  }

  @Override
  public String valueAsText() {
    return country + "/" + mnemonic + "/" + sequence;
  }
}
