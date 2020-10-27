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

package org.ejbca.core.model.hardtoken.types;

import org.ejbca.core.model.SecConst;

/**
 * TurkishEIDHardToken is a class defining data stored in database for a Turkish
 * EID token.
 *
 * @version $Id: TurkishEIDHardToken.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class TurkishEIDHardToken extends HardToken {
  private static final long serialVersionUID = -8771180471734319021L;

  // Public Constants
  /** Config. */
  public static final int THIS_TOKENTYPE = SecConst.TOKEN_TURKISHEID;

  /** Config. */
  public static final String INITIALPIN = "INITIALPIN";
  /** Config. */
  public static final String PUK = "PUK";

  /** Config. */
  public static final String[] FIELDSWITHPUK = {
    INITIALPIN, PUK, EMPTYROW_FIELD
  };
  /** Config. */
  public static final int[] DATATYPESWITHPUK = {STRING, STRING, EMPTYROW};
  /** Config. */
  public static final String[] FIELDTEXTSWITHPUK = {
    INITIALPIN, PUK, EMPTYROW_FIELD
  };
  /** Config. */
  public static final String[] FIELDSWITHOUTPUK = new String[] {};
  /** Config. */
  public static final int[] DATATYPESWITHOUTPUK = new int[] {};
  /** Config. */
  public static final String[] FIELDTEXTSWITHOUTPUK = new String[] {};

  // Public Methods
  /**
   * Constructor to use.
   *
   * @param initialpin PIN
   * @param puk PUK
   * @param hardtokenprofileid Profile
   */
  public TurkishEIDHardToken(
      final String initialpin, final String puk, final int hardtokenprofileid) {
    super(true);
    setInitialPIN(initialpin);
    setPUK(puk);

    setTokenProfileId(hardtokenprofileid);

    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
  }

  /**
   * Constructor only to be used internally.
   *
   * @param includePUK bool
   */
  public TurkishEIDHardToken(final boolean includePUK) {
    super(includePUK);
    if (!includePUK) {
      setInitialPIN("");
      setPUK("");
    }
    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
  }

  // Public Methods.
  /**
   * @return pin
   */
  public String getInitialPIN() {
    return (String) data.get(INITIALPIN);
  }

  /**
   * @param initialpin pin
   */
  public void setInitialPIN(final String initialpin) {
    data.put(INITIALPIN, initialpin);
  }

  /**
   * @return puk
   */
  public String getPUK() {
    return (String) data.get(PUK);
  }

  /**
   * @param puk puk
   */
  public void setPUK(final String puk) {
    data.put(PUK, puk);
  }
  @Override
  public int[] getDataTypes(final boolean includePUK) {
    if (includePUK) {
      return DATATYPESWITHPUK;
    }
    return DATATYPESWITHOUTPUK;
  }
 @Override
  public String[] getFieldTexts(final boolean includePUK) {
    if (includePUK) {
      return FIELDTEXTSWITHPUK;
    }
    return FIELDTEXTSWITHOUTPUK;
  }

  @Override
  public String[] getFields(final boolean includePUK) {
    if (includePUK) {
      return FIELDSWITHPUK;
    }
    return FIELDSWITHOUTPUK;
  }
}
