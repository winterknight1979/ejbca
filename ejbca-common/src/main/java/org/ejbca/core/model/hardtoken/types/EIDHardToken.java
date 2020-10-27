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
 * EIDHardToken is a class defining data stored in database for a EID token.
 *
 * <p>OBSERVE This class should only be used for backward compability with EJBCA
 * 2.0
 *
 * @version $Id: EIDHardToken.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class EIDHardToken extends HardToken {
  private static final long serialVersionUID = -3757040668436850815L;
  // Public Constants
  /** Config. */
  public static final String INITIALBASICPIN = "INITIALBASICPIN";
  /** Config. */
  public static final String BASICPUK = "BASICPUK";
  /** Config. */
  public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
  /** Config. */
  public static final String SIGNATUREPUK = "SIGNATUREPUK";
  /** Config. */
  public static final int THIS_TOKENTYPE = SecConst.TOKEN_EID;

  /** Config. */
  public static final String[] FIELDSWITHPUK =
      new String[] {
        INITIALBASICPIN,
        BASICPUK,
        EMPTYROW_FIELD,
        INITIALSIGNATUREPIN,
        SIGNATUREPUK
      };
  /** Config. */
  public static final int[] DATATYPESWITHPUK =
      new int[] {STRING, STRING, EMPTYROW, STRING, STRING};
  /** Config. */
  public static final String[] FIELDTEXTSWITHPUK =
      new String[] {
        INITIALBASICPIN,
        BASICPUK,
        EMPTYROW_FIELD,
        INITIALSIGNATUREPIN,
        SIGNATUREPUK
      };

  /** Config. */
  public static final String[] FIELDSWITHOUTPUK = new String[] {};
  /** Config. */
  public static final int[] DATATYPESWITHOUTPUK = new int[] {};
  /** Config. */
  public static final String[] FIELDTEXTSWITHOUTPUK = new String[] {};

  // Public Methods

  /**
   * Creates a certificate with the characteristics of an end user.
   *
   * @param includePUK Boolean
   */
  public EIDHardToken(final boolean includePUK) {
    super(includePUK);
    setInitialBasicPIN("");
    setBasicPUK("");
    setInitialSignaturePIN("");
    setSignaturePUK("");

    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
  }

  // Public Methods.
  /**
   * @return PIN
   */
  public String getInitialBasicPIN() {
    return (String) data.get(INITIALBASICPIN);
  }

  /**
   * DOCUMENT ME!
   *
   * @param initialbasicpin DOCUMENT ME!
   */
  public void setInitialBasicPIN(final String initialbasicpin) {
    data.put(INITIALBASICPIN, initialbasicpin);
  }

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public String getBasicPUK() {
    return (String) data.get(BASICPUK);
  }

  /**
   * DOCUMENT ME!
   *
   * @param basicpuk DOCUMENT ME!
   */
  public void setBasicPUK(final String basicpuk) {
    data.put(BASICPUK, basicpuk);
  }

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public String getInitialSignaturePIN() {
    return (String) data.get(INITIALSIGNATUREPIN);
  }

  /**
   * DOCUMENT ME!
   *
   * @param initialsignaturepin DOCUMENT ME!
   */
  public void setInitialSignaturePIN(final String initialsignaturepin) {
    data.put(INITIALSIGNATUREPIN, initialsignaturepin);
  }

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public String getSignaturePUK() {
    return (String) data.get(SIGNATUREPUK);
  }

  /**
   * DOCUMENT ME!
   *
   * @param signaturepuk DOCUMENT ME!
   */
  public void setSignaturePUK(final String signaturepuk) {
    data.put(SIGNATUREPUK, signaturepuk);
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

  // Private fields.
}
