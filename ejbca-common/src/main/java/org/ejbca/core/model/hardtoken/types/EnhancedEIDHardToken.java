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
 * EnhancedEIDHardToken is a class defining data stored in database for a
 * Enhanced EID token.
 *
 * @version $Id: EnhancedEIDHardToken.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class EnhancedEIDHardToken extends HardToken {
  private static final long serialVersionUID = 9043768992711957547L;
  // Public Constants
  /** Config. */
  public static final int THIS_TOKENTYPE = SecConst.TOKEN_ENHANCEDEID;
  /** Config. */
  public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
  /** Config. */
  public static final String SIGNATUREPUK = "SIGNATUREPUK";
  /** Config. */
  public static final String INITIALAUTHPIN = "INITIALAUTHPIN";
  /** Config. */
  public static final String AUTHPUK = "AUTHPUK";
  /** Config. */
  public static final String ENCKEYRECOVERABLE = "ENCKEYRECOVERABLE";

  /** Config. */
  public static final String[] FIELDSWITHPUK =
      new String[] {
        INITIALSIGNATUREPIN,
        SIGNATUREPUK,
        EMPTYROW_FIELD,
        INITIALAUTHPIN,
        AUTHPUK,
        EMPTYROW_FIELD,
        ENCKEYRECOVERABLE
      };
  /** Config. */
  public static final int[] DATATYPESWITHPUK =
      new int[] {STRING, STRING, EMPTYROW, STRING, STRING, EMPTYROW, BOOLEAN};
  /** Config. */
  public static final String[] FIELDTEXTSWITHPUK =
      new String[] {
        "INITIALSIGNATUREPIN",
        "SIGNATUREPUK",
        EMPTYROW_FIELD,
        "INITIALAUTHENCPIN",
        "AUTHENCPUK",
        EMPTYROW_FIELD,
        ENCKEYRECOVERABLE
      };

  /** Config. */
  public static final String[] FIELDSWITHOUTPUK =
      new String[] {ENCKEYRECOVERABLE};
  /** Config. */
  public static final int[] DATATYPESWITHOUTPUK = new int[] {BOOLEAN};
  /** Config. */
  public static final String[] FIELDTEXTSWITHOUTPUK =
      new String[] {ENCKEYRECOVERABLE};

  // Public Methods
  /**
   * Constructor to use.
   *
   * @param initialsignaturepin PIN
   * @param signaturepuk PUK
   * @param initialauthencpin PIN
   * @param authencpuk PUK
   * @param enckeyrecoverable bool
   * @param hardtokenprofileid int
   */
  public EnhancedEIDHardToken(
      final String initialsignaturepin,
      final String signaturepuk,
      final String initialauthencpin,
      final String authencpuk,
      final boolean enckeyrecoverable,
      final int hardtokenprofileid) {
    super(true);
    setInitialSignaturePIN(initialsignaturepin);
    setSignaturePUK(signaturepuk);
    setInitialAuthPIN(initialauthencpin);
    setAuthPUK(authencpuk);
    setEncKeyRecoverable(enckeyrecoverable);
    setTokenProfileId(hardtokenprofileid);

    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
  }

  /**
   * Constructor only to be used internally.
   *
   * @param includePUK bool
   */
  public EnhancedEIDHardToken(final boolean includePUK) {
    super(includePUK);
    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
    if (!includePUK) {
      setInitialAuthPIN("");
      setAuthPUK("");
      setInitialSignaturePIN("");
      setSignaturePUK("");
    }
  }

  // Public Methods.

  /**
   * @return pin
   */
  public String getInitialSignaturePIN() {
    return (String) data.get(INITIALSIGNATUREPIN);
  }

  /**
   * @param initialsignaturepin pin
   */
  public void setInitialSignaturePIN(final String initialsignaturepin) {
    data.put(INITIALSIGNATUREPIN, initialsignaturepin);
  }

  /**
   * @return puk
   */
  public String getSignaturePUK() {
    return (String) data.get(SIGNATUREPUK);
  }

  /**
   * @param signaturepuk puk
   */
  public void setSignaturePUK(final String signaturepuk) {
    data.put(SIGNATUREPUK, signaturepuk);
  }

  /**
   * @return pin
   */
  public String getInitialAuthPIN() {
    return (String) data.get(INITIALAUTHPIN);
  }

  /**
   * @param initialauthpin pin
   */
  public void setInitialAuthPIN(final String initialauthpin) {
    data.put(INITIALAUTHPIN, initialauthpin);
  }

  /**
   * @return puk
   */
  public String getAuthPUK() {
    return (String) data.get(AUTHPUK);
  }

  /**
   * @param authpuk puk
   */
  public void setAuthPUK(final String authpuk) {
    data.put(AUTHPUK, authpuk);
  }

  /**
   * @return bool
   */
  public boolean getEncKeyRecoverable() {
    return ((Boolean) data.get(ENCKEYRECOVERABLE)).booleanValue();
  }

  /**
   * @param enckeyrecoverable bool
   */
  public void setEncKeyRecoverable(final boolean enckeyrecoverable) {
    data.put(ENCKEYRECOVERABLE, Boolean.valueOf(enckeyrecoverable));
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
