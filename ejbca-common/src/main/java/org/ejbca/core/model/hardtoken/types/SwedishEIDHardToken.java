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
 * SwedishEIDHardToken is a class defining data stored in database for a Swedish
 * EID token.
 *
 * @version $Id: SwedishEIDHardToken.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class SwedishEIDHardToken extends HardToken {
  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = 5695294040446656470L;

  // Public Constants
  public static final int THIS_TOKENTYPE = SecConst.TOKEN_SWEDISHEID;

  public static final String INITIALAUTHENCPIN = "INITIALAUTHENCPIN";
  public static final String AUTHENCPUK = "AUTHENCPUK";
  public static final String INITIALSIGNATUREPIN = "INITIALSIGNATUREPIN";
  public static final String SIGNATUREPUK = "SIGNATUREPUK";

  public static final String[] FIELDSWITHPUK =
      new String[] {
        INITIALAUTHENCPIN,
        AUTHENCPUK,
        EMPTYROW_FIELD,
        INITIALSIGNATUREPIN,
        SIGNATUREPUK
      };
  public static final int[] DATATYPESWITHPUK =
      new int[] {STRING, STRING, EMPTYROW, STRING, STRING};
  public static final String[] FIELDTEXTSWITHPUK =
      new String[] {
        INITIALAUTHENCPIN,
        AUTHENCPUK,
        EMPTYROW_FIELD,
        INITIALSIGNATUREPIN,
        SIGNATUREPUK
      };

  public static final String[] FIELDSWITHOUTPUK = new String[] {};
  public static final int[] DATATYPESWITHOUTPUK = new int[] {};
  public static final String[] FIELDTEXTSWITHOUTPUK = new String[] {};

  // Public Methods
  /**
   * Constructor to use.
   *
   * @param initialsignaturepin PIN
   * @param signaturepuk PUK
   * @param initialauthencpin PIN
   * @param authencpuk PUK
   * @param hardtokenprofileid int
   */
  public SwedishEIDHardToken(
      final String initialauthencpin,
      final String authencpuk,
      final String initialsignaturepin,
      final String signaturepuk,
      final int hardtokenprofileid) {
    super(true);
    setInitialAuthEncPIN(initialauthencpin);
    setAuthEncPUK(authencpuk);
    setInitialSignaturePIN(initialsignaturepin);
    setSignaturePUK(signaturepuk);
    setTokenProfileId(hardtokenprofileid);

    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
  }

  /**
   * Constructor only to be used internally.
   *
   * @param includePUK PUK
   */
  public SwedishEIDHardToken(final boolean includePUK) {
    super(includePUK);
    data.put(TOKENTYPE, Integer.valueOf(THIS_TOKENTYPE));
    if (!includePUK) {
      setInitialAuthEncPIN("");
      setAuthEncPUK("");
      setInitialSignaturePIN("");
      setSignaturePUK("");
    }
  }

  // Public Methods.
  public String getInitialAuthEncPIN() {
    return (String) data.get(INITIALAUTHENCPIN);
  }

  public void setInitialAuthEncPIN(final String initialbasicpin) {
    data.put(INITIALAUTHENCPIN, initialbasicpin);
  }

  public String getAuthEncPUK() {
    return (String) data.get(AUTHENCPUK);
  }

  public void setAuthEncPUK(final String basicpuk) {
    data.put(AUTHENCPUK, basicpuk);
  }

  public String getInitialSignaturePIN() {
    return (String) data.get(INITIALSIGNATUREPIN);
  }

  public void setInitialSignaturePIN(final String initialsignaturepin) {
    data.put(INITIALSIGNATUREPIN, initialsignaturepin);
  }

  public String getSignaturePUK() {
    return (String) data.get(SIGNATUREPUK);
  }

  public void setSignaturePUK(final String signaturepuk) {
    data.put(SIGNATUREPUK, signaturepuk);
  }

  public int[] getDataTypes(final boolean includePUK) {
    if (includePUK) {
      return DATATYPESWITHPUK;
    }
    return DATATYPESWITHOUTPUK;
  }

  public String[] getFieldTexts(final boolean includePUK) {
    if (includePUK) {
      return FIELDTEXTSWITHPUK;
    }
    return FIELDTEXTSWITHOUTPUK;
  }

  public String[] getFields(final boolean includePUK) {
    if (includePUK) {
      return FIELDSWITHPUK;
    }
    return FIELDSWITHOUTPUK;
  }

  // Private fields.
}
