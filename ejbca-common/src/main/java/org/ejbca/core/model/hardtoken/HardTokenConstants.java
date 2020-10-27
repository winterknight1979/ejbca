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
package org.ejbca.core.model.hardtoken;

/**
 * @version $Id: HardTokenConstants.java 22117 2015-10-29 10:53:42Z mikekushner
 *     $
 */
public final class HardTokenConstants {
  private HardTokenConstants() { }
  /** Config. */
  public static final int TOKENTYPE_TURKISHEID =
      3; // TurkishEIDProfile.TYPE_TURKISHEID;
  /** Config. */
  public static final int TOKENTYPE_SWEDISHEID =
      1; // SwedishEIDProfile.TYPE_SWEDISHEID;
  /** Config. */
  public static final int TOKENTYPE_ENHANCEDEID =
      2; // EnhancedEIDProfile.TYPE_ENHANCEDEID;

/** Config. */
  public static final String LABEL_REGULARCARD =
      "LABEL_REGULARCARD"; // HardToken.LABEL_REGULARCARD;
  /** Config. */
  public static final String LABEL_TEMPORARYCARD =
      "LABEL_TEMPORARYCARD"; // HardToken.LABEL_TEMPORARYCARD;
  /** Config. */
  public static final String LABEL_PROJECTCARD =
      "LABEL_PROJECTCARD"; // HardToken.LABEL_PROJECTCARD;

/** Config. */
  public static final int PINTYPE_BASIC = 1;
  /** Config. */
  public static final int PINTYPE_SIGNATURE = 2;

/** Config. */
  public static final int REQUESTTYPE_PKCS10_REQUEST = 1;
  /** Config. */
  public static final int REQUESTTYPE_KEYSTORE_REQUEST = 2;
  /** Config. */

  public static final int RESPONSETYPE_CERTIFICATE_RESPONSE = 1;
  /** Config. */
  public static final int RESPONSETYPE_KEYSTORE_RESPONSE = 2;
/** Config. */
  public static final String TOKENTYPE_PKCS12 = "PKCS12";
}
