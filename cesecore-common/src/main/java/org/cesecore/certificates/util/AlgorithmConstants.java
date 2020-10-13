/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.util;

import java.util.Arrays;
import java.util.List;

/**
 * Constants for digital signature algorithms.
 *
 * @version $Id: AlgorithmConstants.java 27720 2018-01-03 11:42:32Z bastianf $
 */
public final class AlgorithmConstants {


  /** RSA/MD5. */
  public static final String SIGALG_MD5_WITH_RSA = "MD5WithRSA";
  /** RSA/SHA1. */
  public static final String SIGALG_SHA1_WITH_RSA = "SHA1WithRSA";
  /** RSA/SHA2-256. */
  public static final String SIGALG_SHA256_WITH_RSA = "SHA256WithRSA";
  /** RSA/SHA2-384. */
  public static final String SIGALG_SHA384_WITH_RSA = "SHA384WithRSA";
  /** RSA/SHA2-512. */
  public static final String SIGALG_SHA512_WITH_RSA = "SHA512WithRSA";
  /** RSA/SHA3-256. */
  public static final String SIGALG_SHA3_256_WITH_RSA = "SHA3-256withRSA";
  /** RSA/SHA3-384. */
  public static final String SIGALG_SHA3_384_WITH_RSA = "SHA3-384withRSA";
  /** RSA/SHA3-512. */
  public static final String SIGALG_SHA3_512_WITH_RSA = "SHA3-512withRSA";
  /** EC/SHA1. */
  public static final String SIGALG_SHA1_WITH_ECDSA = "SHA1withECDSA";
  /** EC/SHA2-224. */
  public static final String SIGALG_SHA224_WITH_ECDSA = "SHA224withECDSA";
  /** EC/SHA2-256. */
  public static final String SIGALG_SHA256_WITH_ECDSA = "SHA256withECDSA";
  /** EC/SHA2-384. */
  public static final String SIGALG_SHA384_WITH_ECDSA = "SHA384withECDSA";
  /** EC/SHA2-512. */
  public static final String SIGALG_SHA512_WITH_ECDSA = "SHA512withECDSA";
  /** EC/SHA3-256. */
  public static final String SIGALG_SHA3_256_WITH_ECDSA = "SHA3-256withECDSA";
  /** EC/SHA3-384. */
  public static final String SIGALG_SHA3_384_WITH_ECDSA = "SHA3-384withECDSA";
  /** EC/SHA3-512. */
  public static final String SIGALG_SHA3_512_WITH_ECDSA = "SHA3-512withECDSA";
  /** RSA/SHA1. */
  public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 =
      "SHA256withRSAandMGF1";
  /** RSA/SHA1. */
  public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1 =
      "SHA1withRSAandMGF1"; // Not possible to select in Admin-GUI
  /** DSA/SHA1. */
  public static final String SIGALG_SHA1_WITH_DSA = "SHA1WithDSA";
  /** GOST/EC. */
  public static final String SIGALG_GOST3411_WITH_ECGOST3410 =
      "GOST3411withECGOST3410";
  /** GOST with DSTU. */
  public static final String SIGALG_GOST3411_WITH_DSTU4145 =
      "GOST3411withDSTU4145";

  /**
   * Signature algorithms available to choose from. Call
   * AlgorithmTools.isSigAlgEnabled() to determine if a given sigalg is enabled
   * and should be shown in the UI.
   */
  public static final String[] AVAILABLE_SIGALGS = {
    SIGALG_SHA1_WITH_RSA,
    SIGALG_SHA256_WITH_RSA,
    SIGALG_SHA384_WITH_RSA,
    SIGALG_SHA512_WITH_RSA,
    SIGALG_SHA3_256_WITH_RSA,
    SIGALG_SHA3_384_WITH_RSA,
    SIGALG_SHA3_512_WITH_RSA,
    SIGALG_SHA256_WITH_RSA_AND_MGF1,
    SIGALG_SHA1_WITH_ECDSA,
    SIGALG_SHA224_WITH_ECDSA,
    SIGALG_SHA256_WITH_ECDSA,
    SIGALG_SHA384_WITH_ECDSA,
    SIGALG_SHA512_WITH_ECDSA,
    SIGALG_SHA3_256_WITH_ECDSA,
    SIGALG_SHA3_384_WITH_ECDSA,
    SIGALG_SHA3_512_WITH_ECDSA,
    SIGALG_SHA1_WITH_DSA,
    SIGALG_GOST3411_WITH_ECGOST3410,
    SIGALG_GOST3411_WITH_DSTU4145,
  };

  /** RSA. */
  public static final String KEYALGORITHM_RSA = "RSA";
  /** EC. */
  public static final String KEYALGORITHM_EC = "EC";
  /** ECDSA. */
  public static final String KEYALGORITHM_ECDSA =
      "ECDSA"; // The same as "EC", just named differently sometimes. "EC" and
               // "ECDSA" should be handled in the same way
  /** DSA. */
  public static final String KEYALGORITHM_DSA = "DSA";
  /** ECGOST. */
  public static final String KEYALGORITHM_ECGOST3410 = "ECGOST3410";
  /** DSTU. */
  public static final String KEYALGORITHM_DSTU4145 = "DSTU4145";

  /** GOST. */
  public static final String KEYSPECPREFIX_ECGOST3410 = "GostR3410-";

  /** Blacklisted curves. */
  public static final List<String> BLACKLISTED_EC_CURVES =
      Arrays.asList(
          new String[] {
            // No blacklisted EC curves at the moment
          });

  /** Extra EC curves that we want to include
   * that are not part of the "standard"
   * curves in BC (ECNamedCurveTable.getNames). */
  public static final List<String> EXTRA_EC_CURVES =
      Arrays.asList(
          new String[] {
            // Part of CustomNamedCurves in BouncyCastle 1.54
            // Commented out due to experimental nature 2017-04 as the
            // signatures using this currently probably is not correct
            // Should probably wait for edDSA, See ECA-5796 and linked issues.
            // "curve25519",
          });

  private AlgorithmConstants() { } // Not for instantiation
}
