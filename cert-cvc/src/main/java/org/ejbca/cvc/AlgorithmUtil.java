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

import java.util.HashMap;

/**
 * Utility for mapping a String of type "SHA1WITHRSA" to our own type OIDFIeld.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public final class AlgorithmUtil {

    /** Param. */
  private static HashMap<String, OIDField> algorithmMap =
      new HashMap<String, OIDField>();
  /** Param. */
  private static HashMap<String, String> conversionMap =
      new HashMap<String, String>();

  // TR-03110 definitions section A.1.1.3
  // id-TA-RSA
  // id-TA-RSA-v1-5-SHA-1
  // id-TA-RSA-v1-5-SHA-256
  // id-TA-RSA-PSS-SHA-1
  // id-TA-RSA-PSS-SHA-256
  // id-TA-RSA-v1-5-SHA-512
  // id-TA-RSA-PSS-SHA-512
  // id-TA-ECDSA
  // id-TA-ECDSA-SHA-1
  // id-TA-ECDSA-SHA-224
  // id-TA-ECDSA-SHA-256
  // id-TA-ECDSA-SHA-384
  // id-TA-ECDSA-SHA-512

  static {
    algorithmMap.put("SHA1WITHRSA",
            CVCObjectIdentifierConstants.ID_TA_RSA_V1_5_SHA_1);
    algorithmMap.put(
        "SHA256WITHRSA", CVCObjectIdentifierConstants.ID_TA_RSA_V1_5_SHA_256);
    algorithmMap.put(
        "SHA512WITHRSA", CVCObjectIdentifierConstants.ID_TA_RSA_V1_5_SHA_512);
    algorithmMap.put(
        "SHA1WITHRSAANDMGF1", CVCObjectIdentifierConstants.ID_TA_RSA_PSS_SHA_1);
    algorithmMap.put(
        "SHA256WITHRSAANDMGF1",
        CVCObjectIdentifierConstants.ID_TA_RSA_PSS_SHA_256);
    algorithmMap.put(
        "SHA512WITHRSAANDMGF1",
        CVCObjectIdentifierConstants.ID_TA_RSA_PSS_SHA_512);
    // Because CVC certificates does not use standard X9.62 signature encoding
    // we
    // have CVC variants of the ECDSA signature algorithms
    // skip SHA1WITHCVC-ECDSA etc since we have to convert the signature
    // manually to
    // support HSM providers
    algorithmMap.put("SHA1WITHECDSA",
            CVCObjectIdentifierConstants.ID_TA_ECDSA_SHA_1);
    algorithmMap.put(
        "SHA224WITHECDSA", CVCObjectIdentifierConstants.ID_TA_ECDSA_SHA_224);
    algorithmMap.put(
        "SHA256WITHECDSA", CVCObjectIdentifierConstants.ID_TA_ECDSA_SHA_256);
    algorithmMap.put(
        "SHA384WITHECDSA", CVCObjectIdentifierConstants.ID_TA_ECDSA_SHA_384);
    algorithmMap.put(
        "SHA512WITHECDSA", CVCObjectIdentifierConstants.ID_TA_ECDSA_SHA_512);
  }

  static {
    // Because CVC certificates does not use standard X9.62 signature encoding
    // we
    // have CVC variants of the ECDSA signature algorithms
    // We have these to make it easier for folks by letting them use the regular
    // style algorithm names
    // skip SHA1WITHCVC-ECDSA etc since we have to convert the signature
    // manually to
    // support HSM providers
    conversionMap.put("SHA1WITHECDSA", "SHA1WITHECDSA");
    conversionMap.put("SHA224WITHECDSA", "SHA224WITHECDSA");
    conversionMap.put("SHA256WITHECDSA", "SHA256WITHECDSA");
    conversionMap.put("SHA384WITHECDSA", "SHA384WITHECDSA");
    conversionMap.put("SHA512WITHECDSA", "SHA512WITHECDSA");
  }

  /**
   * Returns the OIDField associated with 'algorithmName'.
   *
   * @param algorithmName Name
   * @return Field
   */
  public static OIDField getOIDField(final String algorithmName) {
    OIDField oid = algorithmMap.get(convertAlgorithmNameToCVC(algorithmName));
    if (oid == null) {
      throw new IllegalArgumentException(
          "Unsupported algorithmName: " + algorithmName);
    }
    return oid;
  }

  /**
   * Some (ECDSA) algorithms requires use of particular CVC-ECDSA algorithm
   * names, so we sue this conversion map to translate from regular
   * (SHA1WithECDSA) names to CVC (SHA1WithCVC-ECDSA) names.
 * @param algorithmName  name
 * @return  CVC name
   *
   */
  public static String convertAlgorithmNameToCVC(final String algorithmName) {
    String name = conversionMap.get(algorithmName.toUpperCase());
    if (name != null) {
      return name;
    }
    return algorithmName.toUpperCase();
  }

  /**
   * Returns algorithmName for a given OID.
   *
   * @param oid OID
   * @return Name
   */
  public static String getAlgorithmName(final OIDField oid) {
    for (String key : algorithmMap.keySet()) {
      OIDField oidfield = algorithmMap.get(key);
      if (oidfield.getValue().equals(oid.getValue())) {
        return key;
      }
    }
    throw new IllegalArgumentException("Unknown OIDField: " + oid.getValue());
  }

  private AlgorithmUtil() { }
}
