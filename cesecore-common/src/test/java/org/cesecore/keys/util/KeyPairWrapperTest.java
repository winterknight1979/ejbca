/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.util;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.CryptoProviderUtil;
import org.junit.BeforeClass;
import org.junit.Test;

/** @version $Id: KeyPairWrapperTest.java 26057 2017-06-22 08:08:34Z anatom $ */
public class KeyPairWrapperTest {
    /** Setup. */

  @BeforeClass
  public static void beforeClass() {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }
  /**
   * Test.
 * @throws InvalidAlgorithmParameterException fail
 * @throws InvalidKeySpecException  fail
   */
  @Test
  public void testGetKeyPair()
      throws InvalidAlgorithmParameterException, InvalidKeySpecException {
    KeyPair testKeys =
        KeyUtil.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    KeyPairWrapper testWrapper = new KeyPairWrapper(testKeys);
    assertEquals(
        "Decoded public key was not identical to encoded.",
        testKeys.getPublic(),
        testWrapper.getKeyPair().getPublic());
    assertEquals(
        "Decoded private key was not identical to encoded.",
        testKeys.getPrivate(),
        testWrapper.getKeyPair().getPrivate());
  }
}
