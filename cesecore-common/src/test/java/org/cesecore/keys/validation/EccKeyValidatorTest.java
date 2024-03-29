/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CryptoProviderUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests ECC key validator functions.
 *
 * @version $Id: EccKeyValidatorTest.java 27832 2018-01-10 14:34:42Z mikekushner
 *     $
 */
public class EccKeyValidatorTest {

  /** Class logger. */
  private static final Logger LOG = Logger.getLogger(EccKeyValidatorTest.class);
  /**
   * Test.
   * @throws Exception fail
   */
  @Before
  public void setUp() throws Exception {
    LOG.trace(">setUp()");
    CryptoProviderUtil.installBCProvider();
    LOG.trace("<setUp()");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @After
  public void tearDown() throws Exception {
    LOG.trace(">tearDown()");
    // NOOP
    LOG.trace("<tearDown()");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testPublicKeyValidation() throws Exception {
    LOG.trace(">testPublicKeyValidation()");

    // Test ECC key validation OK with an allowed curve.
    KeyPair keys =
        KeyUtil.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
    EccKeyValidator keyValidator =
        (EccKeyValidator)
            ValidatorTestUtil.createKeyValidator(
                EccKeyValidator.class,
                "ecc-parameter-validation-test-1",
                "Description",
                null,
                -1,
                null,
                -1,
                -1,
                new Integer[] {});
    keyValidator.setSettingsTemplate(
        KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
    // Set custom curve
    List<String> curves = new ArrayList<String>();
    curves.add("secp256r1");
    keyValidator.setCurves(curves);
    List<String> messages = keyValidator.validate(keys.getPublic(), null);
    LOG.trace("Key validation error messages: " + messages);
    assertTrue(
        "Key valildation should have been successful.", messages.size() == 0);
    // Set custom curve to something else, so it's not supported
    curves.clear();
    curves.add("secp384r1");
    keyValidator.setCurves(curves);
    messages = keyValidator.validate(keys.getPublic(), null);
    LOG.trace("Key validation error messages: " + messages);
    assertTrue("Key validation should have failed.", messages.size() > 0);
    assertEquals(
        "Key validation should have failed.",
        "Invalid: ECDSA curve [secp256r1, prime256v1, P-256]: Use one of the"
            + " following [secp384r1].",
        messages.get(0));

    // TODO: create some failed EC key to test validation on
    LOG.trace("<testPublicKeyValidation()");
  }

  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testPublicKeyValidationWithAlgorithmEC() throws Exception {
    LOG.trace(">testPublicKeyValidation()");
    // Test ECC key validation OK with an allowed curve.
    KeyPair keys =
        KeyUtil.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
    EccKeyValidator keyValidator =
        (EccKeyValidator)
            ValidatorTestUtil.createKeyValidator(
                EccKeyValidator.class,
                "ecc-parameter-validation-test-1",
                "Description",
                null,
                -1,
                null,
                -1,
                -1,
                new Integer[] {});
    keyValidator.setSettingsTemplate(
        KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
    // Set custom curve
    List<String> curves = new ArrayList<String>();
    curves.add("secp256r1");
    keyValidator.setCurves(curves);
    List<String> messages = keyValidator.validate(keys.getPublic(), null);
    LOG.trace("Key validation error messages: " + messages);
    assertTrue(
        "Key valildation should have been successful.", messages.size() == 0);
    // Set custom curve to something else, so it's not supported
    curves.clear();
    curves.add("secp384r1");
    keyValidator.setCurves(curves);
    messages = keyValidator.validate(keys.getPublic(), null);
    LOG.trace("Key validation error messages: " + messages);
    assertTrue("Key validation should have failed.", messages.size() > 0);
    assertEquals(
        "Key validation should have failed.",
        "Invalid: ECDSA curve [secp256r1, prime256v1, P-256]: Use one of the"
            + " following [secp384r1].",
        messages.get(0));
    LOG.trace("<testPublicKeyValidation()");
  }
}
