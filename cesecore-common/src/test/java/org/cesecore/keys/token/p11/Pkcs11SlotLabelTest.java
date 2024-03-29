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
package org.cesecore.keys.token.p11;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.security.Provider;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CryptoProviderUtil;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Some general test methods for Pkcs11SlotLabel.
 *
 * @version $Id: Pkcs11SlotLabelTest.java 26879 2017-10-24 09:43:21Z bastianf $
 */
public class Pkcs11SlotLabelTest {
  /** Num. */
  private static final String SLOT_NUMBER = "1";
  /** Index. */
  private static final String SLOT_INDEX = "i1";
  /** Label. */
  private static final String SLOT_LABEL = "ejbca";

  /** Setup. */
  @BeforeClass
  public static void beforeClass() {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }
  /**
   * Test.
   */
  @Before
  public void checkPkcs11DriverAvailable() {
    // Skip test if no PKCS11 driver is installed
    assumeTrue(PKCS11TestUtils.getHSMLibrary() != null);
  }
  /**
   * Test.
   * @throws NoSuchSlotException fail
   */
  @Test
  public void testgetProviderWithNumber() throws NoSuchSlotException {
    Provider provider =
        Pkcs11SlotLabel.getP11Provider(
            SLOT_NUMBER,
            Pkcs11SlotLabelType.SLOT_NUMBER,
            PKCS11TestUtils.getHSMLibrary(),
            null);
    assertNotNull(
        "No provider for slot number : " + SLOT_NUMBER + " was found.",
        provider);
  }
  /**
   * Test.
   * @throws NoSuchSlotException fail
   */
  @Test
  public void testgetProviderWithIndex() throws NoSuchSlotException {
    Provider provider =
        Pkcs11SlotLabel.getP11Provider(
            SLOT_INDEX,
            Pkcs11SlotLabelType.SLOT_INDEX,
            PKCS11TestUtils.getHSMLibrary(),
            null);
    assertNotNull(
        "No provider for slot index : " + SLOT_INDEX + " was found.", provider);
  }

  /**
   * Test.
   * @throws NoSuchSlotException fail
   */
  @Test
  public void testgetProviderWithLabel() throws NoSuchSlotException {
    Provider provider =
        Pkcs11SlotLabel.getP11Provider(
            SLOT_LABEL,
            Pkcs11SlotLabelType.SLOT_LABEL,
            PKCS11TestUtils.getHSMLibrary(),
            null);
    assertNotNull(
        "No provider for slot label : " + SLOT_LABEL + " was found.", provider);
  }
}
