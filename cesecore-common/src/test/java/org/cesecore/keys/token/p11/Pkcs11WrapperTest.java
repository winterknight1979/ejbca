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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import org.apache.log4j.Logger;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.util.CryptoProviderUtil;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests instantiating the Pkcs11Wrapper.
 *
 * @version $Id: Pkcs11WrapperTest.java 26889 2017-10-25 13:29:54Z bastianf $
 */
public class Pkcs11WrapperTest {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(Pkcs11WrapperTest.class);
  /** Label. */
  private static final String SLOT_LABEL = "ejbca";
  /** Num. */
  private static final long SLOT_NUMBER = 1;

  /** Setup. */
  @BeforeClass
  public static void beforeClass() {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }
  /** Setup. */

  @Before
  public void checkPkcs11DriverAvailable() {
    // Skip test if no PKCS11 driver is installed
    assumeTrue(PKCS11TestUtils.getHSMLibrary() != null);
  }
  /**
   * Test.
   */
  @Test
  public void testInstantiatePkcs11Wrapper() {
    String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
    try {
      Pkcs11Wrapper.getInstance(new File(pkcs11Library));
    } catch (Exception e) {
      LOG.error("Unknown exception encountered", e);
      fail("Exception was thrown, instantiation failed.");
    }
  }

  /**
   * Verifies that the getTokenLabel method works. Note that this method will
   * fail in HSMs without fixed slot numbers, e.g. nCypher
   */
  @Test
  public void testGetSlotLabel() {
    String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
    Pkcs11Wrapper pkcs11Wrapper =
        Pkcs11Wrapper.getInstance(new File(pkcs11Library));
    assertEquals(
        "Correct slot label was not found.",
        SLOT_LABEL,
        new String(pkcs11Wrapper.getTokenLabel(SLOT_NUMBER)));
  }
}
