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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.CryptoProviderUtil;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id: PublicKeyWrapperTest.java 20836 2015-03-04 14:32:00Z anatom $
 */
public class PublicKeyWrapperTest {
/** Key. */
  private static PublicKey testKey;
/**
 * setup.
 * @throws InvalidAlgorithmParameterException fail
 */
  @BeforeClass
  public static void beforeClass() throws InvalidAlgorithmParameterException {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
    testKey =
        KeyUtil.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA)
            .getPublic();
  }
  /**
   * Test.
   */
  @Test
  public void testGetPublicKey() {
    PublicKeyWrapper testWrapper = new PublicKeyWrapper(testKey);
    assertEquals(
        "Decoded PublicKey was not identical to encoded.",
        testKey,
        testWrapper.getPublicKey());
  }
  /**
   * Test.
 * @throws IOException fail
 * @throws ClassNotFoundException fail
   */
  @Test
  public void testPublicKeySerialization()
      throws IOException, ClassNotFoundException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(testKey);
    oos.close();
    byte[] bytes = baos.toByteArray();
    baos.close();
    ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
    ObjectInputStream ois = new ObjectInputStream(bais);
    Object obj = ois.readObject();
    PublicKey pk = (PublicKey) obj;
    final String str = pk.getClass().getName();
    assertEquals(
        "Deserialized class should be a BC PublicKey",
        "org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey",
        str);
    assertEquals(
        "Deserialized PublicKey was not identical to encoded.", testKey, pk);
  }
}
