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
package org.cesecore.keys.util;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Wrapper class for serializing KeyPair objects.
 *
 * @see org.cesecore.util.EJBUtil
 * @version $Id: KeyPairWrapper.java 26210 2017-08-03 10:12:32Z samuellb $
 */
public class KeyPairWrapper implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Public. */
  private final byte[] encodedPublicKey;
  /** Priuvate. */
  private final byte[] encodedPrivateKey;
  /** Algo. */
  private final String algorithm;
  /** cached keys. */
  private transient KeyPair cachedKeyPair = null;

  /**
   * @param keyPair keys
   */
  public KeyPairWrapper(final KeyPair keyPair) {
    this.encodedPublicKey = keyPair.getPublic().getEncoded();
    this.encodedPrivateKey = keyPair.getPrivate().getEncoded();
    this.algorithm = keyPair.getPublic().getAlgorithm();
  }

  /** @return the decoded PublicKey object wrapped in this class. */
  private PublicKey getPublicKey() {
    try {
      KeyFactory keyFactory =
          KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
      return keyFactory.generatePublic(keySpec);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException(
          "BouncyCastle was not a known provider.", e);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Algorithm " + algorithm + " was not known at deserialisation", e);
    } catch (InvalidKeySpecException e) {
      throw new IllegalStateException(
          "The incorrect key specification was implemented.", e);
    }
  }

  /** @return the decoded PublicKey object wrapped in this class. */
  private PrivateKey getPrivateKey() {
    try {
      KeyFactory keyFactory =
          KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
      return keyFactory.generatePrivate(keySpec);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException(
          "BouncyCastle was not a known provider.", e);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Algorithm " + algorithm + " was not known at deserialisation", e);
    } catch (InvalidKeySpecException e) {
      throw new IllegalStateException(
          "The incorrect key specification was implemented.", e);
    }
  }

  /**
   * @return keys
   */
  public KeyPair getKeyPair() {
    if (cachedKeyPair == null) {
      cachedKeyPair = new KeyPair(getPublicKey(), getPrivateKey());
    }
    return cachedKeyPair;
  }
}
