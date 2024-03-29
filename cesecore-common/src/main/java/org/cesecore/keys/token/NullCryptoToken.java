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
package org.cesecore.keys.token;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class is used as crypto Token for virtual CAs that does not have a
 * keystore, such as external SubCAs.
 *
 * @version $Id: NullCryptoToken.java 22561 2016-01-12 14:35:29Z mikekushner $
 */
public class NullCryptoToken extends BaseCryptoToken {

  private static final long serialVersionUID = -1L;

  /** ID. */
  private int id;

  @Override
  public void init(
          final Properties properties, final byte[] data, final int anId)
      throws Exception {
    // We only need to set JCA provider, if JCE provider is the same (which is
    // the common case)
    setJCAProviderName(BouncyCastleProvider.PROVIDER_NAME);
    this.id = anId;
  }

  @Override
  public int getId() {
    return this.id;
  }

  @Override
  public Properties getProperties() {
    return new Properties();
  }

  @Override
  public PrivateKey getPrivateKey(final String alias) {
    return null;
  }

  @Override
  public PublicKey getPublicKey(final String alias) {
    return null;
  }

  @Override
  public void deleteEntry(final String alias)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
          IOException, CryptoTokenOfflineException {
      // NO-OP
  }

  @Override
  public void generateKeyPair(final String keySpec, final String alias)
      throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
      // NO-OP
  }

  @Override
  public void generateKeyPair(
      final AlgorithmParameterSpec spec, final String alias)
      throws InvalidAlgorithmParameterException, CertificateException,
          IOException, CryptoTokenOfflineException {
      // NO-OP
  }

  @Override
  public void generateKey(
      final String algorithm, final int keysize, final String alias)
      throws NoSuchAlgorithmException, NoSuchProviderException,
          KeyStoreException, CryptoTokenOfflineException {
      // NO-OP
  }

  @Override
  public void activate(final char[] authenticationcode)
      throws CryptoTokenAuthenticationFailedException,
          CryptoTokenOfflineException {
    // Do Nothing
  }

  @Override
  public void deactivate() {
    // Do Nothing
  }

  @Override
  public byte[] getTokenData() {
    return null;
  }

  @Override
  public boolean permitExtractablePrivateKeyForTest() {
    return doPermitExtractablePrivateKey();
  }
}
