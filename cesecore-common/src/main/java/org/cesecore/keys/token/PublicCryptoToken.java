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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.CesecoreException;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderUtil;

/**
 * Just to be used for encryption (not decryption) and verifying (not signing)
 * by the public part of an asymmetric key.
 *
 * @version $Id: PublicCryptoToken.java 28934 2018-05-15 07:36:42Z undulf $
 */
public class PublicCryptoToken implements CryptoToken {

  private static final long serialVersionUID = 1L;
  /** ID. */
  private int id;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(PublicCryptoToken.class);
  /** PK. */
  private PublicKey pk;
  /** Provider. */
  private static final String PROVIDER_NAME
              = BouncyCastleProvider.PROVIDER_NAME;
  /** Name. */
  private String tokenName = "not available";

  @Override
  public void init(
          final Properties properties, final byte[] data, final int anId)
      throws Exception {
    this.id = anId;
    if (data == null || data.length < 1) {
      final String msg = "No data for public key in token with id: " + this.id;
      LOG.error(msg);
      throw new CesecoreException(msg);
    }
    CryptoProviderUtil.installBCProviderIfNotAvailable();
    this.pk = getPublicKey(data);
    if (this.pk == null) {
      final String msg = "Not possible to initiate public key id: " + this.id;
      LOG.error(msg);
      throw new CesecoreException(msg);
    }
  }

  private static PublicKey getPublicKey(final byte[] data) {
    try {
      PublicKey ret = KeyUtil.getPublicKeyFromBytes(data);
      if (ret != null) {
        return ret;
      }
    } catch (IllegalArgumentException e) {
      LOG.debug("Not an X509 key.", e);
    }
    LOG.debug("Trying to parse it as a certificate.");
    try {
      X509Certificate x509Certificate =
          CertTools.getCertfromByteArray(data, X509Certificate.class);
      if (x509Certificate != null) {
        return x509Certificate.getPublicKey();
      }
      LOG.debug("Failed to parse as X509 Certificate.");
    } catch (CertificateException e) {
      LOG.debug("Public key data is not a certificate.", e);
    }
    return null; // no more formats to try
  }

  @Override
  public int getId() {
    return this.id;
  }

  @Override
  public void activate(final char[] authenticationcode)
      throws CryptoTokenOfflineException,
          CryptoTokenAuthenticationFailedException {
    // no private key to activate
  }

  @Override
  public void deactivate() {
    // no private key to deactivate
  }

  @Override
  public boolean isAliasUsed(final String alias) {
    try {
      return getPublicKey(alias) != null;
    } catch (CryptoTokenOfflineException e) {
      // This will never happen
      return false;
    }
  }

  @Override
  public PrivateKey getPrivateKey(final String alias)
      throws CryptoTokenOfflineException {
    // no private key for this token
    return null;
  }

  @Override
  public PublicKey getPublicKey(final String alias)
      throws CryptoTokenOfflineException {
    return this.pk;
  }

  @Override
  public Key getKey(final String alias) throws CryptoTokenOfflineException {
    // no symmetric key for this token.
    return null;
  }

  @Override
  public void deleteEntry(final String alias)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
          IOException, CryptoTokenOfflineException {
    // static do nothing
  }

  @Override
  public void generateKeyPair(
          final String keySpec, final String alias)
      throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
    // static do nothing
  }

  @Override
  public void generateKeyPair(
          final AlgorithmParameterSpec spec, final String alias)
      throws InvalidAlgorithmParameterException, CertificateException,
          IOException, CryptoTokenOfflineException {
    // static do nothing
  }

  @Override
  public void generateKey(
          final String algorithm, final int keysize, final String alias)
      throws NoSuchAlgorithmException, NoSuchProviderException,
          KeyStoreException, CryptoTokenOfflineException, InvalidKeyException,
          InvalidAlgorithmParameterException, SignatureException,
          CertificateException, IOException, NoSuchPaddingException,
          IllegalBlockSizeException {
    // static do nothing
  }

  @Override
  public String getSignProviderName() {
    return PROVIDER_NAME;
  }

  @Override
  public String getEncProviderName() {
    return PROVIDER_NAME;
  }

  @Override
  public void reset() {
    // do nothing
  }

  @Override
  public int getTokenStatus() {
    if (this.pk == null) {
      return CryptoToken.STATUS_OFFLINE;
    }
    return CryptoToken.STATUS_ACTIVE;
  }

  @Override
  public Properties getProperties() {
    return new Properties();
  }

  @Override
  public void setProperties(final Properties properties) {
    // do nothing
  }

  @Override
  public byte[] getTokenData() {
    return this.pk.getEncoded();
  }

  @Override
  public boolean doPermitExtractablePrivateKey() {
    return false;
  }

  @Override
  public List<String> getAliases() {
    return Arrays.asList("dummy");
  }

  @Override
  public void storeKey(
      final String alias,
      final Key key,
      final Certificate[] chain,
      final char[] password)
      throws KeyStoreException {
    if (chain == null || chain.length < 1) {
      return;
    }
    this.pk = chain[0].getPublicKey();
  }

  @Override
  public boolean isAutoActivationPinPresent() {
    return BaseCryptoToken.getAutoActivatePin(getProperties()) != null;
  }

  @Override
  public void testKeyPair(final String alias)
      throws InvalidKeyException, CryptoTokenOfflineException {
    // be positive.. NOT!
    throw new CryptoTokenOfflineException(
        "Implementation does not contain any private keys to use for test.");
  }

  @Override
  public void testKeyPair(
      final String alias,
      final PublicKey publicKey,
      final PrivateKey privateKey)
      throws InvalidKeyException {
    // be positive.. NOT!
    throw new InvalidKeyException(
        "Implementation does not contain any private keys to use for test.");
  }

  @Override
  public String getTokenName() {
    return tokenName;
  }

  @Override
  public void setTokenName(final String aokenName) {
    this.tokenName = aokenName;
  }
}
