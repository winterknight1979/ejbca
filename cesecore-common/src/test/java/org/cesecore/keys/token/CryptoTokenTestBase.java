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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CertTools;

/**
 * @version $Id: CryptoTokenTestBase.java 22596 2016-01-18 14:59:25Z mikekushner
 *     $
 */
public abstract class CryptoTokenTestBase {

    /** PIN. */
  public static final String TOKEN_PIN =
      PKCS11TestUtils.getPkcs11SlotPin("userpin1");

  /** resource. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** constructor. */
  public CryptoTokenTestBase() {
    super();
  }

  /**
   * @param cryptoToken token
   * @throws KeyStoreException fail
   * @throws NoSuchAlgorithmException fail
   * @throws CertificateException fail
   * @throws IOException fail
   * @throws CryptoTokenOfflineException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidAlgorithmParameterException fail
   */
  protected void doCryptoTokenRSA(final CryptoToken cryptoToken)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
          IOException, CryptoTokenOfflineException, NoSuchProviderException,
          InvalidKeyException, SignatureException,
          CryptoTokenAuthenticationFailedException,
          InvalidAlgorithmParameterException {
    // We have not activated the token so status should be offline
    assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
    assertEquals(getProvider(), cryptoToken.getSignProviderName());

    // First we start by deleting all old entries
    try {
      cryptoToken.deleteEntry("rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    // Should still be ACTIVE now, because we run activate
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.deleteEntry("rsatest00001");
    cryptoToken.deleteEntry("rsatest00002");
    cryptoToken.deleteEntry("rsatest00003");

    // Try to delete something that surely does not exist, it should work
    // without error
    cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

    // Generate the first key
    cryptoToken.generateKeyPair("1024", "rsatest00001");
    PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
    PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

    // Make sure keys are or are not extractable, according to what is allowed
    // by the token
    cryptoToken.testKeyPair("rsatest00001");

    // Generate new keys again
    cryptoToken.generateKeyPair("2048", "rsatest00002");
    priv = cryptoToken.getPrivateKey("rsatest00002");
    pub = cryptoToken.getPublicKey("rsatest00002");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(2048, KeyUtil.getKeyLength(pub));
    String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertFalse(
        "New keys are same as old keys, should not be...",
        keyhash.equals(newkeyhash));
    priv = cryptoToken.getPrivateKey("rsatest00001");
    pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(keyhash, previouskeyhash);

    // Delete a key pair
    cryptoToken.deleteEntry("rsatest00001");
    try {
      priv = cryptoToken.getPrivateKey("rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    try {
      pub = cryptoToken.getPublicKey("rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    try {
      // the other keys should still be there
      priv = cryptoToken.getPrivateKey("rsatest00002");
      pub = cryptoToken.getPublicKey("rsatest00002");
      KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
      assertEquals(2048, KeyUtil.getKeyLength(pub));
      String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
      assertEquals(newkeyhash, newkeyhash2);

      // Create keys using AlgorithmParameterSpec
      AlgorithmParameterSpec paramspec = KeyUtil.getKeyGenSpec(pub);
      cryptoToken.generateKeyPair(paramspec, "rsatest00003");
      priv = cryptoToken.getPrivateKey("rsatest00003");
      pub = cryptoToken.getPublicKey("rsatest00003");
      KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
      assertEquals(2048, KeyUtil.getKeyLength(pub));
      String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
      // Make sure it's not the same key
      assertFalse(newkeyhash2.equals(newkeyhash3));
    } finally {
      // Clean up and delete our generated keys
      cryptoToken.deleteEntry("rsatest00002");
      cryptoToken.deleteEntry("rsatest00003");
    }
  }

  /**
   * @param cryptoToken token
   * @throws CryptoTokenOfflineException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidKeyException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws KeyStoreException fail
   * @throws InvalidAlgorithmParameterException fail
   * @throws SignatureException fail
   * @throws CertificateException fail
   * @throws IOException fail
   */
  protected void doCryptoTokenDSA(final CryptoToken cryptoToken)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
          IOException, CryptoTokenOfflineException, NoSuchProviderException,
          InvalidKeyException, SignatureException,
          CryptoTokenAuthenticationFailedException,
          InvalidAlgorithmParameterException {
    // We have not activated the token so status should be offline
    assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
    assertEquals(getProvider(), cryptoToken.getSignProviderName());

    // First we start by deleting all old entries
    try {
      cryptoToken.deleteEntry("dsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    // Should still be ACTIVE now, because we run activate
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.deleteEntry("dsatest00001");
    cryptoToken.deleteEntry("dsatest00002");
    cryptoToken.deleteEntry("dsatest00003");

    // Try to delete something that surely does not exist, it should work
    // without error
    cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

    // Generate the first key
    cryptoToken.generateKeyPair("DSA1024", "dsatest00001");
    PrivateKey priv = cryptoToken.getPrivateKey("dsatest00001");
    PublicKey pub = cryptoToken.getPublicKey("dsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

    // Make sure keys are or are not extractable, according to what is allowed
    // by the token
    cryptoToken.testKeyPair("dsatest00001");

    // Generate new keys again
    cryptoToken.generateKeyPair("DSA1024", "dsatest00002");
    priv = cryptoToken.getPrivateKey("dsatest00002");
    pub = cryptoToken.getPublicKey("dsatest00002");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertFalse(
        "New keys are same as old keys, should not be...",
        keyhash.equals(newkeyhash));
    priv = cryptoToken.getPrivateKey("dsatest00001");
    pub = cryptoToken.getPublicKey("dsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(keyhash, previouskeyhash);

    // Delete a key pair
    cryptoToken.deleteEntry("dsatest00001");
    try {
      priv = cryptoToken.getPrivateKey("dsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    try {
      pub = cryptoToken.getPublicKey("dsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    // the other keys should still be there
    priv = cryptoToken.getPrivateKey("dsatest00002");
    pub = cryptoToken.getPublicKey("dsatest00002");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(newkeyhash, newkeyhash2);

    // Create keys using AlgorithmParameterSpec
    AlgorithmParameterSpec paramspec = KeyUtil.getKeyGenSpec(pub);
    cryptoToken.generateKeyPair(paramspec, "dsatest00003");
    priv = cryptoToken.getPrivateKey("dsatest00003");
    pub = cryptoToken.getPublicKey("dsatest00003");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
    // Make sure it's not the same key
    assertFalse(newkeyhash2.equals(newkeyhash3));

    // Clean up and delete our generated keys
    cryptoToken.deleteEntry("dsatest00002");
    cryptoToken.deleteEntry("dsatest00003");
  }

  /**
   * @param cryptoToken token
   * @param curve1 curve
   * @param keyLen1 length
   * @param curve2 curve
   * @param keyLen2 length
   * @throws KeyStoreException fail
   * @throws NoSuchAlgorithmException fail
   * @throws CertificateException fail
   * @throws IOException fail
   * @throws CryptoTokenOfflineException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidAlgorithmParameterException fail
   */
  protected void doCryptoTokenECC(
      final CryptoToken cryptoToken,
      final String curve1,
      final int keyLen1,
      final String curve2,
      final int keyLen2)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
          IOException, CryptoTokenOfflineException, NoSuchProviderException,
          InvalidKeyException, SignatureException,
          CryptoTokenAuthenticationFailedException,
          InvalidAlgorithmParameterException {
    // We have not activated the token so status should be offline
    assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
    assertEquals(getProvider(), cryptoToken.getSignProviderName());

    // First we start by deleting all old entries
    try {
      cryptoToken.deleteEntry("ecctest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    // Should still be ACTIVE now, because we run activate
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.deleteEntry("ecctest00001");
    cryptoToken.deleteEntry("ecctest00002");
    cryptoToken.deleteEntry("ecctest00003");

    // Try to delete something that surely does not exist, it should work
    // without error
    cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

    // Generate the first key
    cryptoToken.generateKeyPair(curve1, "ecctest00001");
    PrivateKey priv = cryptoToken.getPrivateKey("ecctest00001");
    PublicKey pub = cryptoToken.getPublicKey("ecctest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(keyLen1, KeyUtil.getKeyLength(pub));
    String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

    // Make sure keys are or are not extractable, according to what is allowed
    // by the token
    cryptoToken.testKeyPair("ecctest00001");

    // Generate new keys again
    cryptoToken.generateKeyPair(curve2, "ecctest00002");
    priv = cryptoToken.getPrivateKey("ecctest00002");
    pub = cryptoToken.getPublicKey("ecctest00002");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(keyLen2, KeyUtil.getKeyLength(pub));
    String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertFalse(
        "New keys are same as old keys, should not be...",
        keyhash.equals(newkeyhash));
    priv = cryptoToken.getPrivateKey("ecctest00001");
    pub = cryptoToken.getPublicKey("ecctest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(keyLen1, KeyUtil.getKeyLength(pub));
    String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(keyhash, previouskeyhash);

    // Delete a key pair
    cryptoToken.deleteEntry("ecctest00001");
    try {
      priv = cryptoToken.getPrivateKey("ecctest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    try {
      pub = cryptoToken.getPublicKey("ecctest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    // the other keys should still be there
    priv = cryptoToken.getPrivateKey("ecctest00002");
    pub = cryptoToken.getPublicKey("ecctest00002");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(keyLen2, KeyUtil.getKeyLength(pub));
    String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(newkeyhash, newkeyhash2);

    // Create keys using AlgorithmParameterSpec
    AlgorithmParameterSpec paramspec = KeyUtil.getKeyGenSpec(pub);
    cryptoToken.generateKeyPair(paramspec, "ecctest00003");
    priv = cryptoToken.getPrivateKey("ecctest00003");
    pub = cryptoToken.getPublicKey("ecctest00003");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(keyLen2, KeyUtil.getKeyLength(pub));
    String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
    // Make sure it's not the same key
    assertFalse(newkeyhash2.equals(newkeyhash3));

    // Clean up and delete our generated keys
    cryptoToken.deleteEntry("ecctest00002");
    cryptoToken.deleteEntry("ecctest00003");
  }

  /**
   * @param cryptoToken token
   * @throws KeyStoreException fail
   * @throws NoSuchAlgorithmException fail
   * @throws CertificateException fail
   * @throws IOException fail
   * @throws CryptoTokenOfflineException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidAlgorithmParameterException fail
   */
  protected void doActivateDeactivate(final CryptoToken cryptoToken)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
          IOException, NoSuchProviderException,
          InvalidAlgorithmParameterException, InvalidKeyException,
          SignatureException, CryptoTokenOfflineException,
          CryptoTokenAuthenticationFailedException {
    // We have not activated the token so status should be offline
    assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
    assertEquals(getProvider(), cryptoToken.getSignProviderName());

    // First we start by deleting all old entries
    try {
      cryptoToken.deleteEntry("rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    try {
      // Generate a key, should not work either
      cryptoToken.generateKeyPair("1024", "rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      // NOPMD
    }
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    // Should still be ACTIVE now, because we run activate
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.deleteEntry("rsatest00001");

    // Generate a key, should work
    cryptoToken.generateKeyPair("1024", "rsatest00001");
    PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
    PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));

    // Get a key that does not exist
    try {
      pub = cryptoToken.getPublicKey("sdfsdf77474");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      assertTrue(
          e.getMessage(),
          e.getMessage()
              .contains(
                  INTRES.getLocalizedMessage(
                      "token.errornosuchkey", "sdfsdf77474")));
    }
    // We have not set auto activate, so the internal key storage in CryptoToken
    // is emptied
    cryptoToken.deactivate();
    try {
      priv = cryptoToken.getPrivateKey("rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      assertTrue(
          e.getMessage(), e.getMessage().contains("keyStore (111) == null"));
    }
    try {
      pub = cryptoToken.getPublicKey("rsatest00001");
      assertTrue("Should throw", false);
    } catch (CryptoTokenOfflineException e) {
      assertTrue(
          e.getMessage(), e.getMessage().contains("keyStore (111) == null"));
    }
    // Activate with wrong PIN should not work
    try {
      cryptoToken.activate("gfhf56564".toCharArray());
      fail("Should have thrown");
    } catch (CryptoTokenAuthenticationFailedException e) {
      String strsoft =
          "PKCS12 key store mac invalid - wrong password or corrupted file.";
      String strp11 = "Failed to initialize PKCS11 provider slot '1'.";
      assert (e.getMessage().equals(strsoft) || e.getMessage().equals(strp11));
    }
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    priv = cryptoToken.getPrivateKey("rsatest00001");
    pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));

    // End by deleting all old entries
    cryptoToken.deleteEntry("rsatest00001");
  }

  /**
   * @param cryptoToken token
   * @throws KeyStoreException fail
   * @throws NoSuchAlgorithmException fail
   * @throws CertificateException fail
   * @throws IOException fail
   * @throws CryptoTokenOfflineException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidAlgorithmParameterException fail
   */
  protected void doAutoActivate(final CryptoToken cryptoToken)
      throws CryptoTokenOfflineException, KeyStoreException,
          NoSuchProviderException, NoSuchAlgorithmException,
          CertificateException, IOException, InvalidKeyException,
          SignatureException, CryptoTokenAuthenticationFailedException,
          InvalidAlgorithmParameterException {
    Properties prop = cryptoToken.getProperties();
    prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, TOKEN_PIN);
    cryptoToken.setProperties(prop);

    // We have autoactivation, so status should be ACTIVE
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    assertEquals(getProvider(), cryptoToken.getSignProviderName());

    cryptoToken.deactivate();
    // It should autoactivate getting status
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());

    // Generate a key
    cryptoToken.generateKeyPair("1024", "rsatest00001");
    PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
    PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    // Deactivate
    cryptoToken.deactivate();
    // It should autoactivate trying to get keys
    priv = cryptoToken.getPrivateKey("rsatest00001");
    pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));

    // End by deleting all old entries
    cryptoToken.deleteEntry("rsatest00001");
  }

  /**
   * @param cryptoToken token
   * @throws CryptoTokenOfflineException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidKeyException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws KeyStoreException fail
   * @throws InvalidAlgorithmParameterException fail
   * @throws SignatureException fail
   * @throws CertificateException fail
   * @throws IOException fail
   * @throws NoSuchSlotException fail
   */
  protected void doStoreAndLoad(final CryptoToken cryptoToken)
      throws CryptoTokenOfflineException,
          CryptoTokenAuthenticationFailedException, KeyStoreException,
          NoSuchAlgorithmException, CertificateException, IOException,
          InvalidKeyException, NoSuchProviderException,
          InvalidAlgorithmParameterException, SignatureException,
          NoSuchSlotException {
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.deleteEntry("rsatest00001");

    // Generate a key
    cryptoToken.generateKeyPair("1024", "rsatest00001");
    PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
    PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, cryptoToken.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String pubKHash = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(
        111, cryptoToken.getId()); // What we set in "createCryptoToken"

    // Serialize the token and re-create it from scratch
    Properties prop = cryptoToken.getProperties();
    byte[] data = cryptoToken.getTokenData();
    // prop and data can now be persisted somewhere and retrieved again a week
    // later
    CryptoToken token2 =
        CryptoTokenFactory.createCryptoToken(
            cryptoToken.getClass().getName(),
            prop,
            data,
            555,
            "Another cryptoToken");
    token2.activate(TOKEN_PIN.toCharArray());
    // Now we have a new crypto token, so lets do the same key test again
    priv = token2.getPrivateKey("rsatest00001");
    pub = token2.getPublicKey("rsatest00001");
    KeyUtil.testKey(priv, pub, token2.getSignProviderName());
    assertEquals(1024, KeyUtil.getKeyLength(pub));
    String pubKHash2 = CertTools.getFingerprintAsString(pub.getEncoded());
    assertEquals(pubKHash, pubKHash2);
    assertEquals(555, token2.getId()); // What we set in "createCryptoToken"

    // Clean up by deleting key
    cryptoToken.deleteEntry("rsatest00001");
  }

  /**
   * @param cryptoToken token
   * @throws CryptoTokenOfflineException fail
   * @throws CryptoTokenAuthenticationFailedException fail
   * @throws InvalidKeyException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws KeyStoreException fail
   * @throws InvalidAlgorithmParameterException fail
   * @throws SignatureException fail
   * @throws CertificateException fail
   * @throws NoSuchPaddingException fail
   * @throws IllegalBlockSizeException fail
   * @throws IOException fail
   * @throws BadPaddingException fail
   * @throws NoSuchSlotException fail
   */
  protected void doGenerateSymKey(final CryptoToken cryptoToken)
      throws CryptoTokenOfflineException,
          CryptoTokenAuthenticationFailedException, InvalidKeyException,
          NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
          InvalidAlgorithmParameterException, SignatureException,
          CertificateException, NoSuchPaddingException,
          IllegalBlockSizeException, IOException, BadPaddingException,
          NoSuchSlotException {
    cryptoToken.activate(TOKEN_PIN.toCharArray());
    assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
    cryptoToken.deleteEntry("aestest00001");
    // Generate the symm key
    cryptoToken.generateKey("AES", 256, "aestest00001");
    Key symkey = cryptoToken.getKey("aestest00001");
    // Encrypt something with the key, must be multiple of 16 bytes for AES
    // (need to do padding on your own)
    String input = "1234567812345678";
    Cipher cipher =
        Cipher.getInstance(
            "AES/CBC/NoPadding", cryptoToken.getEncProviderName());
    IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
    cipher.init(Cipher.ENCRYPT_MODE, symkey, ivSpec);
    byte[] cipherText = cipher.doFinal(input.getBytes());
    // Decrypt
    cipher.init(Cipher.DECRYPT_MODE, symkey, ivSpec);
    byte[] plainText = cipher.doFinal(cipherText);
    assertEquals(input, new String(plainText));

    // Serialize the token and re-create it from scratch
    Properties prop = cryptoToken.getProperties();
    byte[] data = cryptoToken.getTokenData();
    CryptoToken token2 =
        CryptoTokenFactory.createCryptoToken(
            cryptoToken.getClass().getName(),
            prop,
            data,
            555,
            "Some cryptoToken");
    token2.activate(TOKEN_PIN.toCharArray());
    // Now we have a new crypto token, so lets do the same hmac again and
    // compare
    Key symkey2 = token2.getKey("aestest00001");
    cipher.init(Cipher.DECRYPT_MODE, symkey2, ivSpec);
    plainText = cipher.doFinal(cipherText);
    assertEquals(input, new String(plainText));
    // Make sure the decryption fails as well, again multiple of 16 bytes
    String input2 = "2345678923456789";
    cipher.init(Cipher.DECRYPT_MODE, symkey2, ivSpec);
    plainText = cipher.doFinal(input2.getBytes());
    assertFalse(input.equals(new String(Hex.encode(plainText))));

    // Test that we can use the key for wrapping as well
    //      KeyPair kp = KeyTools.genKeys("512", "RSA");
    //      Cipher c = Cipher.getInstance("AES/CBC/NoPadding",
    // token.getEncProviderName());
    //        c.init( Cipher.WRAP_MODE, symkey2 );
    //        byte[] wrappedkey = c.wrap( kp.getPrivate() );
    //        Cipher c2 = Cipher.getInstance( "AES/CBC/NoPadding" );
    //        c2.init(Cipher.UNWRAP_MODE, symkey2);
    //        Key unwrappedkey = c.unwrap(wrappedkey, "RSA",
    // Cipher.PRIVATE_KEY);
    //        KeyTools.testKey((PrivateKey)unwrappedkey, kp.getPublic(), "BC");

    // Clean up by deleting key
    cryptoToken.deleteEntry("aestest00001");
  }

  /* Not used because HMAC on HSMs is too hard... keep for future reference
   * though
  protected void doGenerateHmacKey(CryptoToken token)
  throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException,
   NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
   SignatureException, CryptoTokenAuthenticationFailedException, IOException,
   InvalidAlgorithmParameterException, NoSuchPaddingException,
   IllegalBlockSizeException {
      token.activate(tokenpin.toCharArray());
      assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());

      try {
          token.deleteEntry(tokenpin.toCharArray(), "aestest00001");
          // Generate the symm key
          token.generateKey("AES", 256, "aestest00001");
          //token.generateKey("DES", 64, "aestest00001");
          Key hMacKey = token.getKey("aestest00001");
          // HMac something with the key
          String input = "12345678";
          Mac hMac = Mac.getInstance("HmacSHA256", token.getSignProviderName());
          hMac.init(hMacKey);
          hMac.update(input.getBytes());
          byte[] bytes = hMac.doFinal();

          // Serialize the token and re-create it from scratch
          Properties prop = token.getProperties();
          byte[] data = token.getTokenData();
          CryptoToken token2 = CryptoTokenFactory.createCryptoToken(
          token.getClass().getName(), prop, data, 555);
          token2.activate(tokenpin.toCharArray());
          // Now we have a new crypto token, so lets do the same hmac again
           *  and compare
          hMacKey = token2.getKey("aestest00001");
          hMac.init(hMacKey);
          hMac.update(input.getBytes());
          byte[] bytes1 = hMac.doFinal();
          assertEquals(new String(Hex.encode(bytes)),
           new String(Hex.encode(bytes1)));
          // Make sure the HMAC fails as well
          String input2 = "23456789";
          hMac.init(hMacKey);
          hMac.update(input2.getBytes());
          byte[] bytes2 = hMac.doFinal();
          assertFalse(new String(Hex.encode(bytes)).
          equals(new String(Hex.encode(bytes2))));
      } finally {
          // Clean up by deleting key
          //token.deleteEntry(tokenpin.toCharArray(), "aestest00001");
      }
  }
  */

  abstract String getProvider();
}
