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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.StringTools;

/**
 * Base class for crypto tokens handling things that are common for all crypto
 * tokens, hard or soft.
 *
 * @version $Id: BaseCryptoToken.java 30502 2018-11-14 13:44:43Z anatom $
 */
public abstract class BaseCryptoToken implements CryptoToken {

  private static final long serialVersionUID = 2133644669863292622L;

  /** Log4j instance. */
  private static final Logger LOG = Logger.getLogger(BaseCryptoToken.class);
  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** Used for signatures. */
  private String mJcaProviderName = null;
  /**
   * Used for encrypt/decrypt, can be same as for signatures for example for
   * pkcs#11.
   */
  private String mJceProviderName = null;
/** Authentication. */
  private char[] mAuthCode;
 /** Props. */
  private Properties properties;
  /** Id. */
  private int id;

  /** The java KeyStore backing the Crypto Token. */
  protected transient CachingKeyStoreWrapper keyStore;

  /** public constructor. */
  public BaseCryptoToken() {
    super();
  }

  /**
   * @param keystore store
   * @throws KeyStoreException fail
   */
  protected void setKeyStore(final KeyStore keystore)
          throws KeyStoreException {
    if (keystore == null) {
      this.keyStore = null;
    } else {
      this.keyStore =
          new CachingKeyStoreWrapper(
              keystore, CesecoreConfigurationHelper.isKeyStoreCacheEnabled());
    }
  }

  /**
   * Return the key store for this crypto token.
   *
   * @return the keystore.
   * @throws CryptoTokenOfflineException if Crypto Token is not available or
   *     connected.
   */
  protected CachingKeyStoreWrapper getKeyStore()
      throws CryptoTokenOfflineException {
    autoActivate();
    if (this.keyStore == null) {
      final String msg =
          INTRES.getLocalizedMessage(
              "token.errorinstansiate",
              mJcaProviderName,
              "keyStore (" + id + ") == null");
      throw new CryptoTokenOfflineException(msg);
    }
    return this.keyStore;
  }

  /**
   * TODO: This structure is confusing, with exceptions being thrown, caught,
   * ignored and then rethrown at a later stage. Please fix.
   */
  protected void autoActivate() {
    if ((this.mAuthCode != null) && (this.keyStore == null)) {
      try {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Trying to autoactivate CryptoToken");
        }
        activate(this.mAuthCode);
      } catch (Exception e) {
        LOG.debug(e);
      }
    }
  }

  /**
   * Do we permit extractable private keys? Only SW keys should be permitted to
   * be extractable, an overriding crypto token class can override this value.
   *
   * @return false if the key must not be extractable
   */
  public boolean doPermitExtractablePrivateKey() {
    return getProperties()
            .containsKey(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY)
        && Boolean.parseBoolean(
            getProperties()
                .getProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY));
  }

  /**
   * Similar to the method above, but only applies for internal testing of keys.
   * This method is called during testKeyPair to verify that a key that is
   * extractable can never be used, unless we allow extractable private keys.
   * Used for PKCS#11 (HSMs) to ensure that they are configured correctly. On a
   * PKCS11 Crypto Token, this should return the same as
   * doPermitExtractablePrivateKey(), on a Soft Crypto Token this should always
   * return true.
   *
   * @return false if the key must not be extractable, this will throw an error
   *     if the key is extractable when crypto token tries to test it.
   */
  public abstract boolean permitExtractablePrivateKeyForTest();

  @Override
  public void testKeyPair(final String alias)
      throws InvalidKeyException,
          CryptoTokenOfflineException { // NOPMD:this is not a junit test
    final PrivateKey privateKey = getPrivateKey(alias);
    final PublicKey publicKey = getPublicKey(alias);
    testKeyPair(alias, publicKey, privateKey);
  }

  @Override
  public void testKeyPair(
      final String alias,
      final PublicKey publicKey,
      final PrivateKey privateKey)
      throws InvalidKeyException { // NOPMD:this is not a junit test
    if (LOG.isDebugEnabled()) {
      final ByteArrayOutputStream baos = new ByteArrayOutputStream();
      final PrintStream ps = new PrintStream(baos);
      KeyTools.printPublicKeyInfo(publicKey, ps);
      ps.flush();
      LOG.debug("Testing key of type " + baos.toString());
    }
    if (!permitExtractablePrivateKeyForTest()
        && KeyTools.isPrivateKeyExtractable(privateKey)) {
      String msg =
          INTRES.getLocalizedMessage(
              "token.extractablekey",
              CesecoreConfigurationHelper.isPermitExtractablePrivateKeys());
      if (!CesecoreConfigurationHelper.isPermitExtractablePrivateKeys()) {
        throw new InvalidKeyException(msg);
      }
      LOG.info(msg);
    }
    KeyTools.testKey(privateKey, publicKey, getSignProviderName());
  }

  /**
   * Reads the public key object, does so from the certificate retrieved from
   * the alias from the KeyStore.
   *
   * @param alias alias the key alias to retrieve from the token
   * @param warn if we should log a warning if the key does not exist
   * @return the public key for the certificate represented by the given alias.
   * @throws KeyStoreException if the keystore has not been initialized.
   * @throws CryptoTokenOfflineException if Crypto Token is not available or
   *     connected.
   */
  protected PublicKey readPublicKey(final String alias, final boolean warn)
      throws KeyStoreException, CryptoTokenOfflineException {
    try {
      Certificate cert = getKeyStore().getCertificate(alias);
      PublicKey pubk = null;
      if (cert != null) {
        pubk = cert.getPublicKey();
      } else if (warn) {
        LOG.warn(INTRES.getLocalizedMessage("token.nopublic", alias));
        if (LOG.isDebugEnabled()) {
          Enumeration<String> en = getKeyStore().aliases();
          while (en.hasMoreElements()) {
            LOG.debug("Existing alias: " + en.nextElement());
          }
        }
      }
      return pubk;
    } catch (ProviderException e) {
      throw new CryptoTokenOfflineException(e);
    }
  }

  /**
   * Initiates the class members of this crypto token.
   *
   * @param aProperties A Properties object containing
   *     properties for this token.
   * @param doAutoActivate Set true if activation of this crypto token should
   *     happen in this method.
   * @param anId ID of this crypto token.
   */
  protected void init(
          final Properties aProperties,
          final boolean doAutoActivate,
          final int anId) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(">init: doAutoActivate=" + doAutoActivate);
    }
    this.id = anId;
    // Set basic properties that are of dynamic nature
    setProperties(aProperties);
    // Set properties that can not change dynamically

    if (doAutoActivate) {
      autoActivate();
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<init: doAutoActivate=" + doAutoActivate);
    }
  }

  @Override
  public int getId() {
    return this.id;
  }

  /**
   * @param anId ID
   */
  public void setId(final int anId) {
    this.id = anId;
  }

  @Override
  public String getTokenName() {
    return properties.getProperty(CryptoToken.TOKENNAME_PROPERTY);
  }

  @Override
  public void setTokenName(final String tokenName) {
    if (properties == null) {
      this.properties = new Properties();
    }
    properties.setProperty(CryptoToken.TOKENNAME_PROPERTY, tokenName);
  }

  @Override
  public Properties getProperties() {
    return properties;
  }

  @Override
  public void setProperties(final Properties aProperties) {
    if (aProperties == null) {
      this.properties = new Properties();
    } else {
      if (LOG.isDebugEnabled()) {
        // This is only a sections for debug logging. If we have enabled debug
        // logging we don't want to display any password in the log.
        // These properties may contain autoactivation PIN codes and we will,
        // only when debug logging, replace this with "hidden".
        if (aProperties.containsKey(CryptoToken.AUTOACTIVATE_PIN_PROPERTY)
            || aProperties.containsKey("PIN")) {
          Properties prop = new Properties();
          prop.putAll(aProperties);
          if (aProperties.containsKey(CryptoToken.AUTOACTIVATE_PIN_PROPERTY)) {
            prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "hidden");
          }
          if (aProperties.containsKey("PIN")) {
            prop.setProperty("PIN", "hidden");
          }
          LOG.debug("Prop: " + (prop != null ? prop.toString() : "null"));
        } else {
          // If no autoactivation PIN codes exists we can debug log everything
          // as original.
          LOG.debug(
              "Properties: "
                  + (aProperties != null ? aProperties.toString() : "null"));
        }
      } // if (log.isDebugEnabled())
      this.properties = aProperties;
      String authCode = BaseCryptoToken.getAutoActivatePin(aProperties);
      this.mAuthCode = authCode == null ? null : authCode.toCharArray();
    }
  } // setProperties

  /**
   * Retrieves the auto activation PIN code, if it has been set for this crypto
   * token. With an auto activation PIN the token does not have to be manually
   * activated.
   *
   * @param aProperties the crypto token properties that may contain auto
   *     activation PIN code
   * @return String or null
   */
  public static String getAutoActivatePin(final Properties aProperties) {
    final String pin =
        aProperties.getProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
    if (pin != null) {
      return StringTools.passwordDecryption(pin, "autoactivation pin");
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Not using autoactivation pin");
    }
    return null;
  }

  /**
   * Sets auto activation pin in passed in properties. Also returns the string
   * format of the autoactivation properties: pin mypassword
   *
   * @param properties a Properties bag where to set the auto activation pin,
   *     can be null if you only want to create the return string, does not set
   *     a null or empty password
   * @param pin the activation password
   * @param encrypt if the PIN should be encrypted with the configured password
   *     encryption key
   * @return A string that can be used to "setProperties" of a CryptoToken or
   *     null if pin is null or an empty string, this can safely be ignored if
   *     you don't know what to do with it
   */
  public static String setAutoActivatePin(
      final Properties properties,
      final String pin,
      final boolean encrypt) {
    String ret = null;
    if (StringUtils.isNotEmpty(pin)) {
      String authcode = pin;
      if (encrypt) {
        try {
          authcode = StringTools.pbeEncryptStringWithSha256Aes192(pin);
        } catch (Exception e) {
          LOG.error(INTRES.getLocalizedMessage("token.nopinencrypt"), e);
          authcode = pin;
        }
      }
      if (properties != null) {
        properties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, authcode);
      }
      ret = CryptoToken.AUTOACTIVATE_PIN_PROPERTY + " " + authcode;
    }
    return ret;
  }

  /**
   * Sets both signature and encryption providers. If encryption provider is the
   * same as signature provider this class name can be null.
   *
   * @param jcaProviderClassName signature provider class name
   * @param jceProviderClassName encryption provider class name, can be null
   * @throws ClassNotFoundException if the class specified by
   *     jcaProviderClassName could not be found.
   * @throws IllegalAccessException if the default constructor for the class
   *     specified by jcaProviderClassName was not public
   * @throws InstantiationException if the class specified by
   *     jcaProviderClassName was an abstract class, an interface, an array
   *     class, a primitive type, or void; or if it has no nullary constructor;
   *     or if the instantiation fails for some other reason.
   * @throws NoSuchMethodException in constructor not found
   * @throws InvocationTargetException If the underlying constructor throws an
   *     exception
   * @see #setJCAProvider(Provider)
   */
  protected void setProviders(
      final String jcaProviderClassName, final String jceProviderClassName)
      throws InstantiationException, IllegalAccessException,
          ClassNotFoundException, InvocationTargetException,
          NoSuchMethodException {
    Provider jcaProvider =
        (Provider)
            Class.forName(jcaProviderClassName).getConstructor().newInstance();
    setProvider(jcaProvider);
    this.mJcaProviderName = jcaProvider.getName();
    if (jceProviderClassName != null) {
      try {
        Provider jceProvider =
            (Provider)
                Class.forName(jceProviderClassName)
                    .getConstructor()
                    .newInstance();
        setProvider(jceProvider);
        this.mJceProviderName = jceProvider.getName();
      } catch (Exception e) {
        LOG.error(INTRES.getLocalizedMessage("token.jceinitfail"), e);
      }
    } else {
      this.mJceProviderName = null;
    }
  }

  @Override
  public void storeKey(
      final String alias,
      final Key key,
      final Certificate[] chain,
      final char[] password)
      throws KeyStoreException {
    // Removal of old key is only needed for sun-p11 with none ASCII chars in
    // the alias.
    // But it makes no harm to always do it and it should be fast.
    // If not done the entry will not be stored correctly in the p11 KeyStore.
    this.keyStore.deleteEntry(alias);
    this.keyStore.setKeyEntry(alias, key, password, chain);
  }

  /**
   * If we only have one provider to handle both JCA and JCE, and perhaps it is
   * not so straightforward to create the provider (for example PKCS#11
   * provider), we can create the provider in sub class and set it here, instead
   * of calling setProviders.
   *
   * @param prov the fully constructed Provider
   * @see #setProviders(String, String)
   */
  protected void setJCAProvider(final Provider prov) {
    setProvider(prov);
    this.mJcaProviderName = prov != null ? prov.getName() : null;
  }

  /**
   * If we don't use any of the methods to set a specific provider, but use some
   * already existing provider we should set the name of that provider at least.
   *
   * @param pName the provider name as retriever from Provider.getName()
   */
  protected void setJCAProviderName(final String pName) {
    this.mJcaProviderName = pName;
  }

  private void setProvider(final Provider prov) {
    if (prov != null) {
      String pName = prov.getName();
      if (pName.startsWith("LunaJCA")) {
        // Luna Java provider does not contain support for RSA/ECB/PKCS1Padding
        // but this is
        // the same as the alias below on small amounts of data
        prov.put("Alg.Alias.Cipher.RSA/NONE/NoPadding", "RSA//NoPadding");
        prov.put("Alg.Alias.Cipher.1.2.840.113549.1.1.1", "RSA//NoPadding");
        prov.put("Alg.Alias.Cipher.RSA/ECB/PKCS1Padding", "RSA//PKCS1v1_5");
        prov.put(
            "Alg.Alias.Cipher.1.2.840.113549.3.7", "DES3/CBC/PKCS5Padding");
      }
      // The provider will typically not be installed here. The BC provider (for
      // soft crypto tokens)
      // is installed during startup, as a generally used provider,
      // and the P11 provider for a specific slot is installed in #P11Slot
      if (Security.getProvider(pName) == null) {
        LOG.info("Adding Provider from BaseCryptoToken: " + pName);
        Security.addProvider(prov);
      }
      if (Security.getProvider(pName) == null) {
        throw new ProviderException(
            "Not possible to install provider from BaseCryptoToken: " + pName);
      }
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No provider passed to setProvider()");
      }
    }
  }

  @Override
  public String getSignProviderName() {
    return this.mJcaProviderName;
  }

  @Override
  public String getEncProviderName() {
    // If we don't have a specific JCE provider, it is most likely the same
    // as the JCA provider
    if (this.mJceProviderName == null) {
      return this.mJcaProviderName;
    }
    return this.mJceProviderName;
  }

  @Override
  public boolean isAliasUsed(final String alias) {
    boolean aliasInUse = false;
    try {
      getPublicKey(alias, false);
      aliasInUse = true;
    } catch (CryptoTokenOfflineException e) {
      try {
        getPrivateKey(alias, false);
        aliasInUse = true;
      } catch (CryptoTokenOfflineException e2) {
        try {
          getKey(alias, false);
          aliasInUse = true;
        } catch (CryptoTokenOfflineException e3) {
        }
      }
    }
    return aliasInUse;
  }

  @Override
  public PrivateKey getPrivateKey(final String alias)
      throws CryptoTokenOfflineException {
    return getPrivateKey(alias, true);
  }

  /**
   * @param alias Alias
   * @see #getPrivateKey(String)
   * @param warn if we should log a warning if the key does not exist
   * @return Private key
   * @throws CryptoTokenOfflineException if offline
   */
  private PrivateKey getPrivateKey(final String alias, final boolean warn)
      throws CryptoTokenOfflineException {
    // Auto activate is done in the call to getKeyStore below
    try {
      final PrivateKey privateK =
          (PrivateKey)
              getKeyStore()
                  .getKey(
                      alias,
                      (mAuthCode != null && mAuthCode.length > 0)
                          ? mAuthCode
                          : null);
      if (privateK == null) {
        if (warn) {
          LOG.warn(INTRES.getLocalizedMessage("token.noprivate", alias));
          if (LOG.isDebugEnabled()) {
            final Enumeration<String> aliases;
            aliases = getKeyStore().aliases();
            while (aliases.hasMoreElements()) {
              LOG.debug("Existing alias: " + aliases.nextElement());
            }
          }
        }
        final String msg =
            INTRES.getLocalizedMessage("token.errornosuchkey", alias);
        throw new CryptoTokenOfflineException(msg);
      }
      return privateK;
    } catch (KeyStoreException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (UnrecoverableKeyException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (ProviderException e) {
      throw new CryptoTokenOfflineException(e);
    }
  }

  @Override
  public PublicKey getPublicKey(final String alias)
      throws CryptoTokenOfflineException {
    return getPublicKey(alias, true);
  }

  /**
   * @param alias alias
   * @see #getPublicKey(String)
   * @param warn if we should log a warning if the key does not exist
   * @return Public key
   * @throws CryptoTokenOfflineException if offline
   */
  private PublicKey getPublicKey(final String alias, final boolean warn)
      throws CryptoTokenOfflineException {
    // Auto activate is done in the call to getKeyStore below (from
    // readPublicKey)
    try {
      PublicKey publicK = readPublicKey(alias, warn);
      if (publicK == null) {
        final String msg =
            INTRES.getLocalizedMessage("token.errornosuchkey", alias);
        throw new CryptoTokenOfflineException(msg);
      }
      final String str =
          getProperties()
              .getProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS);
      final boolean explicitEccParameters = Boolean.parseBoolean(str);
      if (explicitEccParameters && publicK.getAlgorithm().equals("EC")) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Using explicit parameter encoding for ECC key.");
        }
        publicK =
            ECKeyUtil.publicToExplicitParameters(
                publicK, BouncyCastleProvider.PROVIDER_NAME);
      }
      return publicK;
    } catch (KeyStoreException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (NoSuchProviderException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (IllegalArgumentException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoTokenOfflineException(e);
    }
  }

  @Override
  public Key getKey(final String alias) throws CryptoTokenOfflineException {
    return getKey(alias, true);
  }

  /**
   * see {@link #getKey(String)}.
   *
   * @param alias alias
   * @param warn if we should log a warning if the key does not exist
   * @return key
   * @throws CryptoTokenOfflineException if offline
   */
  private Key getKey(final String alias, final boolean warn)
      throws CryptoTokenOfflineException {
    // Auto activate is done in the call to getKeyStore below
    try {
      Key key =
          getKeyStore()
              .getKey(
                  alias,
                  (mAuthCode != null && mAuthCode.length > 0)
                      ? mAuthCode
                      : null);
      if (key == null) {
        // Do we have it stored as a soft key in properties?
        key = getKeyFromProperties(alias);
        if (key == null) {
          if (warn) {
            LOG.warn(INTRES.getLocalizedMessage("token.errornosuchkey", alias));
            if (LOG.isDebugEnabled()) {
              Enumeration<String> aliases;
              aliases = getKeyStore().aliases();
              while (aliases.hasMoreElements()) {
                LOG.debug("Existing alias: " + aliases.nextElement());
              }
            }
          }
          final String msg =
              INTRES.getLocalizedMessage("token.errornosuchkey", alias);
          throw new CryptoTokenOfflineException(msg);
        }
      }
      return key;
    } catch (KeyStoreException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (UnrecoverableKeyException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoTokenOfflineException(e);
    } catch (ProviderException e) {
      throw new CryptoTokenOfflineException(e);
    }
  }

  private Key getKeyFromProperties(final String alias) {
    Key key = null;
    Properties prop = getProperties();
    String str = prop.getProperty(alias);
    if (StringUtils.isNotEmpty(str)) {
      // TODO: unwrapping with rsa key is also needed later on
      try {
        PrivateKey privK = getPrivateKey("symwrap");
        Cipher cipher =
            Cipher.getInstance("RSA/ECB/PKCS1Padding", getEncProviderName());
        cipher.init(Cipher.UNWRAP_MODE, privK);
        byte[] bytes = Hex.decode(str);
        // TODO: hardcoded AES for now
        key = cipher.unwrap(bytes, "AES", Cipher.SECRET_KEY);
      } catch (CryptoTokenOfflineException e) {
        LOG.debug(e);
      } catch (NoSuchAlgorithmException e) {
        LOG.debug(e);
      } catch (NoSuchProviderException e) {
        LOG.debug(e);
      } catch (NoSuchPaddingException e) {
        LOG.debug(e);
      } catch (InvalidKeyException e) {
        LOG.debug(e);
      }
    }
    return key;
  }

  @Override
  public void reset() {
    // do nothing. the implementing class decides whether something could be
    // done to get the HSM working after a failure.
  }

  @Override
  public int getTokenStatus() {
    // Auto activate is done in the call to getKeyStore below
    int ret = CryptoToken.STATUS_OFFLINE;
    try {
      getKeyStore();
      ret = CryptoToken.STATUS_ACTIVE;
    } catch (CryptoTokenOfflineException e) {
      // NOPMD, ignore status is offline
    }
    return ret;
  }

  @Override
  public List<String> getAliases()
      throws KeyStoreException, CryptoTokenOfflineException {
    return Collections.list(getKeyStore().aliases());
  }

  @Override
  public boolean isAutoActivationPinPresent() {
    return getAutoActivatePin(getProperties()) != null;
  }
}
