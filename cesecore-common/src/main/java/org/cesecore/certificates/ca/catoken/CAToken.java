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
package org.cesecore.certificates.ca.catoken;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.StringTools;

/**
 * The CAToken is keeps references to the CA's key aliases and the CryptoToken
 * where the keys are stored.
 *
 * <p>The signing key can have 3 stages: - Next: Can become the new current CA
 * key when a valid signing certificate is present - Current: Is used to issue
 * certificates and has a CA certificate - Previous: The signing key before the
 * latest CA renewal.
 *
 * <p>Each CA signing key "generation" has a corresponding key sequence number
 * that is kept track of via this class. The key sequence also have the states
 * next, current and previous.
 *
 * <p>The CA token stores a reference (an integer) to the CryptoToken where the
 * CA keys are stored.
 *
 * @version $Id: CAToken.java 26093 2017-06-28 15:05:13Z anatom $
 */
public class CAToken extends UpgradeableDataHashMap {

  private static final long serialVersionUID = -459748276141898509L;

  /** Log4j instance. */
  private static final Logger LOG = Logger.getLogger(CAToken.class);
  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /**
   * Latest version of the UpgradeableHashMap, this determines if we need to
   * auto-upgrade any data.
   */
  public static final float LATEST_VERSION = 8;
  /** Classpath. */
  @Deprecated // Used by upgrade code
  public static final String CLASSPATH = "classpath";
  /** Data. */
  public static final String PROPERTYDATA = "propertydata";
  /** Store. */
  @Deprecated // Used by upgrade code
  public static final String KEYSTORE = "KEYSTORE";

  // The Initial sequence number is 00000-99999 or starts at 00001 according to
  // generated doc 2012-12-03.
  /** Sequence. */
  public static final String DEFAULT_KEYSEQUENCE = "00000";
  /** Alias. */
  public static final String SOFTPRIVATESIGNKEYALIAS = "signKey";
  /** Alias. */
  public static final String SOFTPRIVATEDECKEYALIAS = "encryptKey";
  /** These aliases were changed in EJBCA 6.4.1. */
  private static final String OLDPRIVATESIGNKEYALIAS = "privatesignkeyalias";
  /** Alias. */
  protected static final String OLDPRIVATEDECKEYALIAS = "privatedeckeyalias";

  /** A sequence for the keys, updated when keys are re-generated. */
  public static final String SEQUENCE = "sequence";
  /**
   * Format of the key sequence, the value for this property is one of
   * StringTools.KEY_SEQUENCE_FORMAT_XX.
   */
  public static final String SEQUENCE_FORMAT = "sequenceformat";

  /** Algorithm. */
  public static final String SIGNATUREALGORITHM = "signaturealgorithm";
  /** Algorithm. */
  public static final String ENCRYPTIONALGORITHM = "encryptionalgorithm";
  /** ID. */
  public static final String CRYPTOTOKENID = "cryptotokenid";
  /** ID. */
  private int cryptoTokenId;
  /** Keymap. */
  private transient PurposeMapping keyStrings = null;

  /** Constructor.
   *
   * @param aCryptoTokenId ID
   * @param aCaTokenProperties Props
   */
  public CAToken(final int aCryptoTokenId,
          final Properties aCaTokenProperties) {
    super();
    setCryptoTokenId(aCryptoTokenId);
    internalInit(aCaTokenProperties);
  }

  /**
   * Common code to initialize object called from all constructors.
   *
   * @param caTokenProperties properties
   */
  private void internalInit(final Properties caTokenProperties) {
    this.keyStrings = new PurposeMapping(caTokenProperties);
    setCATokenPropertyData(storeProperties(caTokenProperties));
  }

  /**
   * Constructor used to initialize a stored CA token, when the
   * UpgradeableHashMap has been stored as is.
   *
   * @param tokendata LinkedHashMap
   */
  @SuppressWarnings("rawtypes")
  public CAToken(final HashMap tokendata) {
    loadData(tokendata);
    final Object cryptoTokenIdObject = data.get(CAToken.CRYPTOTOKENID);
    if (cryptoTokenIdObject == null) {
      LOG.warn(
          "No CryptoTokenId in CAToken map. This can safely be ignored if"
              + " shown during an upgrade from EJBCA 5.0.x or lower.");
    } else {
      this.cryptoTokenId = Integer.parseInt((String) cryptoTokenIdObject);
    }
    final Properties caTokenProperties = getProperties();
    internalInit(caTokenProperties);
  }

  /**
   * Verifies that the all the mapped keys are present in the CryptoToken and
   * optionally that the test key is usable.
   *
   * @param caTokenSignTest bool
   * @param cryptoToken token
   * @return status code
   */
  public int getTokenStatus(final boolean caTokenSignTest,
          final CryptoToken cryptoToken) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCATokenStatus");
    }
    int ret = CryptoToken.STATUS_OFFLINE;
    // If we have no key aliases, no point in continuing...
    try {
      if (keyStrings != null) {
        final String[] aliases = keyStrings.getAliases();
        final String aliasCertSignKeyPrevious =
            keyStrings.getAlias(
                CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
        final String aliasCertSignKeyNext =
            keyStrings.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
        final String aliasTestKey =
            getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST);
        int foundKeys = 0;
        // Loop that checks  if there all key aliases have keys
        if (cryptoToken != null) {
          final HashMap<String, PrivateKey> aliasMap =
              new HashMap<String, PrivateKey>();
          for (final String alias : aliases) {
            PrivateKey privateKey = aliasMap.get(alias);
            if (privateKey == null) {
              try {
                privateKey = cryptoToken.getPrivateKey(alias);
                // Cache lookup to avoid having to retrieve the same key when
                // used for multiple purposes
                if (privateKey != null) {
                  aliasMap.put(alias, privateKey);
                }
              } catch (CryptoTokenOfflineException e) {
                privateKey = null;
              }
            }
            if (privateKey == null) {
              // We don't consider it critical if currently unused certificate
              // signing keys has been deleted (as long as it isn't mapped for
              // any other purposes)
              if (alias.equals(aliasCertSignKeyPrevious)
                  && keyStrings.isAliasMappedForSinglePurpose(
                      aliasCertSignKeyPrevious)) {
                foundKeys++;
                if (LOG.isDebugEnabled()) {
                  LOG.debug(
                      "Missing private key for alias: "
                          + alias
                          + " (Not treated as an error, since it is only"
                          + " mapped as the previous CA signing key.)");
                }
              } else if (alias.equals(aliasCertSignKeyNext)
                  && keyStrings.isAliasMappedForSinglePurpose(
                      aliasCertSignKeyNext)) {
                foundKeys++;
                if (LOG.isDebugEnabled()) {
                  LOG.debug(
                      "Missing private key for alias: "
                          + alias
                          + " (Not treated as an error, since it is only"
                          + " mapped as the next CA signing key.)");
                }
              } else {
                if (LOG.isDebugEnabled()) {
                  LOG.debug("Missing private key for alias: " + alias);
                }
              }
            } else {
              foundKeys++;
            }
            if (alias.equals(aliasTestKey)) {
              PublicKey publicKey;
              try {
                publicKey = cryptoToken.getPublicKey(aliasTestKey);
              } catch (CryptoTokenOfflineException e) {
                publicKey = null;
              }
              if (publicKey == null) {
                if (LOG.isDebugEnabled()) {
                  LOG.debug("Missing public key for alias: " + alias);
                }
              }
              // Check that that the testkey is usable by doing a test
              // signature.
              try {
                if (caTokenSignTest) {
                  cryptoToken.testKeyPair(alias, publicKey, privateKey);
                }
                // If we can test the testkey, we are finally active!
                ret = CryptoToken.STATUS_ACTIVE;
              } catch (
                  Throwable
                      th) { // NOPMD: we need to catch _everything_ when dealing
                            // with HSMs
                LOG.error(
                    INTRES.getLocalizedMessage(
                        "token.activationtestfail", cryptoToken.getId()),
                    th);
              }
            }
          }
        }
        if (foundKeys < aliases.length) {
          if (LOG.isDebugEnabled()) {
            StringBuilder builder = new StringBuilder();
            for (int j = 0; j < aliases.length; j++) {
              builder.append(' ').append(aliases[j]);
            }
            LOG.debug(
                "Not enough keys for the key aliases: " + builder.toString());
          }
          ret = CryptoToken.STATUS_OFFLINE;
        }
      }
    } catch (CryptoTokenOfflineException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("CryptoToken offline: " + e.getMessage());
      }
    }

    if (LOG.isTraceEnabled()) {
      LOG.trace("<getCATokenStatus: " + ret);
    }
    return ret;
  }

  /**
   * @param purpose purpose
   * @return the key pair alias in the CryptoToken from the
   *     CATokenConstants.CAKEYPURPOSE_..
   * @throws CryptoTokenOfflineException if offline
   */
  public String getAliasFromPurpose(final int purpose)
      throws CryptoTokenOfflineException {
    if (keyStrings == null) {
      // keyStrings is transient and can be null after serialization
      keyStrings = new PurposeMapping(getProperties());
    }
    final String alias = keyStrings.getAlias(purpose);
    if (alias == null) {
      throw new CryptoTokenOfflineException(
          "No alias for key purpose " + purpose);
    }
    return alias;
  }

  /** @return the reference to the CA's CryptoToken */
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }
  /**
   * Set the reference to the CA's CryptoToken. Use with care!
   *
   * @param aCryptoTokenId ID
   */
  public void setCryptoTokenId(final int aCryptoTokenId) {
    this.cryptoTokenId = aCryptoTokenId;
    data.put(CAToken.CRYPTOTOKENID, String.valueOf(aCryptoTokenId));
  }

  /**
   * Set a property and update underlying Map.
   *
   * @param key Key
   * @param value Value
   */
  public void setProperty(final String key, final String value) {
    final Properties caTokenProperties = getProperties();
    caTokenProperties.setProperty(key, value);
    setCATokenPropertyData(storeProperties(caTokenProperties));
  }

  /**
   * Internal method just to get rid of the always present date that is part of
   * the standard Properties.store().
   *
   * @param caTokenProperties properties
   * @return String that can be loaded by Properties.load
   */
  private String storeProperties(final Properties caTokenProperties) {
    this.keyStrings = new PurposeMapping(caTokenProperties);
    final StringWriter sw = new StringWriter();
    try (PrintWriter writer = new PrintWriter(sw); ) {
      final Enumeration<Object> e = caTokenProperties.keys();
      while (e.hasMoreElements()) {
        final Object s = e.nextElement();
        if (caTokenProperties.get(s) != null) {
          writer.println(s + "=" + caTokenProperties.get(s));
        }
      }
    }
    return sw.toString();
  }

  /**
   * Sets the propertydata used to configure this CA Token.
   *
   * @param propertydata data
   */
  private void setCATokenPropertyData(final String propertydata) {
    data.put(CAToken.PROPERTYDATA, propertydata);
  }

  /** @return Properties */
  public Properties getProperties() {
    String propertyStr = null;
    if (data != null) {
      propertyStr = (String) data.get(CAToken.PROPERTYDATA);
    }
    return getPropertiesFromString(propertyStr);
  }

  /**
   * @param propertyStr String
   * @return Properties */
  public static Properties getPropertiesFromString(final String propertyStr) {
    final Properties prop = new Properties();
    if (StringUtils.isNotEmpty(propertyStr)) {
      try {
        // If the input string contains \ (backslash on windows) we must convert
        // it to \\
        // Otherwise properties.load will parse it as an escaped character, and
        // that is not good
        final String propertyStrAdjusted =
            StringUtils.replace(propertyStr, "\\", "\\\\");
        prop.load(new StringReader(propertyStrAdjusted));
        // Trim whitespace in values
        for (final Object keyObj : prop.keySet()) {
          String key = (String) keyObj;
          String value = prop.getProperty(key);
          prop.setProperty(key, value.trim());
        }
      } catch (IOException e) {
        LOG.error("Error getting PKCS#11 token properties: ", e);
      }
    }
    return prop;
  }

  /**
   * @return the Sequence, that is a sequence that is updated when keys are
   *     re-generated
   */
  public String getKeySequence() {
    Object seq = data.get(SEQUENCE);
    if (seq == null) {
      seq = new String(CAToken.DEFAULT_KEYSEQUENCE);
    }
    return (String) seq;
  }

  /**
   * Sets the key sequence.
   *
   * @param sequence sequence
   */
  public void setKeySequence(final String sequence) {
    data.put(SEQUENCE, sequence);
  }

  /**
   * Sets the SequenceFormat.
   *
   * @param sequence format
   */
  public void setKeySequenceFormat(final int sequence) {
    data.put(SEQUENCE_FORMAT, sequence);
  }

  /** @return the Sequence format, that is the format of the key sequence */
  public int getKeySequenceFormat() {
    Object seqF = data.get(SEQUENCE_FORMAT);
    if (seqF == null) {
      seqF = Integer.valueOf(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
    }
    return (Integer) seqF;
  }

  /** @return the SignatureAlgoritm */
  public String getSignatureAlgorithm() {
    return (String) data.get(CAToken.SIGNATUREALGORITHM);
  }

  /**
   * Sets the SignatureAlgoritm.
   *
   * @param signaturealgoritm Algo
   */
  public void setSignatureAlgorithm(final String signaturealgoritm) {
    data.put(CAToken.SIGNATUREALGORITHM, signaturealgoritm);
  }

  /** @return the EncryptionAlgoritm */
  public String getEncryptionAlgorithm() {
    return (String) data.get(CAToken.ENCRYPTIONALGORITHM);
  }

  /**
   * Sets the EncryptionAlgoritm.
   *
   * @param encryptionalgo Algo
   */
  public void setEncryptionAlgorithm(final String encryptionalgo) {
    data.put(CAToken.ENCRYPTIONALGORITHM, encryptionalgo);
  }

  /** @see org.cesecore.internal.UpgradeableDataHashMap#getLatestVersion() */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** @see org.cesecore.internal.UpgradeableDataHashMap#upgrade() */
  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      String msg =
          INTRES.getLocalizedMessage(
              "token.upgrade", Float.valueOf(getVersion()));
      LOG.info(msg);
      // Put upgrade stuff here
      if (data.get(CAToken.SEQUENCE_FORMAT) == null) { // v7
        LOG.info(
            "Adding new sequence format to CA Token data: "
                + StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        data.put(
            CAToken.SEQUENCE_FORMAT, StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
      }
      if (data.get(CAToken.SEQUENCE) == null) { // v7
        LOG.info(
            "Adding new default key sequence to CA Token data: "
                + CAToken.DEFAULT_KEYSEQUENCE);
        data.put(CAToken.SEQUENCE, CAToken.DEFAULT_KEYSEQUENCE);
      }

      if (data.get(CAToken.CLASSPATH)
          != null) { // v8 upgrade of classpaths for CESeCore
        final String classpath = (String) data.get(CAToken.CLASSPATH);
        LOG.info("Upgrading CA token classpath: " + classpath);
        String newclasspath = classpath;
        if (StringUtils.equals(
            classpath, "org.ejbca.core.model.ca.catoken.SoftCAToken")) {
          newclasspath = "org.cesecore.keys.token.SoftCryptoToken";
          // Upgrade properties to set a default key, also for soft crypto
          // tokens
          Properties prop = getProperties();
          // A small unfortunate special property that we have to make in order
          // to
          // be able to use soft keystores that does not have a specific test or
          // default key
          if ((prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING)
                  == null)
              && (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING)
                  == null)) {
            // The soft key alias was changed from privatesignkeyalias to
            // signKey in EJBCA 6.4.1, which is long after
            // we changed the classpath. So if we come in here, we are upgrading
            // a token that is way before 6.4.1, meaning
            // that it uses the old key aliases
            LOG.info(
                "Setting CAKEYPURPOSE_CERTSIGN_STRING and"
                    + " CAKEYPURPOSE_CRLSIGN_STRING to privatesignkeyalias.");
            prop.setProperty(
                CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING,
                CAToken.OLDPRIVATESIGNKEYALIAS);
            prop.setProperty(
                CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING,
                CAToken.OLDPRIVATESIGNKEYALIAS);
          }
          if ((prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING)
                  == null)
              && (prop.getProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING)
                  == null)) {
            // Same as above regarding key aliases
            LOG.info(
                "Setting CAKEYPURPOSE_DEFAULT_STRING to privatedeckeyalias.");
            prop.setProperty(
                CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING,
                CAToken.OLDPRIVATEDECKEYALIAS);
          }
          setCATokenPropertyData(
              storeProperties(prop)); // Stores property string in "data"
        } else if (StringUtils.equals(
            classpath, "org.ejbca.core.model.ca.catoken.PKCS11CAToken")) {
          newclasspath = "org.cesecore.keys.token.PKCS11CryptoToken";
        } else if (StringUtils.equals(
            classpath, "org.ejbca.core.model.ca.catoken.NullCAToken")) {
          newclasspath = "org.cesecore.keys.token.NullCryptoToken";
        } else if (StringUtils.equals(
            classpath, "org.ejbca.core.model.ca.catoken.NFastCAToken")) {
          LOG.error(
              "Upgrading of NFastCAToken not supported, you need to convert to"
                  + " using PKCS11CAToken before upgrading.");
        }
        data.put(CAToken.CLASSPATH, newclasspath);
      }

      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  /**
   * Use current key sequence to generate and store a "next" key sequence and
   * "next" singing key alias.
   *
   * @return the next sign key alias.
   */
  public String generateNextSignKeyAlias() {
    // Generate a new key sequence
    final String currentKeySequence = getKeySequence();
    final String newKeySequence =
        StringTools.incrementKeySequence(
            getKeySequenceFormat(), currentKeySequence);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Current key sequence: "
              + currentKeySequence
              + "  New key sequence: "
              + newKeySequence);
    }
    // Generate a key alias based on the new key sequence
    final String currentCertSignKeyLabel =
        keyStrings.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
    final String newCertSignKeyLabel =
        StringUtils.removeEnd(currentCertSignKeyLabel, currentKeySequence)
            + newKeySequence;
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Current sign key alias: "
              + currentCertSignKeyLabel
              + "  New sign key alias: "
              + newCertSignKeyLabel);
    }
    // Store the new values in the properties of this token
    setNextCertSignKey(newCertSignKeyLabel);
    setNextKeySequence(newKeySequence);
    return newCertSignKeyLabel;
  }

  /**
   * Next sign key becomes current. Current becomes previous. Same goes for
   * KeySequence. CRL sign key is updated if it is the same as cert sign key
   */
  public void activateNextSignKey() {
    final Properties caTokenProperties = getProperties();
    // Replace certificate (and crl) signing key aliases (if present)
    boolean swichedSigningKey = false;
    final String nextCertSignKeyLabel =
        keyStrings.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
    if (nextCertSignKeyLabel != null) {
      final String currentCertSignKeyLabel =
          keyStrings.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
      final String currentCrlSignKeyLabel =
          keyStrings.getAlias(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
      if (LOG.isDebugEnabled()) {
        LOG.debug("CERTSIGN_NEXT: " + nextCertSignKeyLabel);
        LOG.debug("CERTSIGN:      " + currentCertSignKeyLabel);
        LOG.debug("CRLSIGN:       " + currentCrlSignKeyLabel);
      }
      if (StringUtils.equals(currentCertSignKeyLabel, currentCrlSignKeyLabel)) {
        LOG.info("Setting CRL signing key alias to: " + nextCertSignKeyLabel);
        caTokenProperties.setProperty(
            CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, nextCertSignKeyLabel);
      }
      LOG.info(
          "Setting certificate signing key alias to: " + nextCertSignKeyLabel);
      caTokenProperties.setProperty(
          CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS,
          currentCertSignKeyLabel);
      caTokenProperties.setProperty(
          CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, nextCertSignKeyLabel);
      caTokenProperties.remove(
          CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT);
      swichedSigningKey =
          !StringUtils.equals(nextCertSignKeyLabel, currentCertSignKeyLabel);
    }
    // Replace key sequence (if present)
    final String nextKeySequence =
        caTokenProperties.getProperty(CATokenConstants.NEXT_SEQUENCE_PROPERTY);
    final String currentKeySequence = getKeySequence();
    if (nextKeySequence != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Current KeySequence: " + getKeySequence());
      }
      LOG.info("Set key sequence from nextSequence: " + nextKeySequence);
      caTokenProperties.setProperty(
          CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY, currentKeySequence);
      setKeySequence(nextKeySequence);
      caTokenProperties.remove(CATokenConstants.NEXT_SEQUENCE_PROPERTY);
    } else if (swichedSigningKey) {
      // If we did not have a next key sequence before this activation we
      // generate one and push back the current.
      final String newKeySequence =
          StringTools.incrementKeySequence(
              getKeySequenceFormat(), currentKeySequence);
      caTokenProperties.setProperty(
          CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY, currentKeySequence);
      setKeySequence(newKeySequence);
    } else {
      // So there is no key sequence and we didn't switch singing key..
      // ..let us just set the previous sequence to the current to at least
      // match the singing key alias
      caTokenProperties.setProperty(
          CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY, currentKeySequence);
    }
    // Store changes in the CAToken's properties
    setCATokenPropertyData(storeProperties(caTokenProperties));
  }

  /**
   * Set the next singing key alias.
   *
   * @param nextSignKeyAlias Alias
   */
  public void setNextCertSignKey(final String nextSignKeyAlias) {
    final Properties caTokenProperties = getProperties();
    caTokenProperties.setProperty(
        CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, nextSignKeyAlias);
    setCATokenPropertyData(storeProperties(caTokenProperties));
  }

  /**
   * Set the next key sequence.
   *
   * @param newSequence sequence
   */
  public void setNextKeySequence(final String newSequence) {
    final Properties caTokenProperties = getProperties();
    caTokenProperties.setProperty(
        CATokenConstants.NEXT_SEQUENCE_PROPERTY, newSequence);
    setCATokenPropertyData(storeProperties(caTokenProperties));
  }
}
