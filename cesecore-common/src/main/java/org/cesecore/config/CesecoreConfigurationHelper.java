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

package org.cesecore.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;

/**
 * This file handles configuration from ejbca.properties.
 *
 * @version $Id: CesecoreConfiguration.java 34415 2020-01-30 12:29:30Z aminkh $
 */
public final class CesecoreConfigurationHelper {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CesecoreConfigurationHelper.class);

  /** NOTE: diff between EJBCA and CESeCore. */
  public static final String PERSISTENCE_UNIT = "ejbca";
  /** Splitter. */
  public static final String AVAILABLE_CIPHER_SUITES_SPLIT_CHAR = ";";
  /** SN size. */
  public static final String DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA = "20";
  /** SN size. **/
  private static final String DEFAULT_SERIAL_NUMBER_OCTET_SIZE_EXISTINGCA = "8";
  /** Boolean true. */
  private static final String TRUE = "true";
  /** Default fetch size. */
  private static final long DEFAULT_FETCH = 500000L;
  /**
   * Used just in {@link #getForbiddenCharacters()}. The method is called very
   * often so we declare this String in the class so it does not have to be each
   * time the method is called.
   */
  private static final String FORBIDDEN_CARACTERS_KEY = "forbidden.characters";
  /** Max number of supported suites. */
  private static final int MAX_SUITES = 255;
  /** Milliseconds. */
  private static final long MS_PER_S = 1000L;
  /** Ten seconds. */
  private static final long TEN_SECONDS = 10L * MS_PER_S;
  /** Thirty Seconds. */
  private static final long THIRTY_SECONDS = 30L * MS_PER_S;
  /** 100 seconds. */
  private static final long HUNDRED_SECONDS = 100L * MS_PER_S;

  /**
   * This is a singleton so it's not allowed to create an instance explicitly.
   */
  private CesecoreConfigurationHelper() { }

  /** @return Cesecore Datasource name */
  public static String getDataSourceJndiName() {
    String prefix =
        ConfigurationHolderUtil.getString("datasource.jndi-name-prefix");
    String name = ConfigurationHolderUtil.getString("datasource.jndi-name");

    return prefix + name;
  }

  /** @return Password used to protect CA keystores in the database. */
  public static String getCaKeyStorePass() {
    return ConfigurationHolderUtil.getExpandedString("ca.keystorepass");
  }

  /**
   * @return The length in octets of certificate serial numbers generated for
   *     legacy CAs. (8 octets is a 64 bit serial number.)
   */
  public static int getSerialNumberOctetSizeForExistingCa() {
    String value =
        ConfigurationHolderUtil.getConfiguredString("ca.serialnumberoctetsize");
    if (value == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Using default value of "
                + DEFAULT_SERIAL_NUMBER_OCTET_SIZE_EXISTINGCA
                + " for existing CA's ca.serialnumberoctetsize");
      }
      value = DEFAULT_SERIAL_NUMBER_OCTET_SIZE_EXISTINGCA;
    }
    return Integer.parseInt(value);
  }

  /**
   * @return The length in octets of certificate serial numbers generated for
   *     new CAs.
   */
  public static int getSerialNumberOctetSizeForNewCa() {
    String value =
        ConfigurationHolderUtil.getConfiguredString("ca.serialnumberoctetsize");
    if (value == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Using default value of "
                + DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA
                + " for new CA's ca.serialnumberoctetsize");
      }
      value = DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA;
    }
    return Integer.parseInt(value);
  }

  /**
   * @return The algorithm that should be used to generate random numbers
   *     (Random Number Generator Algorithm)
   */
  public static String getCaSerialNumberAlgorithm() {
    return ConfigurationHolderUtil.getString("ca.rngalgorithm");
  }

  /**
   * @return The date and time from which an expire date of a certificate is to
   *     be considered to be too far in the future.
   */
  public static String getCaTooLateExpireDate() {
    return ConfigurationHolderUtil.getExpandedString("ca.toolateexpiredate");
  }

  /**
   * The relative time offset for the notBefore value of CA and end entity
   * certificates. Changing this value, also changes the notAfter attribute of
   * the certificates, if a relative time is used for its validity. While
   * certificate issuance this value can be overwritten by the corresponding
   * value in the certificate profile used.
   *
   * @see
   *     org.cesecore.certificates.certificateprofile.CertificateProfile#getCertificateValidityOffset()
   * @see org.cesecore.util.SimpleTime
   * @return offset
   */
  public static String getCertificateValidityOffset() {
    return ConfigurationHolderUtil.getExpandedString(
            "certificate.validityoffset");
  }

  /**
   * @return true if it is permitted to use an extractable private key in a HSM.
   */
  public static boolean isPermitExtractablePrivateKeys() {
    final String value =
        ConfigurationHolderUtil.getString("ca.doPermitExtractablePrivateKeys");
    return value != null && value.trim().equalsIgnoreCase(TRUE);
  }

  /**
   * @return The language that should be used internally for logging, exceptions
   *     and approval notifications.
   */
  public static String getInternalResourcesPreferredLanguage() {
    return ConfigurationHolderUtil.getExpandedString(
        "intresources.preferredlanguage");
  }

  /**
   * @return The language used internally if a resource not found in the
   *     preferred language
   */
  public static String getInternalResourcesSecondaryLanguage() {
    return ConfigurationHolderUtil.getExpandedString(
        "intresources.secondarylanguage");
  }

  /**
   * @return Sets pre-defined EC curve parameters for the implicitlyCA facility.
   */
  public static String getEcdsaImplicitlyCaQ() {
    return ConfigurationHolderUtil.getExpandedString("ecdsa.implicitlyca.q");
  }

  /**
   * @return Sets pre-defined EC curve parameters for the implicitlyCA facility.
   */
  public static String getEcdsaImplicitlyCaA() {
    return ConfigurationHolderUtil.getExpandedString("ecdsa.implicitlyca.a");
  }

  /**
   * @return Sets pre-defined EC curve parameters for the implicitlyCA facility.
   */
  public static String getEcdsaImplicitlyCaB() {
    return ConfigurationHolderUtil.getExpandedString("ecdsa.implicitlyca.b");
  }

  /**
   * @return Sets pre-defined EC curve parameters for the implicitlyCA facility.
   */
  public static String getEcdsaImplicitlyCaG() {
    return ConfigurationHolderUtil.getExpandedString("ecdsa.implicitlyca.g");
  }

  /**
   * @return Sets pre-defined EC curve parameters for the implicitlyCA facility.
   */
  public static String getEcdsaImplicitlyCaN() {
    return ConfigurationHolderUtil.getExpandedString("ecdsa.implicitlyca.n");
  }

  /**
   * Flag indicating if the BC provider should be removed before installing it
   * again. When developing and re-deploying alot this is needed so you don't
   * have to restart JBoss all the time. In production it may cause failures
   * because the BC provider may get removed just when another thread wants to
   * use it. Therefore the default value is false.
   *
   * @return flag
   */
  public static boolean isDevelopmentProviderInstallation() {
    return TRUE.equalsIgnoreCase(
        ConfigurationHolderUtil.getString("development.provider.installation"));
  }

  /**
   * @return Parameter to specify if retrieving CAInfo and CA from
   *     CAAdminSession should be cached, and in that case for how long.
   */
  public static long getCacheCaTimeInCaSession() {
    // Cache for 10 seconds is the default (Changed 2013-02-14 under ECA-2801.)
    return getLongValue(
        "cainfo.cachetime", TEN_SECONDS, "milliseconds to cache CA info");
  }

  /**
   * @return configuration for when cached CryptoTokens are considered stale and
   *     will be refreshed from the database.
   */
  public static long getCacheTimeCryptoToken() {
    return getLongValue("cryptotoken.cachetime", TEN_SECONDS, "milliseconds");
  }

  /**
   * @return configuration for when cached SignersMapping are considered stale
   *     and will be refreshed from the database.
   */
  public static long getCacheTimeInternalKeyBinding() {
    return getLongValue("internalkeybinding.cachetime",
            TEN_SECONDS, "milliseconds");
  }

  /**
   * @return Parameter to specify if retrieving Certificate profiles in
   *     StoreSession should be cached, and in that case for how long.
   */
  public static long getCacheCertificateProfileTime() {
    return getLongValue(
        "certprofiles.cachetime",
        MS_PER_S,
        "milliseconds to cache Certificate profiles");
  }

  /**
   * @return Parameter to specify if retrieving GlobalOcspConfiguration (in
   *     GlobalConfigurationSessionBean) should be cached, and in that case for
   *     how long.
   */
  public static long getCacheGlobalOcspConfigurationTime() {
    return getLongValue(
        "ocspconfigurationcache.cachetime",
        THIRTY_SECONDS,
        "milliseconds to cache OCSP settings");
  }

  /**
   * @return Parameter to specify if retrieving PublicKeyBlacklist objects from
   *     PublicKeyBlacklistSession should be cached, and in that case for how
   *     long.
   */
  public static long getCachePublicKeyBlacklistTime() {
    return getLongValue(
        "blacklist.cachetime",
        THIRTY_SECONDS,
        "milliseconds to cache public key blacklist entries");
  }

  /**
   * @return Parameter to specify if retrieving KeyValidator objects from
   *     KeyValidatorSession should be cached, and in that case for how long.
   */
  public static long getCacheKeyValidatorTime() {
    return getLongValue(
        "validator.cachetime",
        THIRTY_SECONDS, "milliseconds to cache validators");
  }

  /**
   * @return Parameter to specify if retrieving Authorization Access Rules (in
   *     AuthorizationSession) should be cached, and in that case for how long.
   */
  public static long getCacheAuthorizationTime() {
    return getLongValue(
        "authorization.cachetime",
        THIRTY_SECONDS,
        "milliseconds to cache authorization");
  }

  /**
   * @return Parameter to specify if retrieving GlobalConfiguration (in
   *     GlobalConfigurationSessionBean) should be cached, and in that case for
   *     how long.
   */
  public static long getCacheGlobalConfigurationTime() {
    return getLongValue(
        "globalconfiguration.cachetime",
        THIRTY_SECONDS,
        "milliseconds to cache authorization");
  }

  private static long getLongValue(
      final String propertyName, final long defaultValue, final String unit) {
    final String value = ConfigurationHolderUtil.getString(propertyName);
    long time = defaultValue;
    try {
      if (value != null) {
        time = Long.valueOf(value);
      }
    } catch (NumberFormatException e) {
      LOG.error(
          "Invalid value for "
              + propertyName
              + ". Using default "
              + defaultValue
              + ". Value must be decimal number ("
              + unit
              + "): "
              + e.getMessage());
    }
    return time;
  }

  /**
   * @return provider
   * @throws ClassNotFoundException not found
   */
  public static Class<?> getTrustedTimeProvider()
      throws ClassNotFoundException {
    String providerClass = ConfigurationHolderUtil.getString("time.provider");
    if (LOG.isDebugEnabled()) {
      LOG.debug("TrustedTimeProvider class: " + providerClass);
    }
    return Class.forName(providerClass);
  }

  /**
   * @return Regular Expression to fetch the NTP offset from an NTP client
   *     output
   */
  public static Pattern getTrustedTimeNtpPattern() {
    String regex = ConfigurationHolderUtil.getString("time.ntp.pattern");
    return Pattern.compile(regex);
  }

  /**
   * @return System command to execute an NTP client call and obtain information
   *     about the selected peers and their offsets
   */
  public static String getTrustedTimeNtpCommand() {
    return ConfigurationHolderUtil.getString("time.ntp.command");
  }

  /**
   * Option if we should keep internal CA keystores in the CAData table to be
   * compatible with CeSecore 1.1/EJBCA 5.0. Default to true. Set to false when
   * all nodes in a cluster have been upgraded to CeSecore 1.2/EJBCA 5.1 or
   * later, then internal keystore in CAData will be replaced with a foreign key
   * in to the migrated entry in CryptotokenData.
   *
   * @return boolean
   */
  public static boolean isKeepInternalCAKeystores() {
    final String value =
        ConfigurationHolderUtil.getString("db.keepinternalcakeystores");
    return value == null || !value.trim().equalsIgnoreCase("false");
  }

  /**
   * When we run in a cluster, each node should have it's own identifier. By
   * default we use the DNS name.
   *
   * @return ID
   */
  public static String getNodeIdentifier() {
    final String propertyName = "cluster.nodeid";
    final String propertyValue = "undefined";
    String value = ConfigurationHolderUtil.getString(propertyName);
    if (value == null) {
      try {
        value = InetAddress.getLocalHost().getHostName();
      } catch (UnknownHostException e) {
        LOG.warn(
            propertyName
                + " is undefined on this host and was not able to resolve"
                + " hostname. Using "
                + propertyValue
                + " which is fine if use a single node.");
        value = propertyValue;
      }
      // Update configuration, so we don't have to make a hostname lookup each
      // time we call this method.
      ConfigurationHolderUtil.updateConfigurationWithoutBackup(
          propertyName, value);
    }
    return value;
  }

  /** @return Oid tree for GOST32410 */
  public static String getOidGost3410() {
    return ConfigurationHolderUtil.getString("extraalgs.gost3410.oidtree");
  }

  /** @return Oid tree for DSTU4145 */
  public static String getOidDstu4145() {
    return ConfigurationHolderUtil.getString("extraalgs.dstu4145.oidtree");
  }

  /** @return extraalgs such as GOST, DSTU */
  public static List<String> getExtraAlgs() {
    return ConfigurationHolderUtil.getPrefixedPropertyNames("extraalgs");
  }

  /**
   * @param algName Name
   * @return title of the algorithm
   */
  public static String getExtraAlgTitle(final String algName) {
    return ConfigurationHolderUtil.getString(
        "extraalgs." + algName.toLowerCase() + ".title");
  }

  /**
   * @param algName Name
   * @return "subalgorithms", e.g. different keylengths or curves
   */
  public static List<String> getExtraAlgSubAlgs(final String algName) {
    return ConfigurationHolderUtil.getPrefixedPropertyNames(
        "extraalgs." + algName + ".subalgs");
  }

  /**
   * @param algName Alg
   * @param subAlg sub-alg
   * @return title
   */
  public static String getExtraAlgSubAlgTitle(
          final String algName, final String subAlg) {
    String name =
        ConfigurationHolderUtil.getString(
            "extraalgs." + algName + ".subalgs." + subAlg + ".title");
    if (name == null) {
      // Show the algorithm name, if it has one
      String end =
          ConfigurationHolderUtil.getString(
              "extraalgs." + algName + ".subalgs." + subAlg + ".name");
      // Otherwise, show the key name in the configuration
      if (end == null) {
        end = subAlg;
      }
      name =
          ConfigurationHolderUtil.getString("extraalgs." + algName + ".title")
              + " "
              + end;
    }
    return name;
  }

  /**
   * @param algName Alg
   * @param subAlg Alg
   * @return Name
   */
  public static String getExtraAlgSubAlgName(
          final String algName, final String subAlg) {
    String name =
        ConfigurationHolderUtil.getString(
            "extraalgs." + algName + ".subalgs." + subAlg + ".name");
    if (name == null) {
      // Not a named algorithm
      name = getExtraAlgSubAlgOid(algName, subAlg);
    }
    return name;
  }

  /**
   * @param algName Alg
   * @param subAlg Alg
   * @return Name
   */
  public static String getExtraAlgSubAlgOid(
          final String algName, final String subAlg) {
    final String oidTree =
        ConfigurationHolderUtil.getString("extraalgs." + algName + ".oidtree");
    final String oidEnd =
        ConfigurationHolderUtil.getString(
            "extraalgs." + algName + ".subalgs." + subAlg + ".oid");

    if (oidEnd != null && oidTree != null) {
      return oidTree + "." + oidEnd;
    }
    if (oidEnd != null) {
      return oidEnd;
    } else {
      return null;
    }
  }

  /**
   * @return true if the Base64CertData table should be used for storing the
   *     certificates.
   */
  public static boolean useBase64CertTable() {
    final String value =
        ConfigurationHolderUtil.getString(
                "database.useSeparateCertificateTable");
    return value != null && Boolean.parseBoolean(value.trim());
  }

  /**
   * @param tableName Name of DB table
   * @return If database integrity protection should be used or not.
   */
  public static boolean useDatabaseIntegrityProtection(final String tableName) {
    // First check if we have explicit configuration for this entity
    final String enableProtect =
        ConfigurationHolderUtil.getString(
            "databaseprotection.enablesign." + tableName);
    if (enableProtect != null) {
      return Boolean.TRUE.toString().equalsIgnoreCase(enableProtect);
    }
    // Otherwise use the global or default
    return Boolean.TRUE
        .toString()
        .equalsIgnoreCase(
            ConfigurationHolderUtil.getString("databaseprotection.enablesign"));
  }

  /**
   * @param tableName Name of DB table
   * @return If database integrity verification should be used or not.
   */
  public static boolean useDatabaseIntegrityVerification(
      final String tableName) {
    // First check if we have explicit configuration for this entity
    final String enableVerify =
        ConfigurationHolderUtil.getString(
            "databaseprotection.enableverify." + tableName);
    if (enableVerify != null) {
      return Boolean.TRUE.toString().equalsIgnoreCase(enableVerify);
    }
    // Otherwise use the global or default
    return Boolean.TRUE
        .toString()
        .equalsIgnoreCase(
            ConfigurationHolderUtil.getString(
                    "databaseprotection.enableverify"));
  }

  /**
   * @return bool
   */
  public static boolean getCaKeepOcspExtendedService() {
    return Boolean.valueOf(
        ConfigurationHolderUtil.getString("ca.keepocspextendedservice")
            .toLowerCase());
  }

  /**
   * @return the number of rows that should be fetched at the time when creating
   *     CRLs.
   */
  public static int getDatabaseRevokedCertInfoFetchSize() {
    return Long.valueOf(
            getLongValue("database.crlgenfetchsize",  DEFAULT_FETCH, "rows"))
        .intValue();
  }

  /**
   * Characters forbidden in fields to be stored in the DB.
   *
   * @return all forbidden characters.
   */
  public static char[] getForbiddenCharacters() {
    // Using 'instance().getString' instead of 'getString' since an empty
    // String (size 0) must be returned when the property is defined without
    // any value.
    final String s =
        ConfigurationHolderUtil.instance().getString(FORBIDDEN_CARACTERS_KEY);
    if (s == null) {
      return ConfigurationHolderUtil.getDefaultValue(FORBIDDEN_CARACTERS_KEY)
          .toCharArray();
    }
    return s.toCharArray();
  }

  /**
   * @return true if sign mechanisms that uses pkcs#11 for hashing should be
   *     disabled.
   */
  public static boolean p11disableHashingSignMechanisms() {
    final String value =
        ConfigurationHolderUtil.getString(
                "pkcs11.disableHashingSignMechanisms");
    return value == null || Boolean.parseBoolean(value.trim());
  }

  /** @return true key store content of Crypto Tokens should be cached. */
  public static boolean isKeyStoreCacheEnabled() {
    return Boolean.parseBoolean(
        ConfigurationHolderUtil.getString("cryptotoken.keystorecache"));
  }

  /** Java 6: http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
   *  TLS versions: SSLv3, TLSv1, SSLv2Hello
   * Java 7: http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
   *  TLS versions: SSLv3, TLSv1, TLSv1.1, TLSv1.2
   *  Cipher suites with SHA384 and SHA256 are available only for TLS 1.2 or later.
   * Java 8: http://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
   *  TLS versions: SSLv3, TLSv1, TLSv1.1, TLSv1.2
   *  Cipher suites with SHA384 and SHA256 are available only for TLS 1.2 or later.
   *  @return a list of enabled TLS protocol versions and cipher suites */
  public static String[] getAvailableCipherSuites() {
    final List<String> availableCipherSuites = new ArrayList<String>();
    for (int i = 0; i < MAX_SUITES; i++) {
      final String key = "authkeybind.ciphersuite." + i;
      final String value = ConfigurationHolderUtil.getString(key);
      if (value == null
          || value.indexOf(AVAILABLE_CIPHER_SUITES_SPLIT_CHAR) == -1) {
        continue;
      }
      availableCipherSuites.add(value);
    }
    return availableCipherSuites.toArray(new String[0]);
  }

  /**
   * Gets the maximum number of entries in the CT cache. Each entry contains the
   * SCTs for a given certificate. Each SCT will be around 100-150 bytes, and a
   * certificate will typically have 2-4 SCTs. Also, the cache may temporarily
   * overshoot by 50%. There's also some overhead for the cache data structure
   * (ConcurrentCache).
   *
   * <p>-1 means no limit (and not "off"). The default is 100 000.
   *
   * @return max entries
   * @see #getCTCacheEnabled
   */
  public static long getCTCacheMaxEntries() {
    return getLongValue(
        "ct.cache.maxentries", HUNDRED_SECONDS, "number of entries in cache");
  }

  /**
   * @return How many milliseconds between periodic cache cleanup. The cleanup
   *     routine is only run when the cache is filled with too many entries.
   */
  public static long getCTCacheCleanupInterval() {
    return getLongValue(
        "ct.cache.cleanupinterval",
        TEN_SECONDS,
        "milliseconds between periodic cache cleanup");
  }

  /** @return Whether caching of SCTs should be enabled. The default is true. */
  public static boolean getCTCacheEnabled() {
    final String value = ConfigurationHolderUtil.getString("ct.cache.enabled");
    return value == null || !value.trim().equalsIgnoreCase("false");
  }

  /**
   * @return Whether log availability should be tracked, and requests should
   *     "fast fail" whenever a log is known to be down. A log is "known to be
   *     down" when it is either unreachable or responds with an HTTP error
   *     status to a request.
   */
  public static boolean getCTFastFailEnabled() {
    final String value = ConfigurationHolderUtil.getString(
            "ct.fastfail.enabled");
    return value != null && value.trim().equalsIgnoreCase(TRUE);
  }

  /**
   * @return How long time (in milliseconds) EJBCA should wait until trying to
   *     use a log which has failed to respond to a request.
   */
  public static long getCTFastFailBackOff() {
    return getLongValue("ct.fastfail.backoff", MS_PER_S, "milliseconds");
  }

  /** @return true if key should be unmodifiable after generation. */
  public static boolean makeKeyUnmodifiableAfterGeneration() {
    final String value =
        ConfigurationHolderUtil.getString(
            "pkcs11.makeKeyUnmodifiableAfterGeneration");
    return value != null && Boolean.parseBoolean(value.trim());
  }
}
