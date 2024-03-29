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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.util.CertTools;

/**
 * Parses configuration bundled in conf/ocsp.properties, both for the internal
 * and external OCSP responder.
 *
 * @version $Id: OcspConfiguration.java 28629 2018-04-04 11:32:55Z henriks $
 */
public final class OcspConfiguration { // NOPMD


/** Logger. */
  private static final Logger LOG = Logger.getLogger(OcspConfiguration.class);
 /** responder. */
  @Deprecated // Deprecated in 6.2.4, remains to allow migration from previous
              // versions
  public static final String DEFAULT_RESPONDER = "ocsp.defaultresponder";
  /** time. */
  public static final String SIGNING_CERTD_VALID_TIME =
      "ocsp.signingCertsValidTime";
  /** time. */
  public static final String REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME =
      "ocsp.reqsigncertrevcachetime";
  /** time. */
  public static final String SIGNING_TRUSTSTORE_VALID_TIME =
      "ocsp.signtrustvalidtime";
  /** sig. */
  public static final String SIGNATUREREQUIRED = "ocsp.signaturerequired";
  /** pwd. */
  public static final String CARD_PASSWORD = "ocsp.keys.cardPassword";
  /** url. */
  public static final String REKEYING_WSURL = "ocsp.rekeying.wsurl";
  /** bool. */
  public static final String WARNING_BEFORE_EXPERATION_TIME =
      "ocsp.warningBeforeExpirationTime";
  /** bool. */
  public static final String NON_EXISTING_IS_GOOD = "ocsp.nonexistingisgood";
  /** URI. */
  public static final String NON_EXISTING_IS_GOOD_URI =
      NON_EXISTING_IS_GOOD + ".uri.";
  /** bool. */
  public static final String NON_EXISTING_IS_BAD_URI =
      "ocsp.nonexistingisbad.uri.";
  /** bool. */
  public static final String NON_EXISTING_IS_REVOKED =
      "ocsp.nonexistingisrevoked";
  /** IRI. */
  public static final String NON_EXISTING_IS_REVOKED_URI =
      NON_EXISTING_IS_REVOKED + ".uri.";
  /** config. */
  public static final String NON_EXISTING_IS_UNAUTHORIZED =
      "ocsp.nonexistingisunauthorized";
  /** hosts. */
  public static final String REKEYING_TRIGGERING_HOSTS =
      "ocsp.rekeying.trigging.hosts";
  /** password. */
  public static final String REKEYING_TRIGGERING_PASSWORD =
      "ocsp.rekeying.trigging.password";
  /** time. */
  public static final String REKEYING_UPDATE_TIME_IN_SECONDS =
      "ocsp.rekeying.update.time.in.seconds";
  /** margin. */
  public static final String REKEYING_SAFETY_MARGIN_IN_SECONDS =
      "ocsp.rekeying.safety.margin.in.seconds";
  /** period. */
  public static final String EXPIREDCERT_RETENTIONPERIOD =
      "ocsp.expiredcert.retentionperiod";
  /** update. */
  public static final String UNTIL_NEXT_UPDATE = "ocsp.untilNextUpdate";
  /** update. */
  public static final String REVOKED_UNTIL_NEXT_UPDATE =
      "ocsp.revoked.untilNextUpdate";
  /** age. */
  public static final String MAX_AGE = "ocsp.maxAge";
  /** age. */
  public static final String REVOKED_MAX_AGE = "ocsp.revoked.maxAge";
  /** Vert. */
  public static final String INCLUDE_SIGNING_CERT = "ocsp.includesignercert";
  /** Chain. */
  public static final String INCLUDE_CERT_CHAIN = "ocsp.includecertchain";

  /** type. */
  @Deprecated // Remove this value once upgrading to 6.7.0 has been dropped
  public static final String RESPONDER_ID_TYPE = "ocsp.responderidtype";
  /** type. */
  @Deprecated // Remove this value once upgrading VAs to EJBCA 6 has been
              // dropped
  public static final int RESTRICTONISSUER = 0;
  /** type. */
  @Deprecated // Remove this value once upgrading VAs to EJBCA 6 has been
              // dropped
  public static final int RESTRICTONSIGNER = 1;
  /** type. */
  @Deprecated // Remove this value once upgrading to 6.7.0 has been dropped
  public static final int RESPONDERIDTYPE_NAME = 1;
  /** type. */
  @Deprecated // Remove this value once upgrading to 6.7.0 has been dropped
  public static final int RESPONDERIDTYPE_KEYHASH = 2;
  /** Algorithms. */
  private static Set<String> acceptedSignatureAlgorithms = new HashSet<>();

  /** 1 year in seconds. */
  private static final long DEFAULT_RETENTION = 365L * 24 * 3600;
  /** 30s. */
  private static final int HTTP_TIMEOUT = 30;
  /** milliseconds. */
  private static final long MS_PER_S = 1000L;

  private OcspConfiguration() { }

  /**
 * @return the acceptedSignatureAlgorithms
 */
  public static Set<String> getAcceptedSignatureAlgorithms() {
      return acceptedSignatureAlgorithms;
}

/**
 * @param aAcceptedSignatureAlgorithms the acceptedSignatureAlgorithms to set
 */
    public static void setAcceptedSignatureAlgorithms(
        final Set<String> aAcceptedSignatureAlgorithms) {
        OcspConfiguration.acceptedSignatureAlgorithms =
            aAcceptedSignatureAlgorithms;
}

/**
   * @return Algorithm used by server to generate signature on OCSP responses
   */
  public static String getSignatureAlgorithm() {
    return ConfigurationHolderUtil.getString("ocsp.signaturealgorithm");
  }

  /**
   * Returns if the specified signature algorithm is among the signature
   * algorithms accepted by EJBCA.
   *
   * <p>The signatures algorithms that are accepted by EJBCA are specified in
   * 'ocsp.signaturealgorithm' in the EJBCA_HOME/conf/ocsp.properties file.
   *
   * @param sigAlg Algorithm name
   * @return 'true' if sigAlg is accepted by EJBCA, and 'false' otherwise
   */
  public static boolean isAcceptedSignatureAlgorithm(final String sigAlg) {
    if (acceptedSignatureAlgorithms.size() == 0) {
      String[] algs = getSignatureAlgorithm().split(";");
      for (String alg : algs) {
        acceptedSignatureAlgorithms.add(alg);
      }
    }
    return acceptedSignatureAlgorithms.contains(sigAlg);
  }

  /**
   * acceptedSignatureAlgorithms are cached, so if we try to dynamically change
   * the value (for testing) we need to clear this cache so it is reloaded.
   */
  public static void clearAcceptedSignatureAlgorithmCache() {
    acceptedSignatureAlgorithms = new HashSet<>();
  }

  /**
   * @return How often the standalone OCSP certificate cache should be checked
   *     for expiring certificates. Default value i 1 hour
   */
  public static long getRekeyingUpdateTimeInSeconds() {
    return Long.parseLong(
        ConfigurationHolderUtil.getString(REKEYING_UPDATE_TIME_IN_SECONDS));
  }

  /**
   * @return How long from true expiry time that a certificate should be
   *     renewed. Default value is 1 day
   */
  public static long getRekeyingSafetyMarginInSeconds() {
    return Long.parseLong(
        ConfigurationHolderUtil.getString(REKEYING_SAFETY_MARGIN_IN_SECONDS));
  }

  /**
   * @return The interval on which new OCSP signing certificates are loaded in
   *     milliseconds
   */
  public static int getSigningCertsValidTimeInMilliseconds() {
    int timeInSeconds;
    final int defaultTimeInSeconds = 300; // 5 minutes
    try {
      timeInSeconds =
          Integer.parseInt(
              ConfigurationHolderUtil.getString(SIGNING_CERTD_VALID_TIME));
    } catch (NumberFormatException e) {
      timeInSeconds = defaultTimeInSeconds;
      LOG.warn(
          SIGNING_CERTD_VALID_TIME
              + " is not a decimal integer. Using default 5 minutes");
    }
    return timeInSeconds * (int) MS_PER_S;
  }

  /**
   * @return The interval on which new OCSP signing certificates are loaded in
   *     milliseconds
   */
  public static long getRequestSigningCertRevocationCacheTimeMs() {
    long timeInSeconds;
    final long defaultTimeInSeconds = 60 * 1000L; // 1 minute
    try {
      timeInSeconds =
          Long.parseLong(
              ConfigurationHolderUtil.getString(
                  REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME));
    } catch (NumberFormatException e) {
      timeInSeconds = defaultTimeInSeconds;
      LOG.warn(
          REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME
              + " is not a decimal long. Using default "
              + defaultTimeInSeconds
              + " ms.");
    }
    return timeInSeconds;
  }

  /** @return If set to true the responder will enforce OCSP request signing */
  public static boolean getEnforceRequestSigning() {
    String value = ConfigurationHolderUtil.getString(SIGNATUREREQUIRED);
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /** @return If set to true the responder will restrict OCSP request signing */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static boolean getRestrictSignatures() {
    String value = ConfigurationHolderUtil.getString("ocsp.restrictsignatures");
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * Set this to issuer or signer depending on how you want to restrict allowed
   * signatures for OCSP request signing.
   *
   * @return one of OcspConfiguration.RESTRICTONISSUER and
   *     OcspConfiguration.RESTRICTONSIGNER
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static int getRestrictSignaturesByMethod() {
    if ("signer"
        .equalsIgnoreCase(
        ConfigurationHolderUtil.getString("ocsp.restrictsignaturesbymethod"))) {
      return RESTRICTONSIGNER;
    }
    return RESTRICTONISSUER;
  }

  /**
   * @return If ocsp.restrictsignatures is true the Servlet will look in this
   *     directory for allowed signer certificates or issuers.
   */
  @Deprecated // Remove this value once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getSignTrustDir() {
    return ConfigurationHolderUtil.getString("ocsp.signtrustdir");
  }

  /**
   * @return If set to true the certificate chain will be returned with the OCSP
   *     response.
   */
  public static boolean getIncludeCertChain() {
    String value = ConfigurationHolderUtil.getString(INCLUDE_CERT_CHAIN);
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * @return If set to true the signature certificate will be included the OCSP
   *     response.
   */
  public static boolean getIncludeSignCert() {
    String value = ConfigurationHolderUtil.getString(INCLUDE_SIGNING_CERT);
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * If set to name the OCSP responses will use the Name ResponseId type, if set
   * to keyhash the KeyHash type will be used.
   *
   * @return one of OCSPUtil.RESPONDERIDTYPE_NAME and
   *     OCSPUtil.RESPONDERIDTYPE_KEYHASH
   * @deprecated no longer used, as responder ID type is instead set
   *     individually for each keybinding and CA
   */
  @Deprecated
  public static int getResponderIdType() {
    if ("name"
      .equalsIgnoreCase(ConfigurationHolderUtil.getString(RESPONDER_ID_TYPE))) {
      return RESPONDERIDTYPE_NAME;
    }
    return RESPONDERIDTYPE_KEYHASH;
  }

  /**
   * @return true if a certificate that does not exist in the database, but is
   *     issued by a CA the responder handles will be treated as not revoked.
   */
  public static boolean getNonExistingIsGood() {
    String value = ConfigurationHolderUtil.getString(NON_EXISTING_IS_GOOD);
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * @return true if a certificate that does not exist in the database, but is
   *     issued by a CA the responder handles will be treated as revoked.
   */
  public static boolean getNonExistingIsRevoked() {
    String value = ConfigurationHolderUtil.getString(NON_EXISTING_IS_REVOKED);
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * @return true if a certificate that does not exist in the database, but is
   *     issued by a CA the responder handles will be responded to with an
   *     unsigned "Unauthorized" response.
   */
  public static boolean getNonExistingIsUnauthorized() {
 String value = ConfigurationHolderUtil.getString(NON_EXISTING_IS_UNAUTHORIZED);
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  private static String getRegex(final String prefix) {
    int i = 1;
    final StringBuffer regex = new StringBuffer();
    while (true) {
      final String key = prefix + i;
      final String value = ConfigurationHolderUtil.getString(key);
      if (value == null) {
        break;
      }
      if (i > 1) {
        regex.append('|');
      }
      regex.append('(');
      regex.append(value);
      regex.append(')');
      i++;
    }
    if (regex.length() < 1) {
      return null;
    }
    return regex.toString();
  }

  /**
   * Calls from client fulfilling this regex returns good for non existing
   * certificates even if {@link #getNonExistingIsGood()} return false.
   *
   * @return the regex
   */
  public static String getNonExistingIsGoodOverideRegex() {
    return getRegex(NON_EXISTING_IS_GOOD_URI);
  }

  /**
   * Calls from client fulfilling this regex returns "not existing" for non
   * existing certificates even if {@link #getNonExistingIsGood()} return true.
   *
   * @return the regex
   */
  public static String getNonExistingIsBadOverideRegex() {
    return getRegex(NON_EXISTING_IS_BAD_URI);
  }

  /**
   * Calls from client fulfilling this regex returns "revoked" for non existing
   * certificates even if {@link #getNonExistingIsGood()} return true.
   *
   * @return the regex
   */
  public static String getNonExistingIsRevokedOverideRegex() {
    return getRegex(NON_EXISTING_IS_REVOKED_URI);
  }

  /**
   * Specifies the subject of a certificate which is used to identify the
   * responder which will generate responses when no real CA can be found from
   * the request. This is used to generate 'unknown' responses when a request is
   * received for a certificate that is not signed by any CA on this server.
   *
   * @return the name configured in ocsp.defaultresponder, reordered to EJBCA
   *     normalized ordering.
   * @deprecated This value is deprecated since 6.2.4, and only remains in order
   *     to allow migration. Default responder is now set in global
   *     configuration instead.
   */
  @Deprecated
  public static String getDefaultResponderId() {
    final String ret = ConfigurationHolderUtil.
            getExpandedString(DEFAULT_RESPONDER);
    if (ret != null) {
      return CertTools.stringToBCDNString(ret);
    }
    return ret;
  }

  /**
   * Specifies OCSP extension OIDs that will result in a call to an extension
   * class, separate multiple entries with ';'. For any entry that should be
   * always used, preface with '*' (e.g. *2.16.578.1.16.3.2)
   *
   * <p>Deprecated: May still be required for 6.12 upgrades
   *
   * @return a List&lt;String&gt; of extension OIDs, an empty list if none are
   *     found.
   */
  @Deprecated
  public static List<String> getExtensionOids() {
    String value = ConfigurationHolderUtil.getString("ocsp.extensionoid");
    if ("".equals(value)) {
      return new ArrayList<>();
    }
    return Arrays.asList(value.split(";"));
  }

  /**
   * Specifies classes implementing OCSP extensions matching OIDs in
   * getExtensionOid(), separate multiple entries with ';'.
   *
   * @deprecated since 6.12. May still be required for upgrades.
   * @return a List&lt;String&gt; of extension classes
   */
  @Deprecated
  public static List<String> getExtensionClasses() {
    String value = ConfigurationHolderUtil.getString("ocsp.extensionclass");
    if ("".equals(value)) {
      return new ArrayList<>();
    }
    return Arrays.asList(value.split(";"));
  }

  /**
   * Intended for debugging.
   *
   * @return OID of extension to always respond with, even if not requested.
   */
  public static String getAlwaysSendCustomOCSPExtension() {
    return ConfigurationHolderUtil.getString("ocsp.alwayssendcustomextension");
  }

  /**
   * @return Directory containing certificates of trusted entities allowed to
   *     query for Fnrs.
   * @deprecated since 6.12. May still be required for upgrades. CA+serial of
   *     trusted certificates are now stored in the database, in internal key
   *     bindings.
   */
  @Deprecated
  public static String getUnidTrustDir() {
    return ConfigurationHolderUtil.getString("ocsp.unidtrustdir");
  }

  /**
   * @return File containing the CA-certificate, in PEM format, that signed the
   *     trusted clients.
   * @deprecated since 6.12. May still be required for upgrades. CA+serial of
   *     trusted certificates are now stored in the database, in internal key
   *     bindings.
   */
  @Deprecated
  public static String getUnidCaCert() {
    return ConfigurationHolderUtil.getString("ocsp.unidcacert");
  }

  /** @return true if UnidFnr is enabled in ocsp.properties */
  public static boolean isUnidEnabled() {
    return ConfigurationHolderUtil.getString("unidfnr.enabled") != null
       && ConfigurationHolderUtil.getString("unidfnr.enabled").equals("true");
  }

  /** @return When true, an audit log will be created. */
  public static boolean getAuditLog() {
    String value = ConfigurationHolderUtil.getString("ocsp.audit-log");
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * @return A format string for logging of dates in auditLog and accountLog.
   */
  public static String getLogDateFormat() {
    return ConfigurationHolderUtil.getString("ocsp.log-date");
  }

  /** @return A format string for TimeZone auditLog and accountLog. */
  public static String getLogTimeZone() {
    return ConfigurationHolderUtil.getString("ocsp.log-timezone");
  }

  /**
   * @return Set to true if you want transactions to be aborted when logging
   *     fails.
   */
  public static boolean getLogSafer() {
    String value = ConfigurationHolderUtil.getString("ocsp.log-safer");
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /** @return A String to create a java Pattern to format the audit Log */
  public static String getAuditLogPattern() {
    return ConfigurationHolderUtil.getString("ocsp.audit-log-pattern");
  }

  /**
   * @return A String which combined with auditLogPattern determines how
   *     auditLog output is formatted.
   */
  public static String getAuditLogOrder() {
    String value = ConfigurationHolderUtil.getString("ocsp.audit-log-order");
    value =
        value.replace(
            "\\\"",
            "\""); // From EJBCA 3.9 the "-char does not need to be escaped, but
                   // we want to be backward compatible
    return value;
  }

  /** @return All available signing keys should be tested. */
  public static boolean getHealthCheckSignTest() {
    return ConfigurationHolderUtil.getString("ocsphealthcheck.signtest")
            .toLowerCase()
            .indexOf("false")
        < 0;
  }

  /**
   * @return true if the validity of the OCSP signing certificates should be
   *     tested by the healthcheck.
   */
  public static boolean getHealthCheckCertificateValidity() {
    return ConfigurationHolderUtil.getString(
                "ocsphealthcheck.checkSigningCertificateValidity")
            .toLowerCase()
            .indexOf("false")
        < 0;
  }

  /** @return When true, a transaction log will be created. */
  public static boolean getTransactionLog() {
    String value = ConfigurationHolderUtil.getString("ocsp.trx-log");
    return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
  }

  /**
   * @return A String to create a java Pattern to format the transaction Log.
   */
  public static String getTransactionLogPattern() {
    return ConfigurationHolderUtil.getString("ocsp.trx-log-pattern");
  }

  /**
   * @return A String which combined with transactionLogPattern determines how
   *     transaction Log output is formatted.
   */
  public static String getTransactionLogOrder() {
    String value = ConfigurationHolderUtil.getString("ocsp.trx-log-order");
    value =
        value.replace(
            "\\\"",
            "\""); // From EJBCA 3.9 the "-char does not need to be escaped, but
                   // we want to be backward compatible
    return value;
  }

  /**
   * @return The default number of milliseconds a response is valid, or -1 to
   *     disable. See RFC5019.
   */
  public static long getExpiredArchiveCutoff() {
    Configuration config = ConfigurationHolderUtil.instance();

    if (StringUtils.equals(
        config.getString(EXPIREDCERT_RETENTIONPERIOD), "-1")) {
      return -1;
    }

    long value = DEFAULT_RETENTION;
    try {
      value = config.getLong(EXPIREDCERT_RETENTIONPERIOD, value) * MS_PER_S;
    } catch (ConversionException e) {
      LOG.warn(
          "\"ocsp.expiredcert.retentionperiod\" is not a decimal integer."
              + " Using default value: "
              + value);
    }

    return value;
  }

  /**
   * @param certProfileId profile ID
   * @return The default number of milliseconds a response is valid, or 0 to
   *     disable. See RFC5019.
   */
  public static long getUntilNextUpdate(final int certProfileId) {
    long value = 0;
    Configuration config = ConfigurationHolderUtil.instance();
    String key = "ocsp." + certProfileId + ".untilNextUpdate";
    if (certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE
        || !config.containsKey(key)) {
      key = UNTIL_NEXT_UPDATE;
    }
    try {
      value = config.getLong(key, value) * MS_PER_S;
    } catch (ConversionException e) {
      LOG.warn(
          "\"ocsp.untilNextUpdate\" is not a decimal integer. Using default"
              + " value: "
              + value);
    }
    return value;
  }

  /**
   * @param certificateProfileId Profile ID
   * @return true if Until Next Update is explicitly configured for the
   *     requested certificate profile
   */
  public static boolean isUntilNextUpdateConfigured(
      final int certificateProfileId) {
    if (certificateProfileId
        == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
      return ConfigurationHolderUtil.instance().containsKey(UNTIL_NEXT_UPDATE);
    } else {
      return ConfigurationHolderUtil.instance()
          .containsKey("ocsp." + certificateProfileId + ".untilNextUpdate");
    }
  }

  /**
   * @param certProfileId profile ID
   * @return The default number of milliseconds a response of a revoked
   *     certificate is valid, or 0 to disable. See RFC5019.
   */
  public static long getRevokedUntilNextUpdate(final int certProfileId) {
    long value = 0;
    Configuration config = ConfigurationHolderUtil.instance();
    String key = "ocsp." + certProfileId + ".revoked.untilNextUpdate";
    if (certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE
        || !config.containsKey(key)) {
      key = REVOKED_UNTIL_NEXT_UPDATE;
    }
    try {
      value = config.getLong(key, value) * MS_PER_S;
    } catch (ConversionException e) {
      LOG.warn(
          "\"ocsp.revoked.untilNextUpdate\" is not a decimal integer. Using"
              + " default value: "
              + value);
    }
    return value;
  }

  /**
   * @param certificateProfileId Profile ID
   * @return true if Until Next Update is explicitly configured for the
   *     requested certificate profile in case of a revoked certificate
   */
  public static boolean isRevokedUntilNextUpdateConfigured(
      final int certificateProfileId) {
    if (certificateProfileId
        == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
      return ConfigurationHolderUtil.instance()
          .containsKey(REVOKED_UNTIL_NEXT_UPDATE);
    } else {
      return ConfigurationHolderUtil.instance()
          .containsKey(
              "ocsp." + certificateProfileId + ".revoked.untilNextUpdate");
    }
  }

  /**
   * @param certProfileId profile ID
   * @return The default number of milliseconds a HTTP-response should be
   *     cached. See RFC5019.
   */
  public static long getMaxAge(final int certProfileId) {
    long value = HTTP_TIMEOUT;
    Configuration config = ConfigurationHolderUtil.instance();
    String key = "ocsp." + certProfileId + ".maxAge";
    if (certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE
        || !config.containsKey(key)) {
      key = MAX_AGE;
    }
    try {
      value = config.getLong(key, value) * MS_PER_S;
    } catch (ConversionException e) {
      // Convert default value to milliseconds
      value = value * MS_PER_S;
      LOG.warn(
          "\"ocsp.maxAge\" is not a decimal integer. Using default value: "
              + value);
    }
    return value;
  }

  /**
   * @param certificateProfileId Profile ID
   * @return true if Until Next Update is explicitly configured for the
   *     requested certificate profile
   */
  public static boolean isMaxAgeConfigured(final int certificateProfileId) {
    if (certificateProfileId
        == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
      return ConfigurationHolderUtil.instance().containsKey(MAX_AGE);
    } else {
      return ConfigurationHolderUtil.instance()
          .containsKey("ocsp." + certificateProfileId + ".maxAge");
    }
  }

  /**
   * @param certProfileId Profile ID
   * @return The default number of milliseconds a HTTP-response for a revoked
   *     certificater should be cached. See RFC5019.
   */
  public static long getRevokedMaxAge(final int certProfileId) {
    long value = HTTP_TIMEOUT;
    Configuration config = ConfigurationHolderUtil.instance();
    String key = "ocsp." + certProfileId + ".revoked.maxAge";
    if (certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE
        || !config.containsKey(key)) {
      key = REVOKED_MAX_AGE;
    }
    try {
      value = config.getLong(key, value) * MS_PER_S;
    } catch (ConversionException e) {
      // Convert default value to milliseconds
      value = value * MS_PER_S;
      LOG.warn(
          "\"ocsp.revoked.maxAge\" is not a decimal integer. Using default"
              + " value: "
              + value);
    }
    return value;
  }

  /**
   * @param certificateProfileId Profile ID
   * @return true if Until Next Update is explicitly configured for the
   *     requested certificate profile in case of a revoked certificate
   */
  public static boolean isRevokedMaxAgeConfigured(
      final int certificateProfileId) {
    if (certificateProfileId
        == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
      return ConfigurationHolderUtil.instance().containsKey(REVOKED_MAX_AGE);
    } else {
      return ConfigurationHolderUtil.instance()
          .containsKey("ocsp." + certificateProfileId + ".revoked.maxAge");
    }
  }

  // Values for stand-alone OCSP

  /**
   * @return Directory name of the soft keystores. The signing keys will be
   *     fetched from all files in this directory. Valid formats of the files
   *     are JKS and PKCS12 (p12)."
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getSoftKeyDirectoryName() {
    return ConfigurationHolderUtil.getString("ocsp.keys.dir");
  }

  /**
   * The password for the all the soft keys of the OCSP responder.
   *
   * @return {@link #getStorePassword()} if property isn't set.
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getKeyPassword() {
    final String value = ConfigurationHolderUtil.
            getString("ocsp.keys.keyPassword");
    if (value != null) {
      return value;
    }
    return getStorePassword();
  }

  /**
   * The password to all soft keystores.
   *
   * @return the value of getKeyPassword() if property isn't set.
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getStorePassword() {
    return ConfigurationHolderUtil.getString("ocsp.keys.storePassword");
  }

  /** @return The password for all keys stored on card. */
  public static String getCardPassword() {
    return ConfigurationHolderUtil.getString(CARD_PASSWORD);
  }

  /** @return The class that implements card signing of the OCSP response. */
  public static String getHardTokenClassName() {
    return ConfigurationHolderUtil.getString("ocsp.hardToken.className");
  }

  /** @return Sun P11 configuration file name. */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getSunP11ConfigurationFile() {
    return ConfigurationHolderUtil.getString("ocsp.p11.sunConfigurationFile");
  }

  /**
   * Get set of host IPs that are allowed to trigger rekeying.
   *
   * @return the array
   */
  public static Set<String> getRekeyingTriggingHosts() {
    final String sHosts =
        ConfigurationHolderUtil.getString(REKEYING_TRIGGERING_HOSTS);
    if (sHosts == null) {
      return new HashSet<>();
    } else {
      return new HashSet<>(
          Arrays.asList(StringUtils.split(sHosts.trim(), ';')));
    }
  }
  /**
   * Get password needed for triggering rekey. Null means that it is not
   * possible to trigger rekey.
   *
   * @return the password
   */
  public static String getRekeyingTriggingPassword() {
    return ConfigurationHolderUtil.getString(REKEYING_TRIGGERING_PASSWORD);
  }

  /** @return EJBCA web service URL */
  public static String getEjbcawsracliUrl() {
    return ConfigurationHolderUtil.getString(REKEYING_WSURL);
  }

  /**
   * P11 shared library path name.
   *
   * @return The value;
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getP11SharedLibrary() {
    return ConfigurationHolderUtil.getString("ocsp.p11.sharedLibrary");
  }

  /**
   * P11 password.
   *
   * @return The value
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getP11Password() {
    return ConfigurationHolderUtil.getString("ocsp.p11.p11password");
  }

  /**
   * P11 slot number.
   *
   * @return The value.
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static String getP11SlotIndex() {
    return ConfigurationHolderUtil.getString("ocsp.p11.slot");
  }

  /**
   * Should passwords be stored in memory.
   *
   * <p>Default value is true.
   *
   * @return True if password should not be stored in memory.
   */
  @Deprecated // Remove this method once upgrading VAs to EJBCA 6 has been
              // dropped
  public static boolean getDoNotStorePasswordsInMemory() {
    final String s =
        ConfigurationHolderUtil.getString(
            "ocsp.activation.doNotStorePasswordsInMemory");
    return !(s == null
        || s.toLowerCase().indexOf("false") >= 0
        || s.toLowerCase().indexOf("no") >= 0);
  }

  /**
   * @return The interval on which new OCSP signing certificates are loaded in
   *     seconds
   */
  public static long getWarningBeforeExpirationTime() {
    int timeInSeconds = 0;
    final int defaultTimeInSeconds = 604800; // 1 week 60*60*24*7
    try {
      String configValue =
          ConfigurationHolderUtil.getString(WARNING_BEFORE_EXPERATION_TIME);
      if (configValue != null) {
        timeInSeconds = Integer.parseInt(configValue);
      } else {
        timeInSeconds = defaultTimeInSeconds;
      }

    } catch (NumberFormatException e) {
      timeInSeconds = defaultTimeInSeconds;
      LOG.warn(
          WARNING_BEFORE_EXPERATION_TIME
              + " is not a decimal integer. Using default 1 week.");
    }
    return MS_PER_S * (long) timeInSeconds;
  }

}
