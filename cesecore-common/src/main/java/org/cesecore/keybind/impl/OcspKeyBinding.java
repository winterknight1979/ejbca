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
package org.cesecore.keybind.impl;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingBase;
import org.cesecore.util.CertTools;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Holder of "external" (e.g. non-CA signing key) OCSP InternalKeyBinding
 * properties.
 *
 * @version $Id: OcspKeyBinding.java 25867 2017-05-17 16:18:06Z mikekushner $
 */
public class OcspKeyBinding extends InternalKeyBindingBase {

  private static final long serialVersionUID = 1L;
/** Logger. */
  private static final Logger LOG = Logger.getLogger(OcspKeyBinding.class);

  public enum ResponderIdType {
      /** Hash. */
    KEYHASH(2, "KeyHash"),
    /** Name. */
    NAME(1, "Name");

      /** Value. */
    private final int numericValue;
    /** Label. */
    private final String label;
    /** Map. */
    private static Map<Integer, ResponderIdType> numericValueLookupMap;

    static {
      numericValueLookupMap = new HashMap<>();
      for (ResponderIdType responderIdType : ResponderIdType.values()) {
        numericValueLookupMap.put(
            responderIdType.getNumericValue(), responderIdType);
      }
    }

    /**         *
     * @param aNumericValue typw
     * @param aLabel label
     */
    ResponderIdType(final int aNumericValue, final String aLabel) {
      this.numericValue = aNumericValue;
      this.label = aLabel;
    }

    /**
     * @return value
     */
    public int getNumericValue() {
      return numericValue;
    }

    /**
     * @return label
     */
    public String getLabel() {
      return label;
    }

    /**
     * @param numericValue value
     * @return type
     */
    public static ResponderIdType getFromNumericValue(final int numericValue) {
      return numericValueLookupMap.get(Integer.valueOf(numericValue));
    }
  }

  /** Alias. */
  public static final String IMPLEMENTATION_ALIAS =
      "OcspKeyBinding"; // This should not change, even if we rename the class
                        // in EJBCA 5.3+..
  /** Good. */
  public static final String PROPERTY_NON_EXISTING_GOOD = "nonexistingisgood";
 /** Revoked. */
  public static final String PROPERTY_NON_EXISTING_REVOKED =
      "nonexistingisrevoked";
  /** Unauth. */
  public static final String PROPERTY_NON_EXISTING_UNAUTHORIZED =
      "nonexistingisunauthorized";
  /** Chain. */
  public static final String PROPERTY_INCLUDE_CERT_CHAIN = "includecertchain";
  /** Cert. */
  public static final String PROPERTY_INCLUDE_SIGN_CERT = "includesigncert";
  /** Type. */
  public static final String PROPERTY_RESPONDER_ID_TYPE =
      "responderidtype"; // keyhash, name
  /** Sig. */
  public static final String PROPERTY_REQUIRE_TRUSTED_SIGNATURE =
      "requireTrustedSignature";
  /** time. */
  public static final String PROPERTY_UNTIL_NEXT_UPDATE = "untilNextUpdate";
  /** Age. */
  public static final String PROPERTY_MAX_AGE = "maxAge";
  /** Nonce. */
  public static final String PROPERTY_ENABLE_NONCE = "enableNonce";

  /** Constructor. */
   public OcspKeyBinding() {
    super();
    addProperty(
        new DynamicUiProperty<Boolean>(
            PROPERTY_NON_EXISTING_GOOD, Boolean.FALSE));
    addProperty(
        new DynamicUiProperty<Boolean>(
            PROPERTY_NON_EXISTING_REVOKED, Boolean.FALSE));
    addProperty(
        new DynamicUiProperty<Boolean>(
            PROPERTY_NON_EXISTING_UNAUTHORIZED, Boolean.FALSE));
    addProperty(
        new DynamicUiProperty<Boolean>(
            PROPERTY_INCLUDE_CERT_CHAIN, Boolean.TRUE));
    addProperty(
        new DynamicUiProperty<Boolean>(
            PROPERTY_INCLUDE_SIGN_CERT, Boolean.TRUE));
    addProperty(
        new DynamicUiProperty<String>(
            PROPERTY_RESPONDER_ID_TYPE,
            ResponderIdType.KEYHASH.name(),
            Arrays.asList(
                ResponderIdType.KEYHASH.name(), ResponderIdType.NAME.name())));
    addProperty(
        new DynamicUiProperty<Boolean>(
            PROPERTY_REQUIRE_TRUSTED_SIGNATURE, Boolean.FALSE));
    addProperty(
        new DynamicUiProperty<Long>(
            PROPERTY_UNTIL_NEXT_UPDATE, Long.valueOf(0L)));
    addProperty(
        new DynamicUiProperty<Long>(PROPERTY_MAX_AGE, Long.valueOf(0L)));
    addProperty(
        new DynamicUiProperty<Boolean>(PROPERTY_ENABLE_NONCE, Boolean.TRUE));
  }

  @Override
  public String getImplementationAlias() {
    return IMPLEMENTATION_ALIAS;
  }

  @Override
  public float getLatestVersion() {
    return serialVersionUID;
  }

  @Override
  protected void upgrade(
          final float latestVersion, final float currentVersion) {
    // Nothing to do
  }

  @Override
  public void assertCertificateCompatability(
      final Certificate certificate,
      final AvailableExtendedKeyUsagesConfiguration ekuConfig)
      throws CertificateImportException {
    assertCertificateCompatabilityInternal(certificate, ekuConfig);
  }

  /**
   * @return bool
   */
  public boolean getNonExistingGood() {
    return (Boolean) getProperty(PROPERTY_NON_EXISTING_GOOD).getValue();
  }

  /**
   * @param nonExistingGood bool
   */
  public void setNonExistingGood(final boolean nonExistingGood) {
    setProperty(PROPERTY_NON_EXISTING_GOOD, Boolean.valueOf(nonExistingGood));
  }

  /**
   * @return bool
   */
  public boolean getNonExistingRevoked() {
    return (Boolean) getProperty(PROPERTY_NON_EXISTING_REVOKED).getValue();
  }

  /**
   * @param nonExistingRevoked bool
   */
  public void setNonExistingRevoked(final boolean nonExistingRevoked) {
    setProperty(
        PROPERTY_NON_EXISTING_REVOKED, Boolean.valueOf(nonExistingRevoked));
  }

  /**
   * @return bool
   */
  public boolean getNonExistingUnauthorized() {
    if (getProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED) == null) {
      setNonExistingUnauthorized(false);
    }
    return (Boolean) getProperty(PROPERTY_NON_EXISTING_UNAUTHORIZED).getValue();
  }

  /**
   * @param nonExistingUnauthorized bool
   */
  public void setNonExistingUnauthorized(
          final boolean nonExistingUnauthorized) {
    setProperty(
        PROPERTY_NON_EXISTING_UNAUTHORIZED,
        Boolean.valueOf(nonExistingUnauthorized));
  }

  /**
   * @return bool
   */
  public boolean getIncludeCertChain() {
    return (Boolean) getProperty(PROPERTY_INCLUDE_CERT_CHAIN).getValue();
  }

  /**
   * @param includeCertChain chain
   */
  public void setIncludeCertChain(final boolean includeCertChain) {
    setProperty(PROPERTY_INCLUDE_CERT_CHAIN, Boolean.valueOf(includeCertChain));
  }

  /**
   * @return bool
   */
  public boolean getIncludeSignCert() {
    return (Boolean) getProperty(PROPERTY_INCLUDE_SIGN_CERT).getValue();
  }

  /**
   * @param includeCertChain bool
   */
  public void setIncludeSignCert(final boolean includeCertChain) {
    setProperty(PROPERTY_INCLUDE_SIGN_CERT, Boolean.valueOf(includeCertChain));
  }

  /**
   * @return type
   */
  public ResponderIdType getResponderIdType() {
    return ResponderIdType.valueOf(
        (String) getProperty(PROPERTY_RESPONDER_ID_TYPE).getValue());
  }

  /**
   * @param responderIdType type
   */
  public void setResponderIdType(final ResponderIdType responderIdType) {
    setProperty(PROPERTY_RESPONDER_ID_TYPE, responderIdType.name());
  }

  /**
   * @return bool
   */
  public boolean getRequireTrustedSignature() {
    return (Boolean) getProperty(PROPERTY_REQUIRE_TRUSTED_SIGNATURE).getValue();
  }

  /**
   * @param requireTrustedSignature bool
   */
  public void setRequireTrustedSignature(
          final boolean requireTrustedSignature) {
    setProperty(
        PROPERTY_REQUIRE_TRUSTED_SIGNATURE,
        Boolean.valueOf(requireTrustedSignature));
  }
  /** @return the value in seconds (granularity defined in RFC 5019) */
  public long getUntilNextUpdate() {
    return (Long) getProperty(PROPERTY_UNTIL_NEXT_UPDATE).getValue();
  }
  /**
   * Set the value in seconds (granularity defined in RFC 5019).
   *
   * @param untilNextUpdate time
   */
  public void setUntilNextUpdate(final long untilNextUpdate) {
    setProperty(PROPERTY_UNTIL_NEXT_UPDATE, Long.valueOf(untilNextUpdate));
  }
  /** @return the value in seconds (granularity defined in RFC 5019) */
  public long getMaxAge() {
    return (Long) getProperty(PROPERTY_MAX_AGE).getValue();
  }
  /**
   * Set the value in seconds (granularity defined in RFC 5019).
   *
   * @param maxAge age
   */
  public void setMaxAge(final long maxAge) {
    setProperty(PROPERTY_MAX_AGE, Long.valueOf(maxAge));
  }

  /** @return true if NONCE's are to be used in replies */
  public boolean isNonceEnabled() {
    if (getProperty(PROPERTY_ENABLE_NONCE) == null) {
      setNonceEnabled(true);
    }
    return (Boolean) getProperty(PROPERTY_ENABLE_NONCE).getValue();
  }
  /** @param enabled as true of NONCE's are to be included in replies */
  public void setNonceEnabled(final boolean enabled) {
    setProperty(PROPERTY_ENABLE_NONCE, Boolean.valueOf(enabled));
  }

  /**
   * @param certificate Cert
   * @param ekuConfig Config
   * @return Bool
   */
  public static boolean isOcspSigningCertificate(
      final Certificate certificate,
      final AvailableExtendedKeyUsagesConfiguration ekuConfig) {
    try {
      assertCertificateCompatabilityInternal(certificate, ekuConfig);
    } catch (CertificateImportException e) {
      return false;
    }
    return true;
  }

  private static void assertCertificateCompatabilityInternal(
      final Certificate certificate,
      final AvailableExtendedKeyUsagesConfiguration ekuConfig)
      throws CertificateImportException {
    if (certificate == null) {
      throw new CertificateImportException("No certificate provided.");
    }
    if (!(certificate instanceof X509Certificate)) {
      throw new CertificateImportException(
          "Only X509 certificates are supported for OCSP.");
    }
    try {
      final X509Certificate x509Certificate = (X509Certificate) certificate;
      logDebug(x509Certificate);
      if (x509Certificate.getExtendedKeyUsage() == null) {
        throw new CertificateImportException(
            "No Extended Key Usage present in certificate.");
      }
      for (String extendedKeyUsage : x509Certificate.getExtendedKeyUsage()) {
        LOG.debug(
            "EKU: "
                + extendedKeyUsage
                + " ("
                + ekuConfig.getAllEKUOidsAndNames().get(extendedKeyUsage)
                + ")");
      }
      if (!x509Certificate
          .getExtendedKeyUsage()
          .contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
        throw new CertificateImportException(
            "Extended Key Usage 1.3.6.1.5.5.7.3.9 (EKU_PKIX_OCSPSIGNING) is"
                + " required.");
      }
      if (!x509Certificate.getKeyUsage()[0]
          && !x509Certificate.getKeyUsage()[1]) {
        throw new CertificateImportException(
            "Key Usage digitalSignature is required (nonRepudiation would also"
                + " be accepted).");
      }
    } catch (CertificateParsingException e) {
      throw new CertificateImportException(e.getMessage(), e);
    }
  }

/**
 * @param x509Certificate cert
 */
private static void logDebug(final X509Certificate x509Certificate) {
    if (LOG.isDebugEnabled()) {
        LOG.debug(
            "SubjectDN: "
                + CertTools.getSubjectDN(x509Certificate)
                + " IssuerDN: "
                + CertTools.getIssuerDN(x509Certificate));
        final boolean[] ku = x509Certificate.getKeyUsage();
        LOG.debug("Key usages: " + Arrays.toString(ku));
        if (ku != null) {
          LOG.debug(
              "Key usage (digitalSignature): "
                  + x509Certificate.getKeyUsage()[0]);
          LOG.debug(
              "Key usage (nonRepudiation):   "
                  + x509Certificate.getKeyUsage()[1]);
          LOG.debug(
              "Key usage (keyEncipherment):  "
                  + x509Certificate.getKeyUsage()[2]);
        }
      }
}
}
