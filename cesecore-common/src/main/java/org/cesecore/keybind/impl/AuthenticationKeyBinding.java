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
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingBase;
import org.cesecore.util.CertTools;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Used when this EJBCA instance authenticates to other instances.
 *
 * @version $Id: AuthenticationKeyBinding.java 26192 2017-08-02 07:59:40Z anatom
 *     $
 */
public class AuthenticationKeyBinding extends InternalKeyBindingBase {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AuthenticationKeyBinding.class);

  /** Alias. */
  public static final String IMPLEMENTATION_ALIAS =
      "AuthenticationKeyBinding"; // This should not change, even if we rename
                                  // the class in EJBCA 5.3+..
  /** Property name. */
  public static final String PROPERTY_PROTOCOL_AND_CIPHER_SUITE =
      "protocolAndCipherSuite";

  {
    final String[] cipherSuitesSubset =
        CesecoreConfiguration.getAvailableCipherSuites();
    addProperty(
        new DynamicUiProperty<String>(
            PROPERTY_PROTOCOL_AND_CIPHER_SUITE,
            cipherSuitesSubset[0],
            Arrays.asList(cipherSuitesSubset)));
  }

  /** @return an array of supported protocols named according to JSSE */
  public String[] getSupportedProtocols() {
    return getSelectedProtocolOrSuite(0);
  }

  /** @return an array of supported cipher suites named according to JSSE */
  public String[] getSupportedCipherTextSuites() {
    return getSelectedProtocolOrSuite(1);
  }

  private String[] getSelectedProtocolOrSuite(final int pos) {
    final String value =
        (String) getProperty(PROPERTY_PROTOCOL_AND_CIPHER_SUITE).getValue();
    final String[] values =
        value.split(CesecoreConfiguration.AVAILABLE_CIPHER_SUITES_SPLIT_CHAR);
    if (LOG.isDebugEnabled() && pos == 0) {
      LOG.debug(
          "Configured cipher suite for this AuthenticationKeyBinding: "
              + value);
    }
    if (values.length == 2) {
      return new String[] {values[pos]};
    }
    return new String[0];
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
  public void assertCertificateCompatability(
      final Certificate certificate,
      final AvailableExtendedKeyUsagesConfiguration ekuConfig)
      throws CertificateImportException {
    if (!isClientSSLCertificate(certificate, ekuConfig)) {
      throw new CertificateImportException(
          "Not a valid Client SSL authentication certificate.");
    }
  }

  @Override
  protected void upgrade(
          final float latestVersion, final float currentVersion) {
    // Nothing to do
  }

  /**
   * @param certificate Cert
   * @param ekuConfig Config
   * @return Bool
   */
  public static boolean isClientSSLCertificate(
      final Certificate certificate,
      final AvailableExtendedKeyUsagesConfiguration ekuConfig) {
    if (certificate == null) {
      LOG.debug("No certificate provided.");
      return false;
    }
    if (!(certificate instanceof X509Certificate)) {
      LOG.debug("Only X509 supported.");
      return false;
    }
    try {
      final X509Certificate x509Certificate = (X509Certificate) certificate;
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "SubjectDN: "
                + CertTools.getSubjectDN(x509Certificate)
                + " IssuerDN: "
                + CertTools.getIssuerDN(x509Certificate));
      }
      final boolean[] ku = x509Certificate.getKeyUsage();
      if (ku != null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Key usages: " + Arrays.toString(ku));
          LOG.debug("Key usage (digitalSignature): " + ku[0]);
          LOG.debug("Key usage (keyEncipherment): " + ku[2]);
        }
      } else {
        LOG.debug("No Key Usage to verify.");
        return false;
      }
      if (x509Certificate.getExtendedKeyUsage() == null) {
        LOG.debug("No EKU to verify.");
        return false;
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
          .contains(KeyPurposeId.id_kp_clientAuth.getId())) {
        LOG.debug(
            "Extended Key Usage 1.3.6.1.5.5.7.3.2 (EKU_PKIX_CLIENTAUTH) is"
                + " required.");
        return false;
      }
      // For TLS _client_ certificates you can actually be without KU
      // completely, but we take the safe route here and require
      // digitalSignature
      // for TLS _server_ certificates also keyEncipherment is required, but not
      // for client (it doesn't hurt it it's there for clients as well though)
      if (!ku[0]) {
        LOG.debug("Key usage digitalSignature is required.");
        return false;
      }
    } catch (CertificateParsingException e) {
      LOG.debug(e.getMessage());
      return false;
    }
    return true;
  }
}
