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

package org.cesecore.certificates.ca.internal;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;

/**
 * A cache for storing CA certificates.
 *
 * @version $Id: CaCertificateCache.java 27419 2017-12-05 13:18:18Z anatom $
 */
public enum CaCertificateCache {
  /** Singleton instance. */
  INSTANCE;

    /** Logger. */
  private final Logger log = Logger.getLogger(CaCertificateCache.class);

  /** Mapping from subjectDN to key in the certs HashMap. */
  private Map<Integer, X509Certificate> certsFromSubjectDN =
      new HashMap<Integer, X509Certificate>();
  /** Mapping from issuerDN to key in the certs HashMap. */
  private Map<Integer, Set<X509Certificate>> certsFromIssuerDN =
      new HashMap<Integer, Set<X509Certificate>>();
  /** Mapping from subject key identifier to key in the certs HashMap. */
  private Map<Integer, X509Certificate> certsFromSubjectKeyIdentifier =
      new HashMap<Integer, X509Certificate>();
  /** All root certificates. */
  private Set<X509Certificate> rootCertificates =
      new HashSet<X509Certificate>();

  /** Cache time counter, set and used by loadCertificates. */
  private long certValidTo = 0;
  /**
   *
   * @param id ID
   * @return Cert
   */
  public X509Certificate findLatestBySubjectDN(final HashID id) {
    final X509Certificate ret = certsFromSubjectDN.get(id.getKey());
    if (ret == null && log.isDebugEnabled()) {
      log.debug(
          "Certificate not found from SubjectDN HashId in certsFromSubjectDN"
              + " map. HashID="
              + id.getB64());
    }
    return ret;
  }

  /** @param id ID
 * @return cert */
  public X509Certificate[] findLatestByIssuerDN(final HashID id) {
    final Set<X509Certificate> sCert = certsFromIssuerDN.get(id.getKey());
    if (sCert == null || sCert.isEmpty()) {
      if (log.isDebugEnabled()) {
        log.debug(
            "Certificate not found from IssuerDN HashId in certsFromIssuerDN"
                + " map. HashID="
                + id.getB64());
      }
      return null;
    }
    return sCert.toArray(new X509Certificate[sCert.size()]);
  }

  /** @return root certs */
  public X509Certificate[] getRootCertificates() {
    return rootCertificates.toArray(new X509Certificate[0]);
  }

  /**
   *  @param id ID
 * @return cert */
  public X509Certificate findBySubjectKeyIdentifier(final HashID id) {
    final X509Certificate ret = certsFromSubjectKeyIdentifier.get(id.getKey());
    if (ret == null && log.isDebugEnabled()) {
      log.debug(
          "Certificate not found from SubjectKeyIdentifier HashId in"
              + " certsFromSubjectKeyIdentifier map. HashID="
              + id.getB64());
    }
    return ret;
  }

  /** @return true if cache has expired */
  public boolean isCacheExpired() {
    return certValidTo < System.currentTimeMillis();
  }

  /**
   * Loads CA certificates but holds a cache so it's reloaded only every five
   * minutes (configurable).
   *
   * <p>We keep this method as synchronized, it should not take more than a few
   * microseconds to complete if the cache does not have to be reloaded. If the
   * cache must be reloaded, we must wait for it anyway to not have
   * ConcurrentModificationException. We also only want one single thread to do
   * the rebuilding.
   *
   * @param certs Certificates
   */
  public synchronized void loadCertificates(
      final Collection<Certificate> certs) {
    if (log.isDebugEnabled()) {
      log.debug(
          "Loaded "
              + (certs == null ? "0" : Integer.toString(certs.size()))
              + " ca certificates");
    }

    Map<Integer, X509Certificate> newCertsFromSubjectDN =
        new HashMap<Integer, X509Certificate>();
    Map<Integer, Set<X509Certificate>> newCertsFromIssuerDN =
        new HashMap<Integer, Set<X509Certificate>>();
    Map<Integer, X509Certificate> newCertsFromSubjectKeyIdentifier =
        new HashMap<Integer, X509Certificate>();
    Set<X509Certificate> newRootCertificates = new HashSet<X509Certificate>();
    for (final Certificate tmp : certs) {
      if (!(tmp instanceof X509Certificate)) {
        log.debug("Not adding CA certificate of type: " + tmp.getType());
        continue;
      }
      final X509Certificate cert = (X509Certificate) tmp;
      try { // test if certificate is OK. we have experienced that BC could
            // decode a certificate that later on could not be used.
        handlePastCert(newCertsFromSubjectKeyIdentifier, cert);
      } catch (
          Throwable t) { // NOPMD: catch all to not break with an error here.
        logCertError(cert);
        continue;
      }
      final Integer subjectDNKey = HashID.getFromSubjectDN(cert).getKey();
      // Check if we already have a certificate from this issuer in the HashMap.
      // We only want to store the latest cert from each issuer in this map
      final X509Certificate pastCert = newCertsFromSubjectDN.get(subjectDNKey);
      final boolean isLatest;
      if (pastCert != null) {
        if (CertTools.getNotBefore(cert)
            .after(CertTools.getNotBefore(pastCert))) {
          isLatest = true;
        } else {
          isLatest = false;
        }
      } else {
        isLatest = true;
      }
      if (isLatest) {
        handleLatest(newCertsFromSubjectDN, newCertsFromIssuerDN,
                newRootCertificates, cert, subjectDNKey, pastCert);
      }
    }
    // Log what we have stored in the cache
    logDebugCache(newCertsFromSubjectKeyIdentifier);
    // Replace the old caches
    certsFromSubjectKeyIdentifier = newCertsFromSubjectKeyIdentifier;
    certsFromIssuerDN = newCertsFromIssuerDN;
    certsFromSubjectDN = newCertsFromSubjectDN;
    rootCertificates = newRootCertificates;
    certValidTo =
        System.currentTimeMillis()
            + OcspConfiguration.getSigningCertsValidTimeInMilliseconds();
  }

/**
 * @param newCertsFromSubjectKeyIdentifier certs
 */
private void logDebugCache(
        final Map<Integer, X509Certificate> newCertsFromSubjectKeyIdentifier) {
    if (log.isDebugEnabled()) {
      final StringWriter sw = new StringWriter();
      final PrintWriter pw = new PrintWriter(sw, true);
      pw.println("Found the following CA certificates :");
      for (Entry<Integer, X509Certificate> key
          : newCertsFromSubjectKeyIdentifier.entrySet()) {
        final Certificate cert = key.getValue();
        pw.print(CertTools.getSubjectDN(cert));
        pw.print(',');
        pw.println(CertTools.getSerialNumberAsString(cert));
      }
      log.debug(sw);
    }
}

/**
 * @param newCertsFromSubjectKeyIdentifier Map
 * @param cert Cert
 */
private void handlePastCert(
        final Map<Integer, X509Certificate> newCertsFromSubjectKeyIdentifier,
        final X509Certificate cert) {
    final Integer key = HashID.getFromKeyID(cert).getKey();
    final X509Certificate pastCert =
        newCertsFromSubjectKeyIdentifier.get(key);
    // Add the entry if it's the first, or if it is more recent than the one
    // existing (in that case replace it)
    if (pastCert == null
        || pastCert != null
            && CertTools.getNotBefore(cert)
                .after(CertTools.getNotBefore(pastCert))) {
      newCertsFromSubjectKeyIdentifier.put(key, cert);
    }
}

/**
 * @param newCertsFromSubjectDN Map
 * @param newCertsFromIssuerDN Map
 * @param newRootCertificates Map
 * @param cert Cert
 * @param subjectDNKey Key
 * @param pastCert Cert
 */
private void handleLatest(
        final Map<Integer, X509Certificate> newCertsFromSubjectDN,
        final Map<Integer, Set<X509Certificate>> newCertsFromIssuerDN,
        final Set<X509Certificate> newRootCertificates,
        final X509Certificate cert, final Integer subjectDNKey,
        final X509Certificate pastCert) {
    newCertsFromSubjectDN.put(subjectDNKey, cert);
    final Integer issuerDNKey = HashID.getFromIssuerDN(cert).getKey();
    if (!issuerDNKey.equals(
        subjectDNKey)) { // don't add roots to themselves
      Set<X509Certificate> sIssuer = newCertsFromIssuerDN.get(issuerDNKey);
      if (sIssuer == null) {
        sIssuer = new HashSet<X509Certificate>();
        newCertsFromIssuerDN.put(issuerDNKey, sIssuer);
      }
      sIssuer.add(cert);
      sIssuer.remove(pastCert);
    } else {
      newRootCertificates.add(cert);
      newRootCertificates.remove(pastCert);
    }
}

/**
 * @param cert cert
 */
private void logCertError(final X509Certificate cert) {
    if (log.isDebugEnabled()) {
      final StringWriter sw = new StringWriter();
      final PrintWriter pw = new PrintWriter(sw);
      pw.println("Erroneous certificate fetched from database.");
      pw.println(
          "The public key can not be extracted from the certificate.");
      pw.println("Here follows a base64 encoding of the certificate:");
      try {
        final String b64encoded =
            new String(Base64Util.encode(cert.getEncoded()));
        pw.println(CertTools.BEGIN_CERTIFICATE);
        pw.println(b64encoded);
        pw.println(CertTools.END_CERTIFICATE);
      } catch (CertificateEncodingException e) {
        pw.println("Not possible to encode certificate.");
      }
      pw.flush();
      log.debug(sw.toString());
    }
}
}
