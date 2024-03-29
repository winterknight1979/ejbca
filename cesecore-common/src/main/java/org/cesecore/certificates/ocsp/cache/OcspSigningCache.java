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
package org.cesecore.certificates.ocsp.cache;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.util.CertTools;

/**
 * Hold information needed to create OCSP responses without database lookups.
 *
 * @version $Id: OcspSigningCache.java 28643 2018-04-06 08:53:57Z samuellb $
 */
public enum OcspSigningCache {
    /** Singleton instance. */
  INSTANCE;

    /** Cache. */
  private Map<Integer, OcspSigningCacheEntry> cache =
      new HashMap<Integer, OcspSigningCacheEntry>();
  /** Staging. */
  private Map<Integer, OcspSigningCacheEntry> staging =
      new HashMap<Integer, OcspSigningCacheEntry>();
  /** Default. */
  private OcspSigningCacheEntry defaultResponderCacheEntry = null;
  /** Lock. */
  private final ReentrantLock lock = new ReentrantLock(false);
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(OcspSigningCache.class);
  /** Flag to detect and log non-existence of a default responder once. */
  private boolean logDefaultHasRunOnce = false;

  /**
   * @param certID ID
   * @return Entry
   */
  public OcspSigningCacheEntry getEntry(final CertificateID certID) {
    return cache.get(getCacheIdFromCertificateID(certID));
  }

  /**
   * @return the entry corresponding to the default responder, or null if it
   *     wasn't found.
   */
  public OcspSigningCacheEntry getDefaultEntry() {
    return defaultResponderCacheEntry;
  }

  /**
   * WARNING: This method potentially exports references to CAs private keys!
   *
   * @return entries
   */
  public Collection<OcspSigningCacheEntry> getEntries() {
    return cache.values();
  }

  /** Start. */
  public void stagingStart() {
    lock.lock();
    staging = new HashMap<Integer, OcspSigningCacheEntry>();
  }

  /**
   * @param ocspSigningCacheEntry Entry
   */
  public void stagingAdd(final OcspSigningCacheEntry ocspSigningCacheEntry) {
    List<CertificateID> certIDs = ocspSigningCacheEntry.getCertificateID();
    for (CertificateID certID : certIDs) {
      staging.put(getCacheIdFromCertificateID(certID), ocspSigningCacheEntry);
    }
  }

  /**
   * @param defaultResponderSubjectDn DN
   */
  public void stagingCommit(final String defaultResponderSubjectDn) {
    OcspSigningCacheEntry lDefaultResponderCacheEntry =
            getDefaultEntry(defaultResponderSubjectDn);
    // Lastly, walk through the list of entries and replace all placeholders
    // with the default responder
    Map<Integer, OcspSigningCacheEntry> modifiedEntries =
        new HashMap<Integer, OcspSigningCacheEntry>();
    List<Integer> removedEntries = new ArrayList<Integer>();
    for (Integer key : staging.keySet()) {
      OcspSigningCacheEntry entry = staging.get(key);
      // If entry has been created without a private key, replace it with the
      // default responder.
      if (entry.isPlaceholder()) {
        if (lDefaultResponderCacheEntry != null) {
          entry =
              new OcspSigningCacheEntry(
                  entry.getIssuerCaCertificate(),
                  entry.getIssuerCaCertificateStatus(),
                  lDefaultResponderCacheEntry.getCaCertificateChain(),
                  lDefaultResponderCacheEntry.getOcspSigningCertificate(),
                  lDefaultResponderCacheEntry.getPrivateKey(),
                  lDefaultResponderCacheEntry.getSignatureProviderName(),
                  lDefaultResponderCacheEntry.getOcspKeyBinding(),
                  lDefaultResponderCacheEntry.getResponderIdType());
          modifiedEntries.put(key, entry);
        } else {
          // If no default responder is defined, remove placeholder.
          removedEntries.add(key);
        }
      }
    }
    staging.putAll(modifiedEntries);
    for (Integer removedKey : removedEntries) {
      staging.remove(removedKey);
    }
    logDefaultResponderChanges(
        this.defaultResponderCacheEntry,
        lDefaultResponderCacheEntry,
        defaultResponderSubjectDn);
    cache = staging;
    this.defaultResponderCacheEntry = lDefaultResponderCacheEntry;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Committing the following to OCSP cache:");
      for (final Integer key : staging.keySet()) {
        final OcspSigningCacheEntry entry = staging.get(key);
        LOG.debug(
            " KeyBindingId: "
                + key
                + ", SubjectDN '"
                + CertTools.getSubjectDN(entry.getFullCertificateChain().get(0))
                + "', IssuerDN '"
                + CertTools.getIssuerDN(entry.getFullCertificateChain().get(0))
                + "', SerialNumber "
                + entry
                    .getFullCertificateChain()
                    .get(0)
                    .getSerialNumber()
                    .toString()
                + "/"
                + entry
                    .getFullCertificateChain()
                    .get(0)
                    .getSerialNumber()
                    .toString(16));
        if (entry.getOcspKeyBinding() != null) {
          LOG.debug(
              "   keyPairAlias: "
                  + entry.getOcspKeyBinding().getKeyPairAlias());
        }
      }
    }
  }

/**
 * @param defaultResponderSubjectDn DM
 * @return Entry
 */
private OcspSigningCacheEntry getDefaultEntry(
        final String defaultResponderSubjectDn) {
    OcspSigningCacheEntry lDefaultResponderCacheEntry = null;
    for (final OcspSigningCacheEntry entry : staging.values()) {
      if (entry.getOcspSigningCertificate() != null) {
        final X509Certificate signingCertificate =
            entry.getOcspSigningCertificate();
        if (CertTools.getIssuerDN(signingCertificate)
            .equals(defaultResponderSubjectDn)) {
          lDefaultResponderCacheEntry = entry;
          break;
        }
      } else if (entry.getCaCertificateChain() != null
          && !entry.getCaCertificateChain().isEmpty()) {
        final X509Certificate signingCertificate =
            entry.getCaCertificateChain().get(0);
        if (CertTools.getSubjectDN(signingCertificate)
            .equals(defaultResponderSubjectDn)) {
          lDefaultResponderCacheEntry = entry;
          break;
        }
      }
    }
    return lDefaultResponderCacheEntry;
}

  /** Unlock. */
  public void stagingRelease() {
    lock.unlock();
  }

  /**
   * Log any change in default responder.
   *
   * @param currentEntry current entry
   * @param stagedEntry staged entry
   * @param defaultResponderSubjectDn boolean
   */
  private void logDefaultResponderChanges(
      final OcspSigningCacheEntry currentEntry,
      final OcspSigningCacheEntry stagedEntry,
      final String defaultResponderSubjectDn) {
    String msg = null;
    if (stagedEntry == null
        && (currentEntry != null || !logDefaultHasRunOnce)) {
      // No default responder after staging. Did we loose it or is it the first
      // time we run this check?
      if (StringUtils.isEmpty(defaultResponderSubjectDn)) {
        msg = "No default responder was defined.";
      } else {
        msg =
            "The default OCSP responder with subject '"
                + defaultResponderSubjectDn
                + "' was not found.";
      }
      msg +=
          " OCSP requests for certificates issued by unknown CAs will return"
              + " \"unauthorized\" as per RFC6960, Section 2.3";
    } else if (stagedEntry != null && currentEntry == null) {
      // We gained a default responder.
      if (stagedEntry.isUsingSeparateOcspSigningCertificate()) {
        msg =
            "Setting keybinding with ID"
                + stagedEntry.getOcspKeyBinding().getId()
                + " and DN "
                + defaultResponderSubjectDn
                + " as default OCSP responder.";
      } else {
        msg =
            "Setting CA with DN "
                + defaultResponderSubjectDn
                + " as default OCSP responder.";
      }
    } else if (stagedEntry != null && currentEntry != null) {
      // We have a default responder both before and after. Did it change in any
      // way?
      if (stagedEntry.isUsingSeparateOcspSigningCertificate()
              != currentEntry.isUsingSeparateOcspSigningCertificate()
          || !CertTools.getSubjectDN(stagedEntry.getIssuerCaCertificate())
              .equals(
                  CertTools.getSubjectDN(
                      currentEntry.getIssuerCaCertificate()))) {
        // We switched from signing with a CA to OcspKeyBindinig or vice versa,
        // or use a different default.
        if (stagedEntry.isUsingSeparateOcspSigningCertificate()) {
          msg =
              "Setting keybinding with ID"
                  + stagedEntry.getOcspKeyBinding().getId()
                  + " and DN "
                  + defaultResponderSubjectDn
                  + " as default OCSP responder.";
        } else {
          msg =
              "Setting CA with DN "
                  + defaultResponderSubjectDn
                  + " as default OCSP responder.";
        }
      } else if (stagedEntry.isUsingSeparateOcspSigningCertificate()
        && stagedEntry.getOcspKeyBinding().getId()
            != currentEntry.getOcspKeyBinding().getId()) {
          // A different OcspKeyBinding will be used to respond to requests even
          // though the issuing CA has not changed
          msg =
              "Setting keybinding with ID"
                  + stagedEntry.getOcspKeyBinding().getId()
                  + " and DN "
                  + defaultResponderSubjectDn
                  + " as default OCSP responder.";
        }

    }
    if (msg == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No change in default responder.");
      }
    } else {
      LOG.info(msg);
    }
    logDefaultHasRunOnce = true;
  }

  /**
   * This method will add a single cache entry to the cache. It should only be
   * used to solve temporary cache inconsistencies.
   *
   * @param ocspSigningCacheEntry the entry to add
   */
  public void addSingleEntry(
          final OcspSigningCacheEntry ocspSigningCacheEntry) {
    List<CertificateID> certIDs = ocspSigningCacheEntry.getCertificateID();
    for (CertificateID certID : certIDs) {
      int cacheId = getCacheIdFromCertificateID(certID);
      lock.lock();
      try {
        // Make sure that another thread didn't add the same entry while this
        // one was waiting.
        if (!cache.containsKey(cacheId)) {
          cache.put(cacheId, ocspSigningCacheEntry);
        }
      } finally {
        lock.unlock();
      }
    }
  }

  /**
   * @param certID ID
   * @return a cache identifier based on the provided CertificateID.
   */
  public static int getCacheIdFromCertificateID(final CertificateID certID) {
    // Use bitwise XOR of the hashcodes for IssuerNameHash and IssuerKeyHash to
    // produce the integer.
    int result =
        new BigInteger(certID.getIssuerNameHash()).hashCode()
            ^ new BigInteger(certID.getIssuerKeyHash()).hashCode();
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Using getIssuerNameHash "
              + new BigInteger(certID.getIssuerNameHash()).toString(16)
              + " and getIssuerKeyHash "
              + new BigInteger(certID.getIssuerKeyHash()).toString(16)
              + " to produce id "
              + result);
    }
    return result;
  }

  /**
   * @param certificate certificate
   * @return the CertificateID's based on the provided certificate
   */
  public static List<CertificateID> getCertificateIDFromCertificate(
      final X509Certificate certificate) {
    try {
      if (LOG.isTraceEnabled()) {
        LOG.trace(
            "Building CertificateId's from certificate with subjectDN '"
                + CertTools.getSubjectDN(certificate)
                + "'.");
      }
      List<CertificateID> ret = new ArrayList<CertificateID>();
      ret.add(
          new JcaCertificateID(
              new BcDigestCalculatorProvider()
                  .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)),
              certificate,
              certificate.getSerialNumber()));
      ret.add(
          new JcaCertificateID(
              new BcDigestCalculatorProvider()
                  .get(
                      new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
              certificate,
              certificate.getSerialNumber()));
      return ret;
    } catch (OCSPException e) {
      throw new OcspFailureException(e);
    } catch (CertificateEncodingException e) {
      throw new OcspFailureException(e);
    } catch (OperatorCreationException e) {
      throw new OcspFailureException(e);
    }
  }
}
