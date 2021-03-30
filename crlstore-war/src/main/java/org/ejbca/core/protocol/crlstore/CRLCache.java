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

package org.ejbca.core.protocol.crlstore;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;

/**
 * An implementation of this is managing a cache of CRLs. The implementation
 * should be optimized for quick lookups of CRLs that the VA responder needs to
 * fetch.
 *
 * @version $Id: CRLCache.java 25645 2017-04-04 09:22:52Z anatom $
 */
public final class CRLCache {
    /** Param. */
  private static final Logger LOG = Logger.getLogger(CRLCache.class);

  /** Param. */
  private static CRLCache instance = null;
  /** Param. */
  private static final Lock LOCK = new ReentrantLock();

  /** Param. */
  private final CrlStoreSessionLocal crlSession;
  /** Param. */
  private final CaCertificateCache certCache;
  /** Param. */
  private final Map<Integer, CRLEntity> crls =
      new HashMap<Integer, CRLEntity>();
  /** Param. */
  private final Map<Integer, CRLEntity> deltaCrls =
      new HashMap<Integer, CRLEntity>();

  private class CRLEntity {
        /** Param. */
    private final CRLInfo crlInfo;
    /** Param. */
    private final byte[] encoded;
    /**
     * @param acrlInfo Info
     * @param anencoded Data
     */
    CRLEntity(final CRLInfo acrlInfo, final byte[] anencoded) {
      super();
      this.crlInfo = acrlInfo;
      this.encoded = anencoded;
    }
  }
  /**
   * We need an object to synchronize around when rebuilding and reading the
   * cache. When rebuilding the cache no thread can be allowed to read the
   * cache, since the cache will be in an inconsistent state. In the normal case
   * we want to use as fast objects as possible (HashMap) for reading fast.
   */
  private final Lock rebuildlock = new ReentrantLock();

  /**
   * @param crlSession Session
   * @param certCache Cache
   * @return {@link CRLCache} for the CA.
   */
  public static CRLCache getInstance(
      final CrlStoreSessionLocal crlSession,
      final CaCertificateCache certCache) {
    if (instance != null) {
      return instance;
    }
    LOCK.lock();
    try {
      if (instance == null) {
        instance = new CRLCache(crlSession, certCache);
      }
      return instance;
    } finally {
      LOCK.unlock();
    }
  }

  /**
   * @param acrlSession reference to CRLStoreSession
   * @param acertCache references to needed CA certificates.
   */
  private CRLCache(
      final CrlStoreSessionLocal acrlSession,
      final CaCertificateCache acertCache) {
    super();
    this.crlSession = acrlSession;
    this.certCache = acertCache;
  }

  /**
   * @param id The ID of the subject key identifier.
   * @param isDelta true if delta CRL
   * @param crlNumber specific crlNumber of the CRL to be retrieved, when not
   *     the latest, or -1 for the latest
   * @return CRL or null if the CRL does not exist in the cache.
   */
  public byte[] findBySubjectKeyIdentifier(
      final HashID id, final boolean isDelta, final int crlNumber) {
    return findCRL(
        certCache.findBySubjectKeyIdentifier(id), isDelta, crlNumber);
  }

  /**
   * @param id The ID of the issuer DN.
   * @param isDelta true if delta CRL
   * @param crlNumber specific crlNumber of the CRL to be retrieved, when not
   *     the latest, or -1 for the latest
   * @return CRL or null if the CRL does not exist in the cache.
   */
  public byte[] findByIssuerDN(
      final HashID id, final boolean isDelta, final int crlNumber) {
    return findCRL(certCache.findLatestBySubjectDN(id), isDelta, crlNumber);
  }

  private byte[] findCRL(
      final X509Certificate caCert,
      final boolean isDelta,
      final int crlNumber) {
    if (caCert == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No CA certificate, returning null.");
      }
      return null;
    }
    final HashID id = HashID.getFromSubjectDN(caCert);
    final String issuerDN = CertTools.getSubjectDN(caCert);
    this.rebuildlock.lock();
    try {
      final CRLInfo crlInfo = this.crlSession.getLastCRLInfo(issuerDN, isDelta);
      if (crlInfo == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "No CRL found with issuerDN '" + issuerDN + "', returning null.");
        }
        return null;
      }
      final Map<Integer, CRLEntity> usedCrls =
          isDelta ? this.deltaCrls : this.crls;
      // If we have not specified a crlNumber we can try to find the latest CRL
      // in the cache
      if (crlNumber == -1) {
        final CRLEntity cachedCRL = usedCrls.get(id.getKey());
        if (cachedCRL != null
            && !crlInfo
                .getCreateDate()
                .after(cachedCRL.crlInfo.getCreateDate())) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Retrieved CRL (from cache) with issuerDN '"
                    + issuerDN
                    + "', with CRL number "
                    + crlInfo.getLastCRLNumber());
          }
          return cachedCRL.encoded;
        }
      }
      final CRLEntity entry;
      if (crlNumber > -1) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Getting CRL with CRL number " + crlNumber);
        }
        entry =
            new CRLEntity(crlInfo, this.crlSession.getCRL(issuerDN, crlNumber));
      } else {
        entry =
            new CRLEntity(
                crlInfo, this.crlSession.getLastCRL(issuerDN, isDelta));
        // Only cache latest CRLs, these should be the ones accessed regularly,
        // and we don't want to fill the cache with old CRLs
        usedCrls.put(id.getKey(), entry);
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Retrieved CRL (not from cache) with issuerDN '"
                + issuerDN
                + "', with CRL number "
                + crlInfo.getLastCRLNumber());
      }
      return entry.encoded;
    } finally {
      this.rebuildlock.unlock();
    }
  }
}
