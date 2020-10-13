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
package org.cesecore.authorization.cache;

import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.util.ConcurrentCache;

/**
 * Holds a ConcurrentCache which can be filled with cached AccessSets from
 * remote systems etc.
 *
 * @version $Id: RemoteAccessSetCacheHolder.java 25591 2017-03-23 13:13:02Z
 *     jeklund $
 * @deprecated since EJBCA 6.8.0
 */
@Deprecated
public final class RemoteAccessSetCacheHolder {
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(RemoteAccessSetCacheHolder.class);

  // These fields are also modified by the test RemoteAccessSetCacheHolderTest
  /** Last update. */
  private static volatile int lastUpdate = -1;
  /** If update is in progress. */
  private static volatile boolean regularUpdateInProgress = false;
  // not clear caches etc.
  /** Semaphore. */
  private static final Object CHECK_CLEAR_LOCK = new Object();
  /** Cache. */
  private static ConcurrentCache<AuthenticationToken, AccessSet> cache =
      new ConcurrentCache<>();

  /** Can't be instantiated. */
  private RemoteAccessSetCacheHolder() { }

  /**
   * Returns a ConcurrentCache object that can be used for caching AccessSets
   * from remote systems. The caller is responsible for filling it with results
   * from getAccessSetForAuthToken from the remote system, but it's
   * automatically cleared whenever local access rules change.
   *
   * @return Cache
   */
  public static ConcurrentCache<AuthenticationToken, AccessSet> getCache() {
    return cache;
  }

  /**
   * Starts a cache reload. The caller is responsible for actually building the
   * cache data after calling this method, i.e. building a map of
   * AuthenticationTokens to AccessSets, and then passing that to
   * finishCacheReload().
   *
   * <p>This method avoids duplicate cache invalidations if invoked multiple
   * times from multiple sources (e.g. CAs in a cluster that broadcast a "clear
   * caches" peer message).
   *
   * @param updateNumber Access tree update number at the time the clear cache
   *     triggered.
   * @return Currently existing AuthenticationTokens in the cache.
   */
  public static Set<AuthenticationToken> startCacheReload(
      final int updateNumber) {
    LOG.trace(">startCacheReload");
    synchronized (CHECK_CLEAR_LOCK) {
      if (updateNumber != -1) {
        if (lastUpdate >= updateNumber) {
          LOG.trace(
              "<startCacheReload " + "(already has a more recent version)");
          return null;
        }
        lastUpdate = updateNumber;
        regularUpdateInProgress = true;
        LOG.debug("Started cache reload");
      } else if (regularUpdateInProgress) {
        LOG.trace("<startCacheReload (regular update was in progress)");
        return null;
      }
    }
    final Set<AuthenticationToken> existing = cache.getKeys();
    LOG.trace("<startCacheReload");
    return existing;
  }

  /**
   * Complete cache reload.
   *
   * @param updateNumber Update
   * @param newCacheMap New map
   */
  public static void finishCacheReload(
      final int updateNumber,
      final Map<AuthenticationToken, AccessSet> newCacheMap) {
    LOG.trace(">finishCacheReload");

    if (updateNumber != -1) {
      if (lastUpdate > updateNumber) {
        LOG.trace(
            "<finishCacheReload "
                + "(not updating because a more recent "
                + "update finished earlier)");
        return;
      }
    } else if (regularUpdateInProgress) {
      LOG.trace(
          "<finishCacheReload "
              + "(not updating because regularUpdateInProgress)");
      return;
    }

    // Build new cache, but don't update it yet
    final ConcurrentCache<AuthenticationToken, AccessSet> newCache =
        new ConcurrentCache<>(newCacheMap, -1L);

    // Make sure we don't overwrite a more recent update
    // (e.g. if it finished faster than us)
    synchronized (CHECK_CLEAR_LOCK) {
      if (updateNumber != -1) {
        if (lastUpdate > updateNumber) {
          LOG.trace(
              "<finishCacheReload " + "(already has a more recent version)");
          return;
        }
        lastUpdate = updateNumber;
        regularUpdateInProgress = false;
      } else if (regularUpdateInProgress) {
        LOG.trace("<finishCacheReload " + "(regular update was in progress)");
        return;
      }
      cache = newCache;
      LOG.debug("Replaced access set cache");
    }
    LOG.trace("<finishCacheReload");
  }

  /**
   * Empties the cache. Please try to only use this method with the local cache
   */
  public static void forceEmptyCache() {
    cache.clear();
  }
}
