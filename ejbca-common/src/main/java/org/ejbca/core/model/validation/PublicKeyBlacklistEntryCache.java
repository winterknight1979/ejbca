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

package org.ejbca.core.model.validation;

import java.util.List;
import java.util.Map;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Public key blacklist entry (see {@link PublicKeyBlacklistEntry}) and name to
 * id lookup cache. Configured through
 * CesecoreConfiguration.getCachePublicKeyBlacklistTime().
 *
 * @version $Id: PublicKeyBlacklistEntryCache.java 28332 2018-02-20 14:40:52Z
 *     anatom $
 */
public enum PublicKeyBlacklistEntryCache
    implements CommonCache<PublicKeyBlacklistEntry> {
  /** Singleton. */
    INSTANCE;

    /** Cache. */
  private final CommonCache<PublicKeyBlacklistEntry> cache =
      new CommonCacheBase<PublicKeyBlacklistEntry>() {
        @Override
        protected long getCacheTime() {
          return Math.max(
              CesecoreConfigurationHelper.getCachePublicKeyBlacklistTime(), 0);
        }


        @Override
        protected long getMaxCacheLifeTime() {
          // We never purge PublicKeyBlacklist unless a database select
          // discovers a missing object.
          return 0L;
        }
      };

  @Override
  public PublicKeyBlacklistEntry getEntry(final Integer id) {
    if (id == null) {
      return null;
    }
    return cache.getEntry(id);
  }

  @Override
  public PublicKeyBlacklistEntry getEntry(final int id) {
    return cache.getEntry(id);
  }

  @Override
  public boolean shouldCheckForUpdates(final int id) {
    return cache.shouldCheckForUpdates(id);
  }

  /**
   * @param id entry ID
   * @param digest Data.getProtectString(0).hashCode()
   * @param name the fingerprint of the entry object
   * @param object black list entry
   */
  @Override
  public void updateWith(
      final int id,
      final int digest,
      final String name,
      final PublicKeyBlacklistEntry object) {
    cache.updateWith(id, digest, name, object);
  }

  @Override
  public void removeEntry(final int id) {
    cache.removeEntry(id);
  }

  @Override
  public String getName(final int id) {
    return cache.getName(id);
  }

  @Override
  public Map<String, Integer> getNameToIdMap() {
    return cache.getNameToIdMap();
  }

  @Override
  public void flush() {
    cache.flush();
  }

  @Override
  public void replaceCacheWith(final List<Integer> keys) {
    cache.replaceCacheWith(keys);
  }

  @Override
  public boolean willUpdate(final int id, final int digest) {
    return cache.willUpdate(id, digest);
  }
}
