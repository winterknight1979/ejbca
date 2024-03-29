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
package org.cesecore.keys.token;

import java.util.List;
import java.util.Map;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * CryptoToken Object cache.
 *
 * @version $Id: CryptoTokenCache.java 28332 2018-02-20 14:40:52Z anatom $
 */
public enum CryptoTokenCache implements CommonCache<CryptoToken> {
  /** Singleton. */
    INSTANCE;

    /**
     * Cache. */
  private final CommonCache<CryptoToken> cryptoTokenCache =
      new CommonCacheBase<CryptoToken>() {
        @Override
        protected long getCacheTime() {
          // We should never disable storage of CryptoTokens in the cache
          // completely, since we want to keep any activation
          // So never use cache value "-1" in the setting, use the value 0
          // instead.
          return CesecoreConfigurationHelper.getCacheTimeCryptoToken();
        }

        @Override
        protected long getMaxCacheLifeTime() {
          // We never purge CryptoTokens unless a database select discovers a
          // missing object.
          return 0;
        }

      };

  @Override
  public CryptoToken getEntry(final Integer id) {
    if (id == null) {
      return null;
    }
    return cryptoTokenCache.getEntry(id);
  }

  @Override
  public CryptoToken getEntry(final int cryptoTokenId) {
    return cryptoTokenCache.getEntry(cryptoTokenId);
  }

  @Override
  public boolean shouldCheckForUpdates(final int cryptoTokenId) {
    return cryptoTokenCache.shouldCheckForUpdates(cryptoTokenId);
  }

  @Override
  public void updateWith(
      final int cryptoTokenId,
      final int digest,
      final String name,
      final CryptoToken object) {
    cryptoTokenCache.updateWith(cryptoTokenId, digest, name, object);
  }

  @Override
  public void removeEntry(final int cryptoTokenId) {
    cryptoTokenCache.removeEntry(cryptoTokenId);
  }

  @Override
  public String getName(final int id) {
    return cryptoTokenCache.getName(id);
  }

  @Override
  public Map<String, Integer> getNameToIdMap() {
    return cryptoTokenCache.getNameToIdMap();
  }

  @Override
  public void flush() {
    cryptoTokenCache.flush();
  }

  @Override
  public void replaceCacheWith(final List<Integer> keys) {
    cryptoTokenCache.replaceCacheWith(keys);
  }

  @Override
  public boolean willUpdate(final int id, final int digest) {
    return cryptoTokenCache.willUpdate(id, digest);
  }
}
