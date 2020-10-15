/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.List;
import java.util.Map;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Key validator object and name to id lookup cache. Configured through
 * CesecoreConfiguration.getCacheKeyValidatorTime().
 *
 * @version $Id: ValidatorCache.java 28332 2018-02-20 14:40:52Z anatom $
 */
public enum ValidatorCache implements CommonCache<Validator> {
  INSTANCE;

  private final CommonCache<Validator> cache =
      new CommonCacheBase<Validator>() {
        @Override
        protected long getCacheTime() {
          long time =
              Math.max(CesecoreConfiguration.getCacheKeyValidatorTime(), -1);
          return time;
        }
        ;

        @Override
        protected long getMaxCacheLifeTime() {
          // We never purge BaseKeyValidators unless a database select discovers
          // a missing object.
          return 0L;
        }
      };

  @Override
  public Validator getEntry(final Integer id) {
    if (id == null) {
      return null;
    }
    return cache.getEntry(id);
  }

  @Override
  public Validator getEntry(final int id) {
    return cache.getEntry(id);
  }

  @Override
  public boolean shouldCheckForUpdates(final int id) {
    return cache.shouldCheckForUpdates(id);
  }

  @Override
  public void updateWith(
      final int id,
      final int digest,
      final String name,
      final Validator object) {
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
