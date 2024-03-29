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

import java.util.List;
import java.util.Map;
import org.cesecore.certificates.ca.CA;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * CA object and name to id lookup cache. Configured through
 * CesecoreConfiguration.getCacheCaTimeInCaSession().
 *
 * @version $Id: CaCache.java 28332 2018-02-20 14:40:52Z anatom $
 */
public enum CaCache implements CommonCache<CA> {
  /** Singleton. */
    INSTANCE;

    /** Cache. **/
  private final CommonCache<CA> caCache =
      new CommonCacheBase<CA>() {
        @Override
        protected long getCacheTime() {
          return CesecoreConfigurationHelper.getCacheCaTimeInCaSession();
        }


        @Override
        protected long getMaxCacheLifeTime() {
          // CAs are not short-lived objects with long cache times so we disable
          // it
          return 0L;
        }

      };

  @Override
  public CA getEntry(final Integer id) {
    if (id == null) {
      return null;
    }
    return caCache.getEntry(id);
  }

  @Override
  public CA getEntry(final int caId) {
    return caCache.getEntry(caId);
  }

  @Override
  public boolean shouldCheckForUpdates(final int caId) {
    return caCache.shouldCheckForUpdates(caId);
  }

  @Override
  public void updateWith(
      final int caId, final int digest, final String name, final CA object) {
    caCache.updateWith(caId, digest, name, object);
  }

  @Override
  public void removeEntry(final int caId) {
    caCache.removeEntry(caId);
  }

  @Override
  public String getName(final int id) {
    return caCache.getName(id);
  }

  @Override
  public Map<String, Integer> getNameToIdMap() {
    return caCache.getNameToIdMap();
  }

  @Override
  public void flush() {
    caCache.flush();
  }

  @Override
  public void replaceCacheWith(final List<Integer> keys) {
    caCache.replaceCacheWith(keys);
  }

  @Override
  public boolean willUpdate(final int id, final int digest) {
    return caCache.willUpdate(id, digest);
  }
}
