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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.util.ConcurrentCache;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id: RemoteAccessSetCacheHolderTest.java 25893 2017-05-23 20:10:03Z
 *     mikekushner $
 */
@SuppressWarnings("deprecation")
public final class RemoteAccessSetCacheHolderTest {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(RemoteAccessSetCacheHolderTest.class);

  /** Token. */
  private final AuthenticationToken token1 =
      new PublicAccessAuthenticationToken("CN=test1", false);
  /** Token. */
  private final AuthenticationToken token2 =
      new PublicAccessAuthenticationToken("CN=test2", false);

  /** Test cycle. */
  @Test
  public void testStartFinishCycle() {
    LOG.trace(">testStartFinishCycle");
    assertTrue(
        "The cache should be empty initially",
        RemoteAccessSetCacheHelper.getCache().getKeys().isEmpty());

    LOG.debug("Starting a update number 10");
    Set<AuthenticationToken> existing =
        RemoteAccessSetCacheHelper.startCacheReload(10);
    assertTrue("Returned set should be empty", existing.isEmpty());
    assertNull(
        "Should return null when trying to refresh with old update.",
        RemoteAccessSetCacheHelper.startCacheReload(9));
    assertNull(
        "Should return null when trying to refresh with -1 while update is in"
            + " progress.",
        RemoteAccessSetCacheHelper.startCacheReload(-1));

    final Map<AuthenticationToken, AccessSet> newCache = new HashMap<>();
    final Set<String> set = new HashSet<>();
    set.add("/test");
    final AccessSet as = new AccessSet(set);
    newCache.put(token1, as);

    RemoteAccessSetCacheHelper.finishCacheReload(10, newCache);
    assertEquals(
        "Cache should have been updated",
        1,
        RemoteAccessSetCacheHelper.getCache().getKeys().size());

    LOG.debug("Starting a update number 11");
    existing = RemoteAccessSetCacheHelper.startCacheReload(11);
    assertEquals(
        "Wrong number of entries in list of existing auth tokens",
        1,
        existing.size());
    assertEquals(
        "Wrong auth token in list", token1, existing.iterator().next());

    final Map<AuthenticationToken, AccessSet> newCache2 = new HashMap<>();
    final Set<String> set2 = new HashSet<>();
    set2.add("/test1");
    set2.add("/test2");
    final AccessSet as2 = new AccessSet(set2);
    newCache2.put(token1, as2);
    newCache2.put(token2, as2);

    LOG.debug("Should not overwrite cache");
    RemoteAccessSetCacheHelper.finishCacheReload(10, newCache2);
    assertEquals(
        "Old update number should not overwrite the cache",
        1,
        RemoteAccessSetCacheHelper.getCache().getKeys().size());

    LOG.debug("Should overwrite cache");
    RemoteAccessSetCacheHelper.finishCacheReload(11, newCache2);
    assertEquals(
        "Cache should have been updated again",
        2,
        RemoteAccessSetCacheHelper.getCache().getKeys().size());
    LOG.trace("<testStartFinishCycle");
  }

  /**
   * Reset.
   * @throws IllegalArgumentException fail
   * @throws IllegalAccessException fail
   * @throws NoSuchFieldException fail
   * @throws SecurityException fail
   */
  @Before
  @After
  public void reset()
      throws IllegalArgumentException, IllegalAccessException,
          NoSuchFieldException, SecurityException {
    final Field lastUpdField =
        RemoteAccessSetCacheHelper.class.getDeclaredField("lastUpdate");
    lastUpdField.setAccessible(true);
    lastUpdField.setInt(null, 0);

    final Field inProgressField =
        RemoteAccessSetCacheHelper.class.getDeclaredField(
            "regularUpdateInProgress");
    inProgressField.setAccessible(true);
    inProgressField.setBoolean(null, false);

    final Field cacheField =
        RemoteAccessSetCacheHelper.class.getDeclaredField("cache");
    cacheField.setAccessible(true);
    cacheField.set(null, new ConcurrentCache<AuthenticationToken, AccessSet>());
  }
}
