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
package org.cesecore.authorization.access;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.junit.Test;

/** @version $Id: AccessSetTest.java 25832 2017-05-10 14:13:58Z mikekushner $ */
public final class AccessSetTest {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(AccessSetTest.class);

  /** Set. */
  @SuppressWarnings("deprecation")
  private final AccessSet as =
      makeLegacyAccessSet(
          "/test",
          "/one/two",
          "/three",
          "/three/four",
          "/three/four/five",
          "/six",
          "/six/" + AccessSet.WILDCARD_RECURSIVE,
          "/seven/eight",
          "/seven/eight/" + AccessSet.WILDCARD_RECURSIVE,
          "/nine/",
          "/ten/eleven/subresource", // currently unused
          "/twelve/" + AccessSet.WILDCARD_SOME,
          "/twelve/-123456",
          "/thirteen/" + AccessSet.WILDCARD_SOME + "/subres",
          "/thirteen/98765/subres");
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testSimpleAllowed() {
    LOG.trace(">testSimpleAllowed");
    assertTrue(as.isAuthorized("/test"));
    assertTrue(as.isAuthorized("/three"));
    LOG.trace("<testSimpleAllowed");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testSimpleDenied() {
    LOG.trace(">testSimpleDenied");
    assertFalse(as.isAuthorized("/"));
    assertFalse(as.isAuthorized("/nonexistent"));
    LOG.trace("<testSimpleDenied");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testNested() {
    LOG.trace(">testNested");
    assertTrue(as.isAuthorized("/one/two"));
    assertTrue(as.isAuthorized("/three/four"));
    assertTrue(as.isAuthorized("/three/four/five"));
    assertFalse(as.isAuthorized("/one/notgranted"));
    assertFalse(as.isAuthorized("/three/five"));
    assertFalse(as.isAuthorized("/three/four/nine"));
    LOG.trace("<testNested");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testRecursive() {
    LOG.trace(">testRecursive");
    assertTrue(as.isAuthorized("/six"));
    assertTrue(as.isAuthorized("/six/blabla"));
    assertTrue(as.isAuthorized("/six/-9876"));
    assertTrue(
        as.isAuthorized("/six/blabla/" + AccessSet.WILDCARD_SOME + "/bla"));
    assertTrue(as.isAuthorized("/six/blabla/123456/bla"));
    assertTrue(as.isAuthorized("/seven/eight"));
    assertTrue(as.isAuthorized("/seven/eight/test"));
    assertTrue(as.isAuthorized("/seven/eight/test/bla/bla/bla"));
    LOG.trace("<testRecursive");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testSlashRecurisve() {
    LOG.trace(">testSlashRecurisve");
    final AccessSet sr =
        makeLegacyAccessSet("/" + AccessSet.WILDCARD_RECURSIVE);
    assertTrue(sr.isAuthorized("/"));
    assertTrue(sr.isAuthorized("/one"));
    assertTrue(sr.isAuthorized("/one/two/three"));
    assertTrue(sr.isAuthorized("/one/-1234/three"));
    LOG.trace("<testSlashRecurisve");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testSomeWilcard() {
    LOG.trace(">testSomeWilcard");
    assertTrue(as.isAuthorized("/twelve/" + AccessSet.WILDCARD_SOME));
    assertTrue(
        as.isAuthorized("/thirteen/" + AccessSet.WILDCARD_SOME + "/subres"));
    assertFalse(as.isAuthorized("/twelve/-11111"));
    assertFalse(as.isAuthorized("/thirteen/22222/subres"));
    LOG.trace("<testAllWilcard");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testBadResources() {
    LOG.trace(">testBadResources");
    // The correct syntax is /bla/blabla
    try {
      as.isAuthorized("bla/blabla");
      fail("Should fail");
    } catch (IllegalArgumentException e) {
      // NOPMD expected
    }
    try {
      as.isAuthorized("/bla/blabla/");
      fail("Should fail");
    } catch (IllegalArgumentException e) {
      // NOPMD expected
    }
    LOG.trace("<testBadResources");
  }
  /**
   * Test.
   */
  @SuppressWarnings("deprecation")
  @Test
  public void testConvertAndMerge() {
    LOG.trace(">testConvertAndMerge");
    final AccessSet asNew = makeNewAccessSet();
    // Merge with an old AccessSet to force downgrade
    final AccessSet asOld =
        new AccessSet(Arrays.asList("/a", "/f", "/nonexistentold"));
    final AccessSet merged = new AccessSet(asNew, asOld);
    assertTrue(merged.isAuthorized("/a"));
    assertFalse(merged.isAuthorized("/b"));
    assertTrue(merged.isAuthorized("/b/c"));
    assertTrue(merged.isAuthorized("/b/c/d"));
    assertFalse(merged.isAuthorized("/b/c/e"));
    assertTrue(merged.isAuthorized("/f"));
    assertFalse(
        merged.isAuthorized(
            "/nonexistent")); // the converter does not allow non-existent
                              // resources
    assertTrue(
        merged.isAuthorized(
            "/nonexistentold")); // this rule comes from the old AccessSet, so
                                 // it's left untouched
    LOG.trace("<testConvertAndMerge");
  }

  /**
   * Creates an AccessSet with the legacy representation of access rules.
   *
   * @param resources resources
   * @return access set
   */
  @SuppressWarnings("deprecation")
  private AccessSet makeLegacyAccessSet(final String... resources) {
    final Collection<String> col = new ArrayList<>();
    for (final String resource : resources) {
      col.add(resource);
    }
    return new AccessSet(col);
  }

  @SuppressWarnings("deprecation")
  private AccessSet makeNewAccessSet() {
    final Set<String> allResources = new HashSet<>();
    allResources.add("/a/");
    allResources.add("/b/");
    allResources.add("/b/c/");
    allResources.add("/b/c/d/");
    allResources.add("/b/c/e/");
    allResources.add("/f/");
    final HashMap<String, Boolean> accessRules = new HashMap<>();
    accessRules.put("/a/", true);
    accessRules.put("/b/c/", true);
    accessRules.put("/b/c/e/", false);
    accessRules.put("/nonexistent/", true);
    return AccessSet.fromAccessRules(accessRules, allResources);
  }
}
