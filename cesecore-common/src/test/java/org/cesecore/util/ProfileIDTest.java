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
package org.cesecore.util;

import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test of {@link ProfileIDUtil}.
 *
 * @version $Id: ProfileIDTest.java 23749 2016-06-30 11:12:39Z mikekushner $
 */
public class ProfileIDTest {
    /** Random source. */
  static final Random RANDOM = new Random();
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(ProfileIDTest.class);

  private class DBTestSometimesFree implements ProfileIDUtil.DB {
      /** tries. */
    private int triesUntilFree = -1;

    DBTestSometimesFree() {
      // do nothing
    }

    @Override
    public boolean isFree(final int i) {
      if (this.triesUntilFree < 0) {
        this.triesUntilFree = RANDOM.nextInt(9);
      }
      final boolean isFree = this.triesUntilFree < 1;
      this.triesUntilFree--;
      return isFree;
    }
  }

  private class DBTestReal implements ProfileIDUtil.DB {
      /** IDs. */
    private final Set<Integer> ids = new HashSet<Integer>();

    DBTestReal() {
      // do nothing
    }

    @Override
    public boolean isFree(final int i) {
      return this.ids.add(Integer.valueOf(i));
    }
  }

  private class DBTestNeverFree implements ProfileIDUtil.DB {
    DBTestNeverFree() {
      // do nothing
    }

    @Override
    public boolean isFree(final int i) {
      return false;
    }
  }
  /** Test that exception is thrown if never free. */
  @Test
  public void testNothingFree() {
    LOG.trace(">testNothingFree()");
    try {
      final int i = ProfileIDUtil.getNotUsedID(new DBTestNeverFree());
      assertTrue(
          "Should not have been possible to generate anything but "
              + i
              + " was generated.",
          false);
    } catch (RuntimeException e) {
      // NOPMD: this is OK in the test
    }
    LOG.trace("<testNothingFree()");
  }
  /**
   * Simulates real behavior. We check that the ID never has been generated
   * before. Check the log and see that {@link
   * ProfileIDUtil#getNotUsedID(ProfileIDUtil.DB)} only calls {@link
   * ProfileIDUtil.DB#isFree} once in almost all test.
   */
  @Test
  public void testReal() {
    LOG.trace(">testReal()");
    for (int i = 0; i < 0x1000000; i++) {
      final int id = ProfileIDUtil.getNotUsedID(new DBTestReal());
      assertTrue(id > 0xffff);
    }
    LOG.trace("<testReal()");
  }
  /**
   * Test when {@link ProfileIDUtil#getNotUsedID(ProfileIDUtil.DB)}
   * sometimes return false.
   */
  @Test
  public void testSometimesFree() {
    LOG.trace(">testSometimesFree()");
    for (int i = 0; i < 0x100; i++) {
      final int id = ProfileIDUtil.getNotUsedID(new DBTestSometimesFree());
      assertTrue(id > 0xffff);
    }
    LOG.trace("<testSometimesFree()");
  }
}
