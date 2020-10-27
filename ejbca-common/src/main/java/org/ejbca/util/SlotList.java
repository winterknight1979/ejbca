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
package org.ejbca.util;

import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A list of slots numbers and indexes. Can contain ranges and individual
 * entries.
 *
 * @version $Id: SlotList.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class SlotList {

  private static final class Range implements Comparable<Range> {
      /** Param. */
    private final int min;
    /** Param. */
    private final int max;

    Range(final int amin, final int amax) {
      if (amin > amax) {
        throw new IllegalArgumentException(
            "Minimum value ("
                + amin
                + ") in slot range is greater than maximum value ("
                + amax
                + ")");
      }
      this.min = amin;
      this.max = amax;
    }

    @Override
    public int compareTo(final Range o) {
      if (min < o.min) {
          return -1;
      }
      if (min > o.min) {
          return 1;
      } else {
          return 0;
      }
    }
  }

  /** Param. */
  private final TreeSet<Range> ranges = new TreeSet<Range>();
  /** Param. */
  private final TreeSet<Range> indexRanges = new TreeSet<Range>();

  private int intval(final String s, final int defaultValue) {
    return s != null ? Integer.valueOf(s) : defaultValue;
  }

  private void addRange(
      final Matcher m, final int groupMin, final int groupMax) {
    final int min = intval(m.group(groupMin), Integer.MIN_VALUE);
    final int max = intval(m.group(groupMax), Integer.MAX_VALUE);
    addRangeTo(ranges, min, max);
  }

  private void addIndexRange(
      final Matcher m, final int groupMin, final int groupMax) {
    final int min = intval(m.group(groupMin), Integer.MIN_VALUE);
    final int max = intval(m.group(groupMax), Integer.MAX_VALUE);
    addRangeTo(indexRanges, min, max);
  }

  private void addRangeTo(
          final TreeSet<Range> r, final int omin, final int omax) {
    int min = omin;
    int max = omax;
      Range toAdd = new Range(min, max);

    // Check for overlap with lower numbers
    final Range lower = r.floor(toAdd);
    if (lower != null
        && (lower.max >= min - 1
            || lower.max >= min)) { // special handling for integer overflows
      if (lower.max >= max) {
          return; // complete overlap
      }
      min = lower.min; // expand self
      toAdd = new Range(min, max);
      r.remove(lower);
    }

    // Check for overlap with higher numbers
    final Range higher = r.ceiling(toAdd);
    if (higher != null && (higher.min <= max + 1 || higher.min <= max)) {
      if (higher.min <= min) {
          return; // complete overlap
      }
      max = higher.max;
      toAdd = new Range(min, max); // expand self
      r.remove(higher);
    }

    r.add(toAdd);
  }

  /** Config. */
  private static final Pattern SLOT_LIST_SINGLE =
          Pattern.compile("^([0-9]+)$");
  /** Config. */
  private static final Pattern SLOT_LIST_RANGE =
      Pattern.compile("^([0-9]+)?-([0-9]+)?$");
  /** Config. */
  private static final Pattern SLOT_LIST_I_SINGLE =
          Pattern.compile("^i([0-9]+)$");
  /** Config. */
  private static final Pattern SLOT_LIST_I_RANGE =
      Pattern.compile("^i([0-9]+)?-i([0-9]+)?$");

  /**
   * @param s string
   * @return lisy
   */
  public static SlotList fromString(final String s) {
    if (s == null) {
        return null;
    }
    final SlotList sl = new SlotList();
    if (s.trim().isEmpty()) {
        return sl;
    }

    for (String piece : s.split(",")) {
      piece = piece.trim();
      Matcher m;

      // Single entries
      m = SLOT_LIST_SINGLE.matcher(piece);
      // create a range from the first matcher group
      if (m.find()) {
        sl.addRange(m, 1, 1);
        continue;
      }

      m = SLOT_LIST_I_SINGLE.matcher(piece);
      if (m.find()) {
        sl.addIndexRange(m, 1, 1);
        continue;
      }

      // Range entries
      m = SLOT_LIST_RANGE.matcher(piece);
      // create a range from the matcher groups 1 and 2
      if (m.find()) {
        sl.addRange(m, 1, 2);
        continue;
      }

      m = SLOT_LIST_I_RANGE.matcher(piece);
      if (m.find()) {
        sl.addIndexRange(m, 1, 2);
        continue;
      }

      throw new IllegalArgumentException(
          "Invalid syntax of slot number or range: " + piece);
    }

    return sl;
  }


/**
 * @param slot slot
 * @return bool
 */
  public boolean contains(final String slot) {
    final boolean isIndexed = slot.startsWith("i");
    final int number = Integer.valueOf(isIndexed ? slot.substring(1) : slot);
    final TreeSet<Range> tree = (isIndexed ? indexRanges : ranges);

    Range lower = tree.floor(new Range(number, number));
    return lower != null && number <= lower.max;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    // Slot numbers
    for (Range r : ranges) {
      if (r.min != Integer.MIN_VALUE) {
        sb.append(r.min);
      }
      if (r.min != r.max) {
        sb.append('-');
        if (r.max != Integer.MAX_VALUE) {
          sb.append(r.max);
        }
      }
      sb.append(", ");
    }

    // Slot index numbers
    for (Range r : indexRanges) {
      sb.append('i');
      if (r.min != Integer.MIN_VALUE) {
        sb.append(r.min);
      }
      if (r.min != r.max) {
        sb.append("-i");
        if (r.max != Integer.MAX_VALUE) {
          sb.append(r.max);
        }
      }
      sb.append(", ");
    }

    // Remove trailing comma
    if (sb.length() > 1) {
      sb.delete(sb.length() - 2, sb.length());
    }

    return sb.toString();
  }
}
