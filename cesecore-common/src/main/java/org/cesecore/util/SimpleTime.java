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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;

/**
 * Helper class for handling user friendly format of time intervals.
 *
 * <p>The format is in the form 'y* mo* *d *h *m *s *ms' where * is a decimal
 * number and d=days, h=hours, m=minutes, s=seconds, ms=milliseconds. Spaces are
 * optional.
 *
 * @version $Id: SimpleTime.java 24744 2016-11-15 14:36:16Z anatom $
 */
public final class SimpleTime {

      /** Config. */
  public static final long MILLISECONDS_PER_YEAR = 31536000000L; // 365 days
  /** Config. */
  public static final long MILLISECONDS_PER_MONTH = 2592000000L; // 30 days
  /** Config. */
  public static final long MILLISECONDS_PER_DAY = 86400000L;
  /** Config. */
  public static final long MILLISECONDS_PER_HOUR = 3600000L;
  /** Config. */
  public static final long MILLISECONDS_PER_MINUTE = 60000L;
  /** Config. */
  public static final long MILLISECONDS_PER_SECOND = 1000L;

  /** Config. */
  public static final String TYPE_YEARS = "y";
  /** Config. */
  public static final String TYPE_MONTHS = "mo";
  /** Config. */
  public static final String TYPE_DAYS = "d";
  /** Config. */
  public static final String TYPE_HOURS = "h";
  /** Config. */
  public static final String TYPE_MINUTES = "m";
  /** Config. */
  public static final String TYPE_SECONDS = "s";
  /** Config. */
  public static final String TYPE_MILLISECONDS = "ms";
  /** MS. */
  public static final String PRECISION_MILLISECONDS = "milliseconds";
  /** Secs. */
  public static final String PRECISION_SECONDS = "seconds";
  /** Days. */
  public static final String PRECISION_DAYS = "days";

  /** Lost. */
  public static final List<String> AVAILABLE_PRECISIONS =
      Arrays.asList(
          new String[] {
            PRECISION_MILLISECONDS, PRECISION_SECONDS, PRECISION_DAYS
          });

  /** Map. */
  private static final Map<String, Long> MILLISECONDS_FACTOR =
      new LinkedHashMap<String, Long>();

  static {
    MILLISECONDS_FACTOR.put(TYPE_YEARS, MILLISECONDS_PER_YEAR);
    MILLISECONDS_FACTOR.put(TYPE_MONTHS, MILLISECONDS_PER_MONTH);
    MILLISECONDS_FACTOR.put(TYPE_DAYS, MILLISECONDS_PER_DAY);
    MILLISECONDS_FACTOR.put(TYPE_HOURS, MILLISECONDS_PER_HOUR);
    MILLISECONDS_FACTOR.put(TYPE_MINUTES, MILLISECONDS_PER_MINUTE);
    MILLISECONDS_FACTOR.put(TYPE_SECONDS, MILLISECONDS_PER_SECOND);
    MILLISECONDS_FACTOR.put(TYPE_MILLISECONDS, 1L);
  }

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(SimpleTime.class);

  /** Format. */
  private static final TimeUnitFormat DAYS_FORMAT_INSTANCE =
      new TimeUnitFormat(
          Arrays.asList(new String[] {TYPE_YEARS, TYPE_MONTHS, TYPE_DAYS}),
          MILLISECONDS_FACTOR);

  /** Format. */
  private static final TimeUnitFormat SECONDS_FORMAT_INSTANCE =
      new TimeUnitFormat(
          Arrays.asList(
              new String[] {
                TYPE_YEARS,
                TYPE_MONTHS,
                TYPE_DAYS,
                TYPE_HOURS,
                TYPE_MINUTES,
                TYPE_SECONDS
              }),
          MILLISECONDS_FACTOR);

  /** Limitation 'ms' (or 'mo') MUST NOT be configured
   * after units containing one
     of their characters 'm', 's' or 'o'! */
  private static final TimeUnitFormat MILLISECONDS_FORMAT_INSTANCE =
      new TimeUnitFormat(
          Arrays.asList(
              new String[] {
                TYPE_MILLISECONDS,
                TYPE_YEARS,
                TYPE_MONTHS,
                TYPE_DAYS,
                TYPE_HOURS,
                TYPE_MINUTES,
                TYPE_SECONDS
              }),
          MILLISECONDS_FACTOR);

  /** Long. */
  private long longTime = 0;
  /** Y. */
  private long years = 0;
  /** M. */
  private long months = 0;
  /** D. */
  private long days = 0;
  /** h. */
  private long hours = 0;
  /** m. */
  private long minutes = 0;
  /** s. */
  private long seconds = 0;
  /** MS.*/
  private long milliSeconds = 0;

  /** @param time milliseconds */
  private SimpleTime(final long time) {
    setTime(time);
  }

  /**
   * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E
   *     milliseconds
   * @throws Exception if unable to parse a String
   */
  private SimpleTime(final String time) throws Exception {
    setTime(parseMillies(time));
  }

  /**
   * @param otime AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E
   *     milliseconds
   * @param defaultTime AdBhCmDsEu meaning A days, B hours, C minutes, D seconds
   *     and E milliseconds
   * @throws Exception if unable to parse a String
   */
  private SimpleTime(
          final String otime, final String defaultTime) throws Exception {
      String time = otime;
    if (time == null || time.trim().length() == 0) {
      time = defaultTime;
    }
    setTime(parseMillies(time));
  }

  /**
   * Get new instance of class.
   *
   * @param time milliseconds
   * @return new instance of class
   */
  public static SimpleTime getInstance(final long time) {
    return new SimpleTime(time);
  }

  /**
   * Get new instance of class.
   *
   * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E
   *     milliseconds
   * @return new instance of class or null if there were errors
   */
  public static SimpleTime getInstance(final String time) {
    SimpleTime simpleTime = null;
    try {
      simpleTime = new SimpleTime(time);
    } catch (Exception e) {
      LOG.info("Failed to parse time \"" + time + "\". " + e.getMessage());
    }
    return simpleTime;
  }

  /**
   * Get new instance of class.
   *
   * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E
   *     milliseconds
   * @param defaultTime AdBhCmDsEu meaning A days, B hours, C minutes, D seconds
   *     and E milliseconds
   * @return new instance of class or null if there were errors
   */
  public static SimpleTime getInstance(
          final String time, final String defaultTime) {
    SimpleTime simpleTime = null;
    try {
      simpleTime = new SimpleTime(time, defaultTime);
    } catch (Exception e) {
      LOG.info(
          "Failed to parse time or defaultTime \""
              + time
              + "\", \""
              + defaultTime
              + "\". "
              + e.getMessage());
    }
    return simpleTime;
  }

  /**
   * Gets the time unit formatter with the default formatting style for days
   * (with year(y), months (mo) and days (d)).
   *
   * @return a time unit formatter.
   */
  public static TimeUnitFormat getDaysFormat() {
    return DAYS_FORMAT_INSTANCE;
  }

  /**
   * Gets the time unit formatter with the default formatting style for seconds
   * (with year(y), months (mo), days (d), hours (h), minutes (m) and seconds
   * (s)).
   *
   * @return a time unit formatter.
   */
  public static TimeUnitFormat getSecondsFormat() {
    return SECONDS_FORMAT_INSTANCE;
  }

  /**
   * Gets the time unit formatter with the default formatting style for
   * milliseconds (with year(y), months (mo), days (d), hours (h), minutes (m),
   * seconds (s) and milliseconds (ms)).
   *
   * @return a time unit formatter.
   */
  public static TimeUnitFormat getMilliSecondsFormat() {
    return MILLISECONDS_FORMAT_INSTANCE;
  }

  /**
   * Gets the TimeUnitFormat by precision.
   *
   * @param precision precision
   * @return the TimeUnitFormat with the desired precision if existent.
   * @throws IllegalArgumentException if invalid args
   * @see SimpleTime#AVAILABLE_PRECISIONS
   */
  public static TimeUnitFormat getTimeUnitFormatOrThrow(
      final String precision) throws IllegalArgumentException {
    TimeUnitFormat result = null;
    if (!AVAILABLE_PRECISIONS.contains(precision)) {
      throw new IllegalArgumentException(
          "Could not get TimeUnitForm for precision: " + precision);
    }
    switch (precision) {
      case SimpleTime.PRECISION_MILLISECONDS:
        result = SimpleTime.getMilliSecondsFormat();
        break;
      case SimpleTime.PRECISION_SECONDS:
        result = SimpleTime.getSecondsFormat();
        break;
      case SimpleTime.PRECISION_DAYS:
        result = SimpleTime.getDaysFormat();
        break;
      default:
        result = SimpleTime.getSecondsFormat();
        break;
    }
    return result;
  }

  /**
   * @param millis MS
   * @param zeroType Zero
   * @return string
   */
  public static String toString(
      final long millis, final String zeroType) {
    return SimpleTime.getMilliSecondsFormat()
        .format(millis, MILLISECONDS_FACTOR, zeroType);
  }

  /**
   * @param time MS
   * @return time
   * @throws NumberFormatException fail
   */
  public static long parseMillies(final String time)
      throws NumberFormatException {
    return SimpleTime.getMilliSecondsFormat().parseMillis(time);
  }

  private void setTime(final long otime) {
    long time = otime;
    longTime = time;
    years = time / MILLISECONDS_PER_YEAR;
    time %= MILLISECONDS_PER_YEAR;
    months = time / MILLISECONDS_PER_MONTH;
    time %= MILLISECONDS_PER_MONTH;
    days = time / MILLISECONDS_PER_DAY;
    time %= MILLISECONDS_PER_DAY;
    hours = time / MILLISECONDS_PER_HOUR;
    time %= MILLISECONDS_PER_HOUR;
    minutes = time / MILLISECONDS_PER_MINUTE;
    time %= MILLISECONDS_PER_MINUTE;
    seconds = time / MILLISECONDS_PER_SECOND;
    time %= MILLISECONDS_PER_SECOND;
    milliSeconds = time;
  }

  /**
   * Get the total number of milliseconds for this time (including days, hours
   * etc).
   *
   * @return ms
   */
  public long getLong() {
    return longTime;
  }

  /**
   * @return Y
   */
  public long getYears() {
    return years;
  }

  /**
   * @return M
   */
  public long getMonths() {
    return months;
  }

  /**
   * @return D
   */
  public long getDays() {
    return days;
  }

  /**
   * @return h
   */
  public long getHours() {
    return hours;
  }

  /**
   * @return m
   */
  public long getMinutes() {
    return minutes;
  }

  /**
   * @return s
   */
  public long getSeconds() {
    return seconds;
  }

  /**
   * @return ms
   */
  public long getMilliSeconds() {
    return milliSeconds;
  }

  /**
   * Get nicely formatted form of this object using seconds as default type.
   *
   * @return time in the format AdBhCmDsEu meaning A days, B hours, C minutes, D
   *     seconds and E milliseconds or "0s" if time is 0.
   */
  public String toString() {
    return toString(TYPE_SECONDS);
  }

  /**
   * @param zeroType the type of the returned value if '0'. One of the
   *     SimpleType.TYPE_ constants.
   * @return time in the format AdBhCmDsEu meaning A days, B hours, C minutes, D
   *     seconds and E milliseconds
   */
  public String toString(final String zeroType) {
    return SimpleTime.getMilliSecondsFormat()
        .format(getLong(), MILLISECONDS_FACTOR, zeroType);
  }
}
