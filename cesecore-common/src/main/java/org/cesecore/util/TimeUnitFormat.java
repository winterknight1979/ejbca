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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;

/**
 * Class to parse and format relative time values, i.e. '1y-2mo+3d-4h+5m-6s7ms'.
 *
 * @version $Id: TimeUnitFormat.java 24933 2016-12-20 08:41:57Z mikekushner $
 */
public final class TimeUnitFormat {
  /** Start. */
  private static final String PATTERN_PREFIX = "\\s*(([+-]?\\d+)\\s*(";
  /** End. */
  private static final String PATTERN_SUFFIX = "))\\s*";
  /** Zero. */
  private static final String ZERO = "0";
  /** Space. */
  private static final String SPACE = " ";
  /** Or. */
  private static final String OR = "|";

  /** Error message. */
  private static final String EXCEPTION_MESSAGE_ILLEGAL_CHARACTERS =
      "Illegal characters.";
  /** Error message. */
  private static final String EXCEPTION_MESSAGE_BLANK_STRING =
      "Cannot parse a blank string.";

  /** Pattern. */
  private final Pattern pattern;
  /** Defaults. */
  private final Map<String, Long> defaultValues; // NOPMD
  /** Factors. */
  private final Map<String, Long> factors;
  /** Units. */
  private final List<String> units;

  /**
   * Instantiates a new TimeUnitFormat and initializes it with the given units.
   *
   * @param theUnits List of units
   *     (suffixes, i.e. 'ms', 'mo', 'y', 'd', 'h', 'm', and 's').
   * @param theFactors factors
   */
  public TimeUnitFormat(
      final List<String> theUnits, final Map<String, Long> theFactors) {
    this.units = theUnits;
    this.factors = theFactors;
    this.defaultValues = new LinkedHashMap<String, Long>(theUnits.size());
    final StringBuilder builder = new StringBuilder(PATTERN_PREFIX);
    int index = 0;
    for (String unit : theUnits) {
      this.defaultValues.put(unit.toLowerCase(), 0L);
      if (index++ > 0) {
        builder.append(OR);
      }
      // allows the characters passed in as units. the regexp is compiled with
      // Pattern.CASE_INSENSITIVE below.
      builder.append(Pattern.quote(unit));
    }
    builder.append(PATTERN_SUFFIX);
    pattern = Pattern.compile(builder.toString(), Pattern.CASE_INSENSITIVE);
  }

  /**
   * Parses a formatted time string.
   *
   * @param aformattedString time string, i.e '1y-2mo10d'.
   * @return the milliseconds as long value from 0.
   * @throws NumberFormatException if the string cannot be parsed, i.e. it
   *     contains units not listed or other illegal characters or forms.
   */
  public long parseMillis(final String aformattedString)
          throws NumberFormatException {
    String formattedString = aformattedString;
    long result = 0;
    final int numlength = 3;
    if (StringUtils.isNotBlank(formattedString)) {
      formattedString = formattedString.trim();
      final Matcher matcher = pattern.matcher(formattedString);
      long parsedValue;
      String unit = null;
      int start = 0;
      int end = 0;
      while (matcher.find()) {
        start = matcher.start();
        if (start != end) {
          throw new NumberFormatException(EXCEPTION_MESSAGE_ILLEGAL_CHARACTERS);
        }
        end = matcher.end();
        for (int i = 0; i < matcher.groupCount(); i = i + numlength) {
          parsedValue = Long.parseLong(matcher.group(i + 2));
          unit = matcher.group(i + numlength).toLowerCase();
          result += factors.get(unit) * parsedValue;
        }
      }
      if (end != formattedString.length()) {
        throw new NumberFormatException(EXCEPTION_MESSAGE_ILLEGAL_CHARACTERS);
      }

    } else {
      throw new NumberFormatException(EXCEPTION_MESSAGE_BLANK_STRING);
    }

    return result;
  }

  /**
   * Formats the given period in milliseconds to a readable string.
   *
   * @param millis the milliseconds (count from 0 - not epoch).
   * @param theFactors factors
   * @param zeroType the unit if the result is 0.
   * @return a readable string in form of the ordered value unit pairs (*y *mo
   *     *d *h *m *s), separated by white space character. Milliseconds are
   *     lost.
   */
  public String format(
      final long millis,
      final Map<String, Long> theFactors,
      final String zeroType) {
    long value = millis;
    String unit = null;
    long factor = 0;
    long currentValue = 0;
    final StringBuilder builder = new StringBuilder();
    for (Entry<String, Long> entry : theFactors.entrySet()) {
      unit = entry.getKey();
      if (units.contains(unit)) {
        factor = entry.getValue();
        currentValue = value / factor;
        value %= factor;
        if (currentValue != 0) {
          if (builder.length() > 0) {
            builder.append(SPACE);
          }
          builder.append(Long.toString(currentValue)).append(unit);
        }
      }
    }
    if (builder.length() < 1) {
      builder.append(ZERO).append(zeroType);
    }
    return builder.toString();
  }
}
