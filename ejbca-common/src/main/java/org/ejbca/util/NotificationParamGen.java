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

import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.cesecore.util.ValidityDateUtil;

/**
 * Base class generating parameter data for email notifications. Derived classes
 * can add additional parameters.
 *
 * <p>The following parameters are set in this class ${NL} = New Line in message
 * ${DATE} or ${current.DATE} = The current date
 *
 * @version $Id: NotificationParamGen.java 24437 2016-09-29 12:52:09Z anatom $
 */
public class NotificationParamGen {

    /** Prameters. */
  private final HashMap<String, String> params = new HashMap<String, String>();

  /** regexp pattern to match ${identifier} patterns. */
  private static final Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");

  protected NotificationParamGen() {
    paramPut("NL", System.getProperty("line.separator"));
    paramPut("DATE", fastDateFormat(new Date()));
  }

  /**
   * Method used to retrieve the populated parameter HashMap with the
   * notification text.
   *
   * @return params
   */
  public HashMap<String, String> getParams() {
    return params;
  }

  /**
   * method that makes sure that a "" is inserted instead of null.
   *
   * @param key key
   * @param value value
   */
  protected void paramPut(final String key, final String value) {
    if (value == null) {
      params.put(key, "");
    } else {
      params.put(key, value);
    }
  }

  /**
   * method that makes sure that a "" is inserted instead of null.
   *
   * @param key key
   * @param value value
   */
  protected void paramPut(final String key, final Integer value) {
    if (value == null) {
      params.put(key, "");
    } else {
      params.put(key, value.toString());
    }
  }

  // Help method used to populate a message
  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   *
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  public String interpolate(final String input) {
    return interpolate(getParams(), input);
  }

  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   *
   * @param patterns patterns
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  public static String interpolate(
      final HashMap<String, String> patterns, final String input) {
    final Matcher m = PATTERN.matcher(input);
    final StringBuffer sb = new StringBuffer(input.length());
    while (m.find()) {
      // when the pattern is ${identifier}, group 0 is 'identifier'
      String key = m.group(1);
      String value = patterns.get(key);
      // if the pattern does exists, replace it by its value
      // otherwise keep the pattern ( it is group(0) )
      if (value != null) {
        // $ is a group symbol in regexp replacement, see:
        // http://stackoverflow.com/questions/11913709/
          //      why-does-replaceall-fail-with-illegal-group-reference
        // since we can generate passwords etc with $ in them we need to escape
        // $ signs in the value. The same applies for backslash.
        m.appendReplacement(sb, Matcher.quoteReplacement(value));
      } else {
        // I'm doing this to avoid the backreference problem as there will be a
        // $
        // if I replace directly with the group 0 (which is also a pattern)
        m.appendReplacement(sb, "");
        String unknown = m.group(0);
        sb.append(unknown);
      }
    }
    m.appendTail(sb);
    return sb.toString();
  }

  /**
   * @param date date
   * @return format
   */
  protected String fastDateFormat(final Date date) {
    return ValidityDateUtil.formatAsISO8601(
            date, ValidityDateUtil.TIMEZONE_SERVER);
  }
}
