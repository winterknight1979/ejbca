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

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test the PatternLogger.
 *
 * @version $Id: PatternLoggerTest.java 22139 2015-11-03 10:41:56Z mikekushner $
 */
public class PatternLoggerTest {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(PatternLoggerTest.class);

  /**
   * Try out some interpolation with focus on different date formats.
   *
   * @throws Exception Fail
   */
  @SuppressWarnings("el-syntax")
  @Test
  public void testPatternLoggerDateFormats() throws Exception {
    LOG.trace(">testPatternLogger");
    final String logPattern =
        "${VAR1};\"${VAR2}\";${"
            + IPatternLogger.LOG_TIME
            + "};${"
            + IPatternLogger.LOG_ID
            + "};${VAR3}";
    testPatternLoggerInternal(
        logPattern,
        "yyyy-MM-dd:HH:mm:ss:z",
        "GMT",
        "^content1;\"content2\";\\d{4}-\\d{2}-"
        + "\\d{2}:\\d{2}:\\d{2}:\\d{2}:GMT;0;content3$");
    testPatternLoggerInternal(
        logPattern,
        "yyyy-MM-dd HH:mm:ssZ",
        "CET",
        "^content1;\"content2\";\\d{4}-\\d{2}-\\d{2}"
            + " \\d{2}:\\d{2}:\\d{2}\\+0\\d00;0;content3$");
    testPatternLoggerInternal(
        logPattern,
        "yyyy-MM-dd'T'HH:mm:ssZ",
        "CET",
        "^content1;\"content2\";\\d{4}-\\d{2}-"
        + "\\d{2}T\\d{2}:\\d{2}:\\d{2}\\+0\\d00;0;content3$");
    LOG.trace("<testPatternLogger");
  }

  /**
   * Helper method that replaces all ${VARx} where x={0..10} with "contentx" and
   * asserts that the result is the expected using regexp.
   *
   * @param pattern Pattern
   * @param dateFormat Date
   * @param timeZone TZ
   * @param expected Expected
   * @throws Exception Fail
   */
  private void testPatternLoggerInternal(
      final String pattern, final String dateFormat,
      final String timeZone, final String expected)
      throws Exception {
    LOG.trace(">testPatternLoggerInternal");
    final IPatternLogger patternLogger =
        new PatternLogger(
            Pattern.compile("\\$\\{(.+?)\\}").matcher(pattern),
            pattern,
            LOG,
            dateFormat,
            timeZone);
    for (int i = 0; i < 10; i++) {
      patternLogger.paramPut("VAR" + i, "content" + i);
    }
    // We reference the private method here, which is a bit ugly but works.
    final Method m =
        PatternLogger.class.getDeclaredMethod("interpolate", new Class[0]);
    m.setAccessible(true);
    final String result = (String) m.invoke(patternLogger);
    LOG.debug("result: " + result);
    assertTrue(
        "Result of interpolation operation did not match expected result.",
        result.matches(expected));
    LOG.trace("<testPatternLoggerInternal");
  }
}
