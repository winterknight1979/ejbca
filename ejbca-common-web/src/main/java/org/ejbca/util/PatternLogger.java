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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class can be extended to create highly configurable log classes. Values
 * that are to be logged are stored in a HashMap and the output is configured
 * using a Java.util.regex.Matcher and a sortString. The extending classes also
 * need to supply a Logger and a String specifying how to log Dates.
 *
 * <p>Use paramPut(String key, String value) to add values, Use writeln() to log
 * all the stored values and then use flush() to store them to file.
 *
 * @author thamwickenberg
 * @version $Id: PatternLogger.java 25870 2017-05-18 13:39:03Z samuellb $
 */
public class PatternLogger implements IPatternLogger {

      /** Param. */
  private final Map<String, String> valuepairs = new HashMap<>();
  /** Param. */
  private final StringWriter sw = new StringWriter();
  /** Param. */
  private final PrintWriter pw = new PrintWriter(this.sw);
  /** Param. */
  private final Matcher m;
  /** Param. */
  private final String orderString;
  /** Param. */
  private final Logger logger;
  /** Param. */
  private final Date startTime;
  /** Param. */
  private Date startProcessTime = null;

  /**
   * @param am A matcher that is used together with orderstring to determine how
   *     output is formatted
   * @param anorderString A string that matches the pattern in m and
   * specifies the
   *     order in which values are logged by the logger
   * @param alogger A log4j Logger that is used for output
   * @param logDateFormat A string that specifies how the log-time is formatted
   * @param timeZone TZ
   */
  public PatternLogger(
      final Matcher am,
      final String anorderString,
      final Logger alogger,
      final String logDateFormat,
      final String timeZone) {
    this.m = am;
    this.orderString = anorderString;
    this.logger = alogger;
    this.startTime = new Date();
    final FastDateFormat dateformat;
    if (timeZone == null) {
      dateformat = FastDateFormat.getInstance(logDateFormat);
    } else {
      dateformat =
          FastDateFormat.getInstance(
              logDateFormat, TimeZone.getTimeZone(timeZone));
    }
    paramPut(LOG_TIME, dateformat.format(new Date()));
    this.paramPut(REPLY_TIME, REPLY_TIME);
    this.paramPut(LOG_ID, "0");
  }

  /** @return output to be logged */
  private String interpolate() {
    final StringBuffer sb = new StringBuffer(this.orderString.length());
    this.m.reset();
    while (this.m.find()) {
      // when the pattern is ${identifier}, group 0 is 'identifier'
      final String key = this.m.group(1);
      final String value = this.valuepairs.get(key);

      // if the pattern does exists, replace it by its value
      // otherwise keep the pattern ( it is group(0) )
      if (value != null) {
        this.m.appendReplacement(sb, value);
      } else {
        // I'm doing this to avoid the backreference problem as there will be a
        // $
        // if I replace directly with the group 0 (which is also a pattern)
        this.m.appendReplacement(sb, "");
        final String unknown = this.m.group(0);
        sb.append(unknown);
      }
    }
    this.m.appendTail(sb);
    return sb.toString();
  }

  /** @see IPatternLogger#paramPut(String, byte[]) */
  @Override
  public void paramPut(final String key, final byte[] value) {
    paramPut(key, new String(Hex.encode(value)));
  }

  /** @see IPatternLogger#paramPut(String, String) */
  @Override
  public void paramPut(final String key, final String value) {
    // logger.debug("paramput: "+ key+ ";" +value +";" +valuepairs.toString());
    if (value == null) {
      this.valuepairs.put(key, "");
    } else {
      this.valuepairs.put(key, value);
    }
    if (StringUtils.equals(key, IPatternLogger.PROCESS_TIME)) {
      startProcessTime = new Date();
    }
  }

  /** @see IPatternLogger#paramPut(String, Integer) */
  @Override
  public void paramPut(final String key, final Integer value) {
    if (value == null) {
      this.valuepairs.put(key, "");
    } else {
      this.valuepairs.put(key, value.toString());
    }
  }

  /** @see IPatternLogger#writeln() */
  @Override
  public void writeln() {
    this.pw.println(interpolate());
  }

  /** @see org.ejbca.util.IPatternLogger#flush() */
  @Override
  public void flush() {
    this.pw.flush();
    String output = this.sw.toString();
    output =
        output.replaceAll(
            IPatternLogger.REPLY_TIME,
            String.valueOf(new Date().getTime() - this.startTime.getTime()));
    if (startProcessTime != null) {
      output =
          output.replaceAll(
              IPatternLogger.PROCESS_TIME,
              String.valueOf(
                  new Date().getTime() - this.startProcessTime.getTime()));
    }
    this.logger.debug(
        output); // Finally output the log row to the logging device
  }
}
