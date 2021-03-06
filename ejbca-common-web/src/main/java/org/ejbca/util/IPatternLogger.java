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

/** @version $Id: IPatternLogger.java 25870 2017-05-18 13:39:03Z samuellb $ */
public interface IPatternLogger {
    /** Const. */
   String LOG_TIME =
      "LOG_TIME"; // The Date and time the request.
    /** Const. */
   String LOG_ID =
      "LOG_ID"; // An integer identifying a log entry for a request
    /** Const. */
   String SESSION_ID =
      "SESSION_ID"; // A random 32 bit number identifying a log entry for a
                    // request
  /**
   * REPLY_TIME is a marker that is used to record the total time a request
   * takes to process, including reading the request. It is replaced with the
   * correct value when the log entry is written.
   *
   * @see org.ejbca.util.PatternLogger#flush()
   */
   String REPLY_TIME = "REPLY_TIME";
  /**
   * PROCESS_TIME is a marker that is used to record the total time a request
   * takes to process, excluding reading the request. It is replaced with the
   * correct value when the log entry is written. the time measurement start
   * when this param is set in the logger with:
   *
   * <pre>
   * patternLogger.paramPut(IPatternLogger.PROCESS_TIME,
   * IPatternLogger.PROCESS_TIME);
   * </pre>
   *
   * This means that this variable can be used to measure any time you want to
   * measure in your code.
   *
   * @see org.ejbca.util.PatternLogger#flush()
   */
  String PROCESS_TIME = "PROCESS_TIME";

  /**
   * Hex-encodes the bytes. method that makes sure that a "" is inserted instead
   * of null
   *
   * @param key Key
   * @param value Value
   */
  void paramPut(String key, byte[] value);

  /**
   * method that makes sure that a "" is inserted instead of null.
   *
   * @param key Key
   * @param value Value
   */
  void paramPut(String key, String value);

  /**
   * method that makes sure that a "" is inserted instead of null.
   *
   * @param key Key
   * @param value Value
   */
  void paramPut(String key, Integer value);

  /** Method used for creating a log row of all added values. */
  void writeln();

  /** Writes all the rows created by writeln() to the Logger. */
  void flush();
}
