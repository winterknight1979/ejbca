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

package org.cesecore.util.log;

import java.io.PrintStream;
import java.util.Date;
import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

/**
 * The purpose of this errorhandler is that we can still respond with
 * InternalServer error if and error occurs, but repeated errors will only be
 * logged once.
 *
 * @version $Id: ProbableErrorHandler.java 17647 2013-09-20 14:02:02Z netmackan
 *     $
 */
public class ProbableErrorHandler implements ErrorHandler {
    /** date,. */
  private static Date lastFailure = null;

  /** Warning. */
  @SuppressWarnings("unused")
private static final String WARN_PREFIX = "log4j warning: ";
  /** Error. */
  private static final String ERROR_PREFIX = "log4j error: ";

  /** Bool. */
  private boolean firstTime = true;

  /**
   * Output.
   */
  private static PrintStream output = System.err;

  @Override
  public void error(final String arg0) {
    if (firstTime) {
      output.println(ERROR_PREFIX + arg0);
      firstTime = false;
    }
    lastFailure = new Date();
  }

  @Override
  public void error(final String arg0, final Exception arg1, final int arg2) {
    error(arg0, arg1, arg2, null);
    lastFailure = new Date();
  }

  @Override
  public void error(
          final String arg0,
          final Exception arg1,
          final int arg2,
          final LoggingEvent arg3) {
    if (firstTime) {
      output.println(ERROR_PREFIX + arg0);
      arg1.printStackTrace(output);
      firstTime = false;
    }
    lastFailure = new Date();
  }

  /**
   * Returns true if an error writing to the log files have happened since
   * 'date'.
   *
   * @param date see if an error happened later than this date
   * @return true if an error has happened, false if logging works fine.
   */
  public static boolean hasFailedSince(final Date date) {
    if (lastFailure != null) {
      if (lastFailure.after(date)) {
        return true;
      }
    }
    return false;
  }

  /** Does not do anything. */
  @Override
  public void setLogger(final Logger logger) { }

  /** Does not do anything. */
  @Override
  public void setAppender(final Appender appender) { }

  /** Does not do anything. */
  @Override
  public void setBackupAppender(final Appender appender) { }
}
