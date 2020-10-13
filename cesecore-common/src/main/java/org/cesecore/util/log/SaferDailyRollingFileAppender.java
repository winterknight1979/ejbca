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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.log4j.DailyRollingFileAppender;
import org.apache.log4j.helpers.LogLog;
import org.apache.log4j.spi.LoggingEvent;

/**
 * The purpose of this extension is to notify the client of the this log
 * appender that it isn't possible to log anymore.
 *
 * @version $Id: SaferDailyRollingFileAppender.java 18195 2013-11-25 08:51:43Z
 *     mikekushner $
 */
public class SaferDailyRollingFileAppender extends DailyRollingFileAppender {
    /** Subscriber. */
  private static SaferAppenderListener subscriber;

  @Override
  public void append(final LoggingEvent evt) {
    super.append(evt);
    File logfile;
    try {
      logfile = new File(super.getFile());
      if ((subscriber != null) && (logfile != null)) {
        if (logfile.canWrite()) {
          subscriber.setCanlog(true);
        } else {
          subscriber.setCanlog(false);
        }
      }
    } catch (Exception e) {
      if (subscriber != null) {
        subscriber.setCanlog(false);
      }
    }
  }

  /**
   * Sets the SaferAppenderListener that will be informed if a logging error
   * occurs.
   *
   * @param pSubscriber subscriber
   */
  public static void addSubscriber(final SaferAppenderListener pSubscriber) {
    subscriber = pSubscriber;
  }

  @Override
  public void setFile(final String filename) {
    constructPath(filename);
    super.setFile(filename);
  }

  private void constructPath(final String filename) {
    File dir;
    try {
      URL url = new URL(filename.trim());
      dir = new File(url.getFile()).getParentFile();
    } catch (MalformedURLException e) {
      dir = new File(filename.trim()).getParentFile();
    }
    if (!dir.exists()) {
      boolean success = dir.mkdirs();
      if (!success) {
        LogLog.error("Failed to create directory structure: " + dir);
      }
    }
  }
}
