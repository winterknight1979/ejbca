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

package org.ejbca.core.protocol.ws.logger;

import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.cesecore.util.GUIDGenerator;
import org.ejbca.config.WebServiceConfiguration;
import org.ejbca.util.DummyPatternLogger;
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.PatternLogger;

/**
 * Transaction logger for EJBCA WS with output in DEBUG log level when enabled.
 *
 * @version $Id: TransactionLogger.java 31242 2019-01-17 22:41:24Z jeklund $
 */
public final class TransactionLogger {

      /** Param. */
  private static TransactionLogger instance = null;

  /** regexp pattern to match ${identifier} patterns. */
  // ${DN};${IP}
  private final Pattern pattern =
      Pattern.compile(WebServiceConfiguration.getTransactionLogPattern());

  /** Param. */
  private final String orderString =
      WebServiceConfiguration.getTransactionLogOrder();
  /** Param. */
  private final String logDateFormat =
      WebServiceConfiguration.getTransactionLogDateFormat();
  /** Param. */
  private final String timeZone =
      WebServiceConfiguration.getTransactionLogTimeZone();
  /** Param. */
  private final boolean doLog =
      WebServiceConfiguration.getTransactionLogEnabled();
  /** Param. */
  private final String sessionID = GUIDGenerator.generateGUID(this);
  /** Param. */
  private final Logger log =
      Logger.getLogger(TransactionLogger.class.getName());
  /** Param. */
  private int transactionID = 0;

  private TransactionLogger() { }

  /** @return a new IPatterLogger */
  public static IPatternLogger getPatternLogger() {
    if (instance == null) {
      instance = new TransactionLogger();
    }
    return instance.getNewPatternLogger();
  }

  private IPatternLogger getNewPatternLogger() {
    if (!this.doLog || !this.log.isDebugEnabled()) {
      return new DummyPatternLogger();
    }
    IPatternLogger pl =
        new PatternLogger(
            this.pattern.matcher(this.orderString),
            this.orderString,
            this.log,
            this.logDateFormat,
            this.timeZone);
    pl.paramPut(TransactionTags.ERROR_MESSAGE.toString(), "NO_ERROR");
    pl.paramPut(
        TransactionTags.METHOD.toString(),
        new Throwable().getStackTrace()[2].getMethodName());
    pl.paramPut(IPatternLogger.LOG_ID, Integer.toString(this.transactionID++));
    pl.paramPut(IPatternLogger.SESSION_ID, this.sessionID);
    return pl;
  }
}
