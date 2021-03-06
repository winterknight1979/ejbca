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
package org.ejbca.util.owaspcsrfguard;

import org.apache.log4j.Logger;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;

/**
 * A logging class for the OWASP CSRF Guard filter.
 * https://www.owasp.org/index.php/Csrfguard We need a custom logger because it
 * is not possible to configure CSRFguard at what level it shold log, so we
 * filter on our own here.
 *
 * @version $Id: JavaLogger.java 25077 2017-01-21 09:13:57Z anatom $
 */
public class JavaLogger implements ILogger {

  private static final long serialVersionUID = -4857601483759096197L;

  /** Loig. */
  private static final Logger LOG = Logger.getLogger(JavaLogger.class);

  @Override
  public void log(final String msg) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(msg.replaceAll("(\\r|\\n)", ""));
    }
  }

  @Override
  public void log(final LogLevel level, final String msg) {
    // Remove CR and LF characters to prevent CRLF injection
    String sanitizedMsg = msg.replaceAll("(\\r|\\n)", "");

    // We don't want to spam the EJBCA log with OWASP stuff, so we'll log
    // everything that are not warning or error at Trace level
    switch (level) {
      case Trace:
        if (LOG.isTraceEnabled()) {
          LOG.trace(sanitizedMsg);
        }
        break;
      case Debug:
        if (LOG.isTraceEnabled()) {
          LOG.trace(sanitizedMsg);
        }
        break;
      case Info:
        if (LOG.isTraceEnabled()) {
          LOG.trace(sanitizedMsg);
        }
        break;
      case Warning:
        LOG.warn(sanitizedMsg);
        break;
      case Error:
        LOG.warn(sanitizedMsg);
        break;
      case Fatal:
        LOG.error(sanitizedMsg);
        break;
      default:
        throw new RuntimeException("unsupported log level " + level);
    }
  }

  @Override
  public void log(final Exception exception) {
    LOG.warn(exception.getLocalizedMessage(), exception);
  }

  @Override
  public void log(final LogLevel level, final Exception exception) {
    // We don't want to spam the EJBCA log with OWASP stuff, so we'll log
    // everything that are not warning or error at Trace level
    switch (level) {
      case Trace:
        if (LOG.isTraceEnabled()) {
          LOG.trace(exception.getLocalizedMessage(), exception);
        }
        break;
      case Debug:
        if (LOG.isTraceEnabled()) {
          LOG.trace(exception.getLocalizedMessage(), exception);
        }
        break;
      case Info:
        if (LOG.isTraceEnabled()) {
          LOG.trace(exception.getLocalizedMessage(), exception);
        }
        break;
      case Warning:
        LOG.warn(exception.getLocalizedMessage(), exception);
        break;
      case Error:
        LOG.warn(exception.getLocalizedMessage(), exception);
        break;
      case Fatal:
        LOG.error(exception.getLocalizedMessage(), exception);
        break;
      default:
        throw new IllegalArgumentException("unsupported log level " + level);
    }
  }
}
