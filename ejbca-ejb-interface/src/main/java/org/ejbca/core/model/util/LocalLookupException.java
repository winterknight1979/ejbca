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
package org.ejbca.core.model.util;

/**
 * Thrown in case a local lookup fails.
 *
 * @version $Id: LocalLookupException.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class LocalLookupException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  /** Default. */
  public LocalLookupException() {
    super();
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public LocalLookupException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message message
   */
  public LocalLookupException(final String message) {
    super(message);
  }

  /**
   * @param cause cause
   */
  public LocalLookupException(final Throwable cause) {
    super(cause);
  }
}
