/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.mail;

/**
 * Generic exception for mail handling.
 *
 * @version $Id: MailException.java 26387 2017-08-22 14:14:36Z mikekushner $
 */
public class MailException extends Exception {

  private static final long serialVersionUID = 1L;

  /** */
  public MailException() { }

  /** @param message message */
  public MailException(final String message) {
    super(message);
  }

  /** @param cause cause */
  public MailException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message message
   * @param cause cause
   */
  public MailException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
