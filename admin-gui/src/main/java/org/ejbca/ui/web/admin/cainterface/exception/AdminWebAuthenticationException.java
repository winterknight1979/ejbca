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
package org.ejbca.ui.web.admin.cainterface.exception;

/**
 * Exception for authentication failures in AdminWeb servlets.
 *
 * <p>The message, but not the stacktrace, should be sent to the client.
 *
 * @version $Id: AdminWebAuthenticationException.java 34154 2019-12-23 13:38:17Z
 *     samuellb $
 */
public final class AdminWebAuthenticationException extends Exception {

  private static final long serialVersionUID = 1L;

  /** @param message Message, will be sent to client. */
  public AdminWebAuthenticationException(final String message) {
    super(message);
  }

  /**
   * @param message Message, will be sent to client.
   * @param cause Cause of exception. Stacktrace will NOT be sent to client.
   */
  public AdminWebAuthenticationException(
      final String message, final Throwable cause) {
    super(message, cause);
  }
}
