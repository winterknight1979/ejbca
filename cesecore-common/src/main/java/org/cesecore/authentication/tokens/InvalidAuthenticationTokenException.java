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
package org.cesecore.authentication.tokens;

/**
 * Thrown when an invalid AuthenticationToken is encountered.
 *
 * @version $Id: InvalidAuthenticationTokenException.java 17625 2013-09-20
 *     07:12:06Z netmackan $
 */
public class InvalidAuthenticationTokenException extends RuntimeException {

  private static final long serialVersionUID = -8887523864100620342L;

  /** Empty exception. */
  public InvalidAuthenticationTokenException() { }

  /**
   * Exception with message.
   *
   * @param message Message
   */
  public InvalidAuthenticationTokenException(final String message) {
    super(message);
  }

  /**
   * Exception with cause.
   *
   * @param e Cause
   */
  public InvalidAuthenticationTokenException(final Throwable e) {
    super(e);
  }

  /**
   * Exception with message and cause.
   *
   * @param message Message
   * @param e Cause
   */
  public InvalidAuthenticationTokenException(
      final String message, final Throwable e) {
    super(message, e);
  }
}
