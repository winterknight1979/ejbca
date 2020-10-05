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
package org.cesecore.authorization.user.matchvalues;

/**
 * This runtime exception is thrown to signify that an attempt of an enum to
 * extend the AccessMatchValue interface failed and could not be recovered.
 *
 * @version $Id: InvalidMatchValueException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class InvalidMatchValueException extends RuntimeException {

  private static final long serialVersionUID = -7145630440532075247L;
  /** Bare exception. */
  public InvalidMatchValueException() {
    super();
  }

  /**
   * Exception with message and cause.
   *
   * @param message Message
   * @param cause Cause
   */
  public InvalidMatchValueException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Exception with message.
   *
   * @param message Message
   */
  public InvalidMatchValueException(final String message) {
    super(message);
  }

  /**
   * Exception with cause.
   *
   * @param cause Cause
   */
  public InvalidMatchValueException(final Throwable cause) {
    super(cause);
  }
}
