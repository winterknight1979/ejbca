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
package org.cesecore.authorization.user;

/**
 * Thrown when an AccessUserAspect is not found.
 *
 * @version $Id: AccessUserAspectNotFoundException.java 25461 2017-03-14
 *     00:10:54Z jeklund $
 */
public class AccessUserAspectNotFoundException extends RuntimeException {

  private static final long serialVersionUID = -3503860340121024920L;

  /** Bare exception. */
  public AccessUserAspectNotFoundException() {
    super();
  }

  /**
   * Exception with messsage and cause.
   *
   * @param message Message
   * @param cause Cause
   */
  public AccessUserAspectNotFoundException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Exception with message.
   *
   * @param message Message
   */
  public AccessUserAspectNotFoundException(final String message) {
    super(message);
  }

  /**
   * Exception with cause.
   *
   * @param cause cause
   */
  public AccessUserAspectNotFoundException(final Throwable cause) {
    super(cause);
  }
}
