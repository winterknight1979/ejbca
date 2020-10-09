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
package org.cesecore.keys.token.p11.exception;

import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Thrown to signify that a slot was not found. Differs from {@link
 * CryptoTokenOfflineException} by virtue of the latter being thrown when a slot
 * exists, but for some reason is unavailable.
 *
 * @version $Id: NoSuchSlotException.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class NoSuchSlotException extends Exception {

  private static final long serialVersionUID = -1943802946146748726L;

  /** Default. */
  public NoSuchSlotException() {
    super();
  }

  /**
   * @param message message
   * @param cause cause
   */
  public NoSuchSlotException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message message
   */
  public NoSuchSlotException(final String message) {
    super(message);
  }

  /**
   * @param cause Cause
   */
  public NoSuchSlotException(final Throwable cause) {
    super(cause);
  }
}
