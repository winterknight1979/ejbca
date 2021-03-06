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
package org.ejbca.core.ejb.upgrade;

import javax.ejb.ApplicationException;

/**
 * Thrown in case an upgrade routine fails. Should trigger rollback.
 *
 * @version $Id: UpgradeFailedException.java 22019 2015-10-13 23:04:25Z jeklund
 *     $
 */
@ApplicationException(rollback = true)
public class UpgradeFailedException extends Exception {

  private static final long serialVersionUID = -8607042944389555117L;

  /** */
  public UpgradeFailedException() { }

  /** @param message msg */
  public UpgradeFailedException(final String message) {
    super(message);
  }

  /** @param cause cause */
  public UpgradeFailedException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message msh
   * @param cause cause
   */
  public UpgradeFailedException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message msg
   * @param cause cause
   * @param enableSuppression bool
   * @param writableStackTrace bool
   */
  public UpgradeFailedException(
      final String message,
      final Throwable cause,
      final boolean enableSuppression,
      final boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
