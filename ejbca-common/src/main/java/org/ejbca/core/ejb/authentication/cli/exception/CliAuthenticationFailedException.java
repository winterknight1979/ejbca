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
package org.ejbca.core.ejb.authentication.cli.exception;

import javax.ejb.ApplicationException;

/**
 * This exception is thrown if authentication fails during the authorization
 * phase of a CliAuthenticationToken.
 *
 * @version $Id: CliAuthenticationFailedException.java 22117 2015-10-29
 *     10:53:42Z mikekushner $
 */
@ApplicationException(rollback = true)
public class CliAuthenticationFailedException extends Exception {

  private static final long serialVersionUID = 1092700837332116526L;

  /** Null. */
  public CliAuthenticationFailedException() {
    super();
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public CliAuthenticationFailedException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message Message
   */
  public CliAuthenticationFailedException(final String message) {
    super(message);
  }

  /**
   * @param cause Cause
   */
  public CliAuthenticationFailedException(final Throwable cause) {
    super(cause);
  }
}
