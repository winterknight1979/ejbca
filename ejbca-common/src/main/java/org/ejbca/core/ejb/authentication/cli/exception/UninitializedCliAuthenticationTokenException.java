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

/**
 * An exception thrown when a CliAuthenticationToken is used without having its
 * password field set.
 *
 * @version $Id: UninitializedCliAuthenticationTokenException.java 22117
 *     2015-10-29 10:53:42Z mikekushner $
 */
public class UninitializedCliAuthenticationTokenException
    extends RuntimeException {

  private static final long serialVersionUID = -3404632335972154544L;

  /** Null. */
  public UninitializedCliAuthenticationTokenException() {
    super();
  }

  /**
   * @param arg0 Message
   * @param arg1 Cause
   */
  public UninitializedCliAuthenticationTokenException(
      final String arg0, final Throwable arg1) {
    super(arg0, arg1);
  }

  /**
   * @param arg0 Message
   */
  public UninitializedCliAuthenticationTokenException(final String arg0) {
    super(arg0);
  }

  /**
   * @param arg0 Cause
   */
  public UninitializedCliAuthenticationTokenException(final Throwable arg0) {
    super(arg0);
  }
}
