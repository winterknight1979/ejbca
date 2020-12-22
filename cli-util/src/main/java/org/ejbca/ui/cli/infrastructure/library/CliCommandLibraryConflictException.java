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
package org.ejbca.ui.cli.infrastructure.library;

/**
 * Exception thrown when trying to construct a CLI command library and a
 * conflict occurs, i.e the commands $ ra &lt;params&gt; $ ra adduser
 * &lt;params&gt; both exist in the same command set.
 *
 * @version $Id: CliCommandLibraryConflictException.java 19902 2014-09-30
 *     14:32:24Z anatom $
 */
public class CliCommandLibraryConflictException extends RuntimeException {

  private static final long serialVersionUID = 3697467436872840222L;

  /** Default. */
  public CliCommandLibraryConflictException() {
    super();
  }

  /**
   * @param message message
   * @param cause Cause
   */
  public CliCommandLibraryConflictException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message Message
   */
  public CliCommandLibraryConflictException(final String message) {
    super(message);
  }
/**
 * @param cause Cause
 */
  public CliCommandLibraryConflictException(final Throwable cause) {
    super(cause);
  }
}
