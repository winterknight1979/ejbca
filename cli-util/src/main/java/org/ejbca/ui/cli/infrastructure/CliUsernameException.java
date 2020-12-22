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
package org.ejbca.ui.cli.infrastructure;

/**
 * @version $Id: CliUsernameException.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class CliUsernameException extends Exception {

  private static final long serialVersionUID = -390353232257435050L;

  /** Default constructor. */
  public CliUsernameException() {
    super();
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public CliUsernameException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message Message
   */
  public CliUsernameException(final String message) {
    super(message);
  }
/**
 * @param cause Cause
 */
  public CliUsernameException(final Throwable cause) {
    super(cause);
  }
}
