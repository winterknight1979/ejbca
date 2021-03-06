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
package org.ejbca.configdump;

/**
 * @version $Id: ConfigdumpException.java 27953 2018-01-15 15:23:46Z samuellb $
 */
public class ConfigdumpException extends Exception {

  private static final long serialVersionUID = 1L;

  /**
   * Null constructor.
   */
  public ConfigdumpException() {
    super();
  }

  /**
   * @param message message
   */
  public ConfigdumpException(final String message) {
    super(message);
  }

  /**
   * @param cause cause
   */
  public ConfigdumpException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message messafr
   * @param cause cause
   */
  public ConfigdumpException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
