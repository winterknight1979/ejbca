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
package org.cesecore.config;

/**
 * Thrown to show that a configuration value was not correctly set.
 *
 * @version $Id: InvalidConfigurationException.java 22764 2016-02-08 14:05:30Z
 *     mikekushner $
 */
public class InvalidConfigurationException extends Exception {

  private static final long serialVersionUID = 2959353827904749328L;

  /** default. */
  public InvalidConfigurationException() { }

  /** @param message message */
  public InvalidConfigurationException(final String message) {
    super(message);
  }

  /** @param cause cause */
  public InvalidConfigurationException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message message
   * @param cause cause
   */
  public InvalidConfigurationException(
          final String message, final Throwable cause) {
    super(message, cause);
  }
}
