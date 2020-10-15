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
package org.cesecore.time.providers;

/**
 * This exception should be used on TrustedTime provider errors.
 *
 * @version $Id: TrustedTimeProviderException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class TrustedTimeProviderException extends Exception {

  private static final long serialVersionUID = -7860047748193141529L;

  /** @see Exception#Exception() */
  public TrustedTimeProviderException() {
    super();
  }

  /**
   * @param message message
   * @see Exception#Exception(String)
   */
  public TrustedTimeProviderException(final String message) {
    super(message);
  }

  /**
   * @param message message
   * @param cause cause
   * @see Exception#Exception(String,Throwable)
   */
  public TrustedTimeProviderException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param cause cause
   * @see Exception#Exception(Throwable)
   */
  public TrustedTimeProviderException(final Throwable cause) {
    super(cause);
  }
}
