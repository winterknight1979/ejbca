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
package org.cesecore.certificates.ocsp.exception;

/**
 * Thrown when an error is encountered while starting OCSP.
 *
 * @version $Id: OcspInitializationException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class OcspInitializationException extends RuntimeException {

  private static final long serialVersionUID = -7920696456058508107L;
 /** Null constructor. */
  public OcspInitializationException() {
    super();
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public OcspInitializationException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message Message
   */
  public OcspInitializationException(final String message) {
    super(message);
  }

  /**
   * @param cause Cause
   */
  public OcspInitializationException(final Throwable cause) {
    super(cause);
  }
}
