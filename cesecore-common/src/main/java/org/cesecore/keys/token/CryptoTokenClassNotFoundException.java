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
package org.cesecore.keys.token;

/**
 * Thrown when trying to instantiate an unknown crypto token class.
 *
 * @version $Id: CryptoTokenClassNotFoundException.java 20648 2015-02-10
 *     14:19:39Z aveen4711 $
 */
public class CryptoTokenClassNotFoundException extends RuntimeException {

  private static final long serialVersionUID = -7935523503522491237L;

  /** default. */
  public CryptoTokenClassNotFoundException() {
    super();
  }

  /**
   * @param message message
   * @param cause cause
   */
  public CryptoTokenClassNotFoundException(
          final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message message
   */
  public CryptoTokenClassNotFoundException(final String message) {
    super(message);
  }

  /**
   * @param cause cause
   */
  public CryptoTokenClassNotFoundException(final Throwable cause) {
    super(cause);
  }
}
