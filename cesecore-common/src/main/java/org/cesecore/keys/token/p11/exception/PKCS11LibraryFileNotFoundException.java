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
package org.cesecore.keys.token.p11.exception;

import org.cesecore.keys.token.CryptoTokenOfflineException; // NOPMD: jdoc

/**
 * Thrown to signify that a slot was not found. Differs from {@link
 * CryptoTokenOfflineException} by virtue of the latter being thrown when a slot
 * exists, but for some reason is unavailable.
 *
 * @version $Id: PKCS11LibraryFileNotFoundException.java 26057 2017-06-22
 *     08:08:34Z anatom $
 */
public class PKCS11LibraryFileNotFoundException extends Exception {

  private static final long serialVersionUID = 471712760739840779L;
 /** Default. */
  public PKCS11LibraryFileNotFoundException() {
    super();
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public PKCS11LibraryFileNotFoundException(
          final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message Message
   */
  public PKCS11LibraryFileNotFoundException(final String message) {
    super(message);
  }

  /**
   * @param cause Cause
   */
  public PKCS11LibraryFileNotFoundException(final Throwable cause) {
    super(cause);
  }
}
