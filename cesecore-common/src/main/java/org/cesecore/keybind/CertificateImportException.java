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
package org.cesecore.keybind;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * An exception thrown when someone tries to import a certificate and an error
 * occurs. Not restricted to key binding imort, but kept in this package for
 * backwards compatibility reasons.
 *
 * @version $Id: CertificateImportException.java 25404 2017-03-07 08:43:40Z
 *     anatom $
 */
public class CertificateImportException extends CesecoreException {

  private static final long serialVersionUID = 1L;
  /** Code. */
  public static final ErrorCode CERTIFICATE_IMPORT =
      ErrorCode.CERTIFICATE_IMPORT;

  /**
   * Creates a new instance of <code>CertificateImportException</code> without
   * detail message.
   */
  public CertificateImportException() {
    super(CERTIFICATE_IMPORT);
  }

  /**
   * Constructs an instance of <code>CertificateImportException</code> with the
   * specified detail message.
   *
   * @param msg the detail message.
   */
  public CertificateImportException(final String msg) {
    super(CERTIFICATE_IMPORT, msg);
  }

  /**
   * Constructs an instance of <code>CertificateImportException</code> with the
   * specified detail message.
   *
   * @param exception the exception that caused this
   */
  public CertificateImportException(final Exception exception) {
    super(CERTIFICATE_IMPORT, exception);
  }

  /**
   * Constructs an instance of <code>CertificateImportException</code> with the
   * specified detail message.
   *
   * @param msg the detail message.
   * @param e the exception that caused this
   */
  public CertificateImportException(final String msg, final Exception e) {
    super(CERTIFICATE_IMPORT, msg, e);
  }
}
