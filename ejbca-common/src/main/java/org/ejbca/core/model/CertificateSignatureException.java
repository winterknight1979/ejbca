/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model;

/**
 * Thrown to show that the signature of an certificate failed to verify somehow.
 *
 * @version $Id: CertificateSignatureException.java 24890 2016-12-13 13:57:17Z
 *     mikekushner $
 */
public class CertificateSignatureException extends Exception {

  private static final long serialVersionUID = 1L;

  /** @param message message */
  public CertificateSignatureException(final String message) {
    super(message);
  }

  /** @param cause cause */
  public CertificateSignatureException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message message
   * @param cause cause
   */
  public CertificateSignatureException(
      final String message, final Throwable cause) {
    super(message, cause);
  }
}
