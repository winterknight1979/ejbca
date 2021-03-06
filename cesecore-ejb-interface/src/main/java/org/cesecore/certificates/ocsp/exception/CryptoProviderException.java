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
 * A exception wrapper to cover different BouncyCastle provider errors.
 *
 * @version $Id: CryptoProviderException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class CryptoProviderException extends RuntimeException {

  private static final long serialVersionUID = -3334600937753128052L;

  /** Null constructor. */
  public CryptoProviderException() {
    super();
  }

  /**
   * @param msg message
   * @param t cause
   */
  public CryptoProviderException(final String msg, final Throwable t) {
    super(msg, t);
  }

  /**
   * @param msg message
   */
  public CryptoProviderException(final String msg) {
    super(msg);
  }

  /**
   * @param msg Cause
   */
  public CryptoProviderException(final Throwable msg) {
    super(msg);
  }
}
