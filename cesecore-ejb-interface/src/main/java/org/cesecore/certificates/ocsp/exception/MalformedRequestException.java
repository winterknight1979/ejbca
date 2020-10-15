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
 * Thrown when a byte array couldn't be formed into a proper OCSP request.
 *
 * @version $Id: MalformedRequestException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class MalformedRequestException extends Exception {

  private static final long serialVersionUID = -6603931681530067622L;
  /** Null constructor. */
  public MalformedRequestException() { }

  /** @param arg0 Message */
  public MalformedRequestException(final String arg0) {
    super(arg0);
  }

  /** @param arg0 Cause */
  public MalformedRequestException(final Throwable arg0) {
    super(arg0);
  }

  /**
   * @param arg0 Message
   * @param arg1 Cause
   */
  public MalformedRequestException(final String arg0, final Throwable arg1) {
    super(arg0, arg1);
  }
}
