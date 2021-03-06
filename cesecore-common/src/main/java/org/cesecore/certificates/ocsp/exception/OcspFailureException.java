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
 * General RuntimeException for OCSP error that can't be handled.
 *
 * @version $Id: OcspFailureException.java 18437 2014-02-03 12:46:08Z
 *     mikekushner $
 */
public class OcspFailureException extends RuntimeException {

  private static final long serialVersionUID = 3024801898030204798L;

  /** Blank. */
  public OcspFailureException() { }

  /** @param msg Message */
  public OcspFailureException(final String msg) {
    super(msg);
  }

  /** @param t cause */
  public OcspFailureException(final Throwable t) {
    super(t);
  }

  /**
   * @param msg message
   * @param t cause
   */
  public OcspFailureException(final String msg, final Throwable t) {
    super(msg, t);
  }
}
