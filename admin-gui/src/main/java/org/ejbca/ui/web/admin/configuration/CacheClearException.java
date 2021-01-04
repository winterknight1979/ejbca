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
package org.ejbca.ui.web.admin.configuration;

/**
 * Thrown as a result of clearing the caches from the UI failing.
 *
 * @version $Id: CacheClearException.java 22945 2016-03-09 13:32:20Z mikekushner
 *     $
 */
public class CacheClearException extends Exception {

  private static final long serialVersionUID = 1L;

  /** */
  public CacheClearException() {}

  /** @param message message */
  public CacheClearException(final String message) {
    super(message);
  }

  /** @param cause Cause */
  public CacheClearException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public CacheClearException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
