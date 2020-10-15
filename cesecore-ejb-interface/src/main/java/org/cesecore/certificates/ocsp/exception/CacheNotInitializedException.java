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
 * This exception is thrown in the case that a cache is accessed before it is
 * initialized.
 *
 * @version $Id: CacheNotInitializedException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class CacheNotInitializedException extends RuntimeException {

  private static final long serialVersionUID = -2298500892023694050L;

  /**
   * Blank.
   */
  public CacheNotInitializedException() {
    super();
  }

  /**
   * @param arg0 Message
   * @param arg1 Cause
   */
  public CacheNotInitializedException(final String arg0, final Throwable arg1) {
    super(arg0, arg1);
  }

  /**
   * @param arg0 Message
   */
  public CacheNotInitializedException(final String arg0) {
    super(arg0);
  }

  /**
   * @param arg0 Cause
   */
  public CacheNotInitializedException(final Throwable arg0) {
    super(arg0);
  }
}
