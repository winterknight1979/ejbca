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
package org.cesecore.keys;

/**
 * This exception is thrown when an error is encountered when trying to create a
 * key.
 *
 * @version $Id: KeyCreationException.java 17625 2013-09-20 07:12:06Z netmackan
 *     $
 */
public class KeyCreationException extends RuntimeException {

  private static final long serialVersionUID = 6589133117806842102L;

  /** default. */
  public KeyCreationException() { }

  /**
   * @param arg0 Message
   */
  public KeyCreationException(final String arg0) {
    super(arg0);
  }

  /**
   * @param arg0 cause
   */
  public KeyCreationException(final Throwable arg0) {
    super(arg0);
  }

  /**
   * @param arg0 Message
   * @param arg1 Cause
   */
  public KeyCreationException(final String arg0, final Throwable arg1) {
    super(arg0, arg1);
  }
}
