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
 * Thrown any time the key renewal process fails.
 *
 * @version $Id: KeyRenewalFailedException.java 19902 2014-09-30 14:32:24Z
 *     anatom $
 */
public class KeyRenewalFailedException extends Exception {

  private static final long serialVersionUID = -7743705042076215320L;

  /** Default. */
  public KeyRenewalFailedException() {
    super();
  }

  /**
   * @param arg0 message
   * @param arg1 cause
   */
  public KeyRenewalFailedException(final String arg0, final Throwable arg1) {
    super(arg0, arg1);
  }

  /**
   * @param arg0 message
   */
  public KeyRenewalFailedException(final String arg0) {
    super(arg0);
  }

  /**
   * @param arg0 cause
   */
  public KeyRenewalFailedException(final Throwable arg0) {
    super(arg0);
  }
}
