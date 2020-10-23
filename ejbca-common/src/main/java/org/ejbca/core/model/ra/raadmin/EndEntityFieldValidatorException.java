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
package org.ejbca.core.model.ra.raadmin;

/**
 * Indicates that a field in an end entity does not match a validator (e.g. a
 * regex)
 *
 * @version $Id: EndEntityFieldValidatorException.java 22117 2015-10-29
 *     10:53:42Z mikekushner $
 */
public class EndEntityFieldValidatorException extends Exception {

  private static final long serialVersionUID = 1L;

  /** Null constructor.
   */
  public EndEntityFieldValidatorException() {
    super();
  }

  /**
   * @param message Message
   */
  public EndEntityFieldValidatorException(final String message) {
    super(message);
  }

  /**
   * @param cause Cause
   */
  public EndEntityFieldValidatorException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public EndEntityFieldValidatorException(
      final String message, final Throwable cause) {
    super(message, cause);
  }
}
