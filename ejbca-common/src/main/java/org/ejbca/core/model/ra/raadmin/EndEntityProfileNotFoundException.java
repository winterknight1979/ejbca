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

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * Thrown when an end entity profile was not found.
 *
 * @version $Id: EndEntityProfileNotFoundException.java 29354 2018-06-26
 *     12:01:45Z mikekushner $
 */
public class EndEntityProfileNotFoundException extends EjbcaException {

  private static final long serialVersionUID = 1901011578701643327L;

  /** Null constructor. */
  public EndEntityProfileNotFoundException() {
    super();
  }

  /**
   * @param message message
   * @param cause cause
   */
  public EndEntityProfileNotFoundException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message message
   */
  public EndEntityProfileNotFoundException(final String message) {
    super(message);
  }

  /**
   * @param cause cause
   */
  public EndEntityProfileNotFoundException(final Throwable cause) {
    super(ErrorCode.EE_PROFILE_NOT_EXISTS, cause);
  }

  /**
   * @param endEntityProfileId ID
   */
  public EndEntityProfileNotFoundException(final int endEntityProfileId) {
    super(
        "Could not find end entity profile with ID "
            + endEntityProfileId
            + ".");
  }
}
