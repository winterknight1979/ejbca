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
package org.ejbca.core.model.approval.profile;

/**
 * Thrown to show that somebody has tried to add steps or partitions to a
 * profile which is set to be unmodifiable. Should not happen other than due to
 * programmer error, so is a RuntimeException
 *
 * @version $Id: NonModifiableApprovalProfileException.java 23688 2016-06-17
 *     10:46:42Z mikekushner $
 */
public class NonModifiableApprovalProfileException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  /** Null constructor. */
  public NonModifiableApprovalProfileException() {
    super();
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public NonModifiableApprovalProfileException(
      final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param message Message
   */
  public NonModifiableApprovalProfileException(final String message) {
    super(message);
  }

  /**
   * @param cause Cause
   */
  public NonModifiableApprovalProfileException(final Throwable cause) {
    super(cause);
  }
}
