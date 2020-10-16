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
 * This exception is thrown when trying to access a nonexistent approval step in
 * an approval profile.
 *
 * @version $Id: NoSuchApprovalStepException.java 23996 2016-07-25 13:20:57Z
 *     mikekushner $
 */
public class NoSuchApprovalStepException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  /** */
  public NoSuchApprovalStepException() {}

  /** @param message Message */
  public NoSuchApprovalStepException(final String message) {
    super(message);
  }

  /** @param cause CAuse */
  public NoSuchApprovalStepException(final Throwable cause) {
    super(cause);
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public NoSuchApprovalStepException(
      final String message, final Throwable cause) {
    super(message, cause);
  }
}
