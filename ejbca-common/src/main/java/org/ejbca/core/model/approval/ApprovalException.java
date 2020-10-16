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
package org.ejbca.core.model.approval;

import javax.xml.ws.WebFault;
import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * General Exception when something serious goes wrong when managing approvals
 *
 * @version $Id: ApprovalException.java 23688 2016-06-17 10:46:42Z mikekushner $
 */
@WebFault
public class ApprovalException extends EjbcaException {

  private static final long serialVersionUID = 7232454568592982535L;

  /**
   * Constructor.
   *
   * @param message Human readable error message, can not be NULL.
   * @param cause exception to be embedded.
   */
  public ApprovalException(final String message, final Throwable cause) {
    super(message, cause);
    setErrorCode(ErrorCode.NOT_SPECIFIED);
  }

  /**
   * Constructor.
   *
   * @param message Human readable error message, can not be NULL.
   */
  public ApprovalException(final String message) {
    super(message);
    setErrorCode(ErrorCode.NOT_SPECIFIED);
  }

  /**
   * Constructor.
   *
   * @param errorCode associated error code.
   * @param message Human readable error message, can not be NULL.
   * @param cause exception to be embedded.
   */
  public ApprovalException(
      final ErrorCode errorCode, final String message, final Throwable cause) {
    super(errorCode, message, cause);
  }

  /**
   * Constructor.
   *
   * @param errorCode associated error code.
   * @param message Human readable error message, can not be NULL.
   */
  public ApprovalException(final ErrorCode errorCode, final String message) {
    super(errorCode, message);
  }
}
