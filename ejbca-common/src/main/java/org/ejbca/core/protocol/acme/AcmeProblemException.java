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
package org.ejbca.core.protocol.acme;

import javax.ws.rs.core.Response.Status;
import org.ejbca.core.protocol.acme.response.AcmeProblem;
import org.ejbca.core.protocol.acme.response.AcmeProblemResponse;

/**
 * Custom Exception for reporting problems from the ACME protocol.
 *
 * @see AcmeProblemResponse
 * @version $Id: AcmeProblemException.java 29587 2018-08-07 15:25:52Z
 *     mikekushner $
 */
public class AcmeProblemException extends Exception {

  private static final long serialVersionUID = 1L;
 /** Status. */
  private final int httpStatusCode;
  /** response. */
  private final AcmeProblemResponse acmeProblemResponse;
  /**
   * @param httpStatus status
   * @param acmeProblem problem
   * @param acmeProblemDetails details
   */
  public AcmeProblemException(
      final Status httpStatus,
      final AcmeProblem acmeProblem,
      final String acmeProblemDetails) {
    this(httpStatus, new AcmeProblemResponse(acmeProblem, acmeProblemDetails));
  }

  /**
   * @param httpStatus status
   * @param acmeProblem problem
   */
  public AcmeProblemException(
      final Status httpStatus, final AcmeProblem acmeProblem) {
    this(httpStatus, new AcmeProblemResponse(acmeProblem));
  }

  /**
   * @param httpStatus status
   * @param anacmeProblemResponse resp
   */
  public AcmeProblemException(
      final Status httpStatus,
      final AcmeProblemResponse anacmeProblemResponse) {
    this.httpStatusCode = httpStatus.getStatusCode();
    this.acmeProblemResponse = anacmeProblemResponse;
  }


  /**
   * @return code
   */
  public int getHttpStatusCode() {
    return httpStatusCode;
  }

  /**
   * @return response.
   */
  public AcmeProblemResponse getAcmeProblemResponse() {
    return acmeProblemResponse;
  }
}
