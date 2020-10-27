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

package org.ejbca.core;

import javax.xml.ws.WebFault;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * Base for all specific application exceptions thrown by EJBCA. Can be used to
 * catch any non-critical application exceptions they may be possible to handle:
 * <code> try { . . . } catch
 * (EjbcaException e) { error("Error: blahblah", e); ... }</code>
 *
 * @version $Id: EjbcaException.java 29354 2018-06-26 12:01:45Z mikekushner $
 */
@WebFault
public class EjbcaException extends Exception {

  private static final long serialVersionUID = -3754146611270578813L;

  // private static final Logger log = Logger.getLogger(EjbcaException.class);

  /** The error code describes the cause of the exception. */
  private ErrorCode errorCode = null;

  /**
   * Constructor used to create exception without an error message. Calls the
   * same constructor in baseclass <code>Exception</code>.
   */
  public EjbcaException() {
    super();
  }

  /**
   * Constructor used to create exception with an error message. Calls the same
   * constructor in baseclass <code>Exception</code>.
   *
   * @param message Human redable error message, can not be NULL.
   */
  public EjbcaException(final String message) {
    super(message);
  }

  /**
   * Constructor used to create exception with an errorCode. Calls the same
   * default constructor in the base class <code>Exception</code>.
   *
   * @param anErrorCode defines the cause of the exception.
   */
  public EjbcaException(final ErrorCode anErrorCode) {
    super();
    this.errorCode = anErrorCode;
  }

  /**
   * Constructor used to create exception with an error message. Calls the same
   * constructor in baseclass <code>Exception</code>.
   *
   * @param anErrorCode defines the cause of the exception.
   * @param message Human readable error message, can not be NULL.
   */
  public EjbcaException(final ErrorCode anErrorCode, final String message) {
    super(message);
    this.errorCode = anErrorCode;
  }

  /**
   * Constructor used to create exception with an embedded exception. Calls the
   * same constructor in baseclass <code>Exception</code>.
   *
   * @param exception exception to be embedded.
   */
  public EjbcaException(final Exception exception) {
    super(exception);
    errorCode = EjbcaException.getErrorCode(exception);
  }

  /**
   * Constructor used to create exception with an embedded exception. Calls the
   * same constructor in baseclass <code>Exception</code>.
   *
   * @param anErrorCode defines the cause of the exception.
   * @param exception exception to be embedded.
   */
  public EjbcaException(final ErrorCode anErrorCode,
          final Throwable exception) {
    super(exception);
    this.errorCode = anErrorCode;
  }

  /**
   * Constructor used to create exception with an error message. Calls the same
   * constructor in baseclass <code>Exception</code>.
   *
   * @param message Human readable error message, can not be NULL.
   * @param cause Caise
   */
  public EjbcaException(final String message, final Throwable cause) {
    super(message, cause);
    if (cause instanceof EjbcaException) {
      errorCode = ((EjbcaException) cause).getErrorCode();
    }
  }

  /**
   * @param anErrorCode EC
   * @param message Message
   * @param cause Cause
   */
  public EjbcaException(
      final ErrorCode anErrorCode,
      final String message, final Throwable cause) {
    super(message, cause);
    this.errorCode = anErrorCode;
  }

  /**
   * Get the error code.
   *
   * @return the error code.
   */
  public ErrorCode getErrorCode() {
    return errorCode;
  }

  /**
   * Set the error code.
   *
   * @param anErrorCode the error code.
   */
  public void setErrorCode(final ErrorCode anErrorCode) {
    this.errorCode = anErrorCode;
  }

  /**
   * Get EJBCA ErrorCode from any exception that is, extends or just wraps
   * EjbcaException or CesecoreException.
   *
   * @param exception exception or its cause from error code should be retrieved
   * @return error code as ErrorCode object, or null if CesecoreException or
   *     EjbcaException could not be found
   */
  public static ErrorCode getErrorCode(final Throwable exception) {
    if (exception == null) {
      return null;
    }
    if (exception instanceof EjbcaException
        && ((EjbcaException) exception).getErrorCode() != null) {
      return ((EjbcaException) exception).getErrorCode();
    } else if (exception instanceof CesecoreException
        && ((CesecoreException) exception).getErrorCode() != null) {
      return ((CesecoreException) exception).getErrorCode();
    } else {
      return getErrorCode(exception.getCause());
    }
  }
}
