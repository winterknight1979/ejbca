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
 
package org.cesecore;

import javax.xml.ws.WebFault;

/**
 * Base for all specific application exceptions thrown by EJBCA. Can be used to catch any
 * non-critical application exceptions they may be possible to handle: <code> try { . . . } catch
 * (EjbcaException e) { error("Error: blahblah", e); ... }</code>
 *
 * @version $Id: CesecoreException.java 26227 2017-08-07 09:48:10Z anatom $
 *
 */
@WebFault
public class CesecoreException extends Exception {

    private static final long serialVersionUID = -3754146611270578813L;
    
    //private static final Logger log = Logger.getLogger(CesecoreException.class);

    /** The error code describes the cause of the exception. */
    ErrorCode errorCode = null;

    /**
     * Constructor used to create exception without an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     */
    public CesecoreException() {
        super();
    }

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public CesecoreException(final String message) {
        super(message);
    }

    /**
     * Constructor used to create exception with an errorCode. Calls the same default constructor
     * in the base class <code>Exception</code>.
     *
     * @param errorCode defines the cause of the exception.
     */
    public CesecoreException(final ErrorCode errorCode) {
        super();
        this.errorCode = errorCode;
    }

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param errorCode defines the cause of the exception.
     * @param message Human readable error message, can not be NULL.
     */
    public CesecoreException(final ErrorCode errorCode, final String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public CesecoreException(final Exception exception) {
        super(exception);
        if (exception instanceof CesecoreException) {
        	errorCode = ((CesecoreException) exception).getErrorCode();
        }
    }

    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param errorCode defines the cause of the exception.
     * @param exception exception to be embedded.
     */
    public CesecoreException(final ErrorCode errorCode, final Exception exception) {
        super(exception);
        this.errorCode = errorCode;
    }

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public CesecoreException(final String message, final Throwable cause) {
		super(message, cause);
        if (cause instanceof CesecoreException) {
        	errorCode = ((CesecoreException) cause).getErrorCode();
        }
	}

	public CesecoreException(final ErrorCode errorCode, final String message, final Throwable cause) {
		super(message, cause);
        this.errorCode = errorCode;
	}

    /** Get the error code.
     * @return the error code.
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    /** Set the error code.
     * @param errorCode the error code.
     */
    public void setErrorCode(final ErrorCode errorCode) {
        this.errorCode = errorCode;
    }
    
    /** Get EJBCA ErrorCode from any exception that is, extends or just wraps CesecoreException
     * @param exception exception or its cause from error code should be retrieved
     * @return error code as ErrorCode object, or null if CesecoreException could not be found
     */
    public static ErrorCode getErrorCode(Throwable exception){
        if(exception == null){
            return null;
        }
        if(exception instanceof CesecoreException){
            return ((CesecoreException)exception).getErrorCode();
        }else{
            return getErrorCode(exception.getCause());
        }
    }
}