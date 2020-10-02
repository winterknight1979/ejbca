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
package org.cesecore.authorization.user.matchvalues;

/**
 * Thrown if an error occurs during reverse lookup.
 *
 * @version $Id: ReverseMatchValueLookupException.java 17625 2013-09-20
 *          07:12:06Z netmackan $
 *
 */
public class ReverseMatchValueLookupException extends RuntimeException {

    private static final long serialVersionUID = -7869788516422286307L;
    /** Bare exception. */
    public ReverseMatchValueLookupException() {
        super();
    }
    /**
     * Exception with message and cause.
     * @param message Message
     * @param cause Cause
     */
    public ReverseMatchValueLookupException(
            final String message, final Throwable cause) {
        super(message, cause);
    }
    /**
     * Exception with message.
     * @param message Message
     */
    public ReverseMatchValueLookupException(final String message) {
        super(message);
    }

    /**
     * Exception with cause.
     * @param cause Cause
     */
    public ReverseMatchValueLookupException(final Throwable cause) {
        super(cause);
    }

}
