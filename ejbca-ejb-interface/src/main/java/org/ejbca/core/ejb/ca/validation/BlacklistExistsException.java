/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.validation;

/**
 * An exception thrown when someone tries to store a public key blacklist entry that already exists.
 *
 * @version $Id: BlacklistExistsException.java 26302 2017-08-14 14:35:32Z anatom $
 */
public class BlacklistExistsException extends Exception {

    private static final long serialVersionUID = 215999965395318151L;

    /**
     * Creates a new instance.
     */
    public BlacklistExistsException() {
        super();
    }

    /**
     * Creates a new instance with the specified detail message.
     * @param message the detail message.
     */
    public BlacklistExistsException(final String message) {
        super(message);
    }
}
