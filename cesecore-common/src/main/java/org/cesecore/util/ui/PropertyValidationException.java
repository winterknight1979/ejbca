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
package org.cesecore.util.ui;

/**
 * Thrown to show that a set property failed validation. 
 * 
 * @version $Id: PropertyValidationException.java 24964 2017-01-02 08:15:35Z mikekushner $
 *
 */
public class PropertyValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public PropertyValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public PropertyValidationException(String message) {
        super(message);
    }

    public PropertyValidationException(Throwable cause) {
        super(cause);
    }


}
