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
package org.cesecore.keys.util;

/**
 * Exception that may be thrown by the {@link ISignOperation#taskWithSigning(String, java.security.Provider)}
 * @version $Id: TaskWithSigningException.java 22566 2016-01-13 08:49:18Z mikekushner $
 *
 */
public class TaskWithSigningException extends Exception {

    private static final long serialVersionUID = 1L;

    public TaskWithSigningException(final String message) {
        super(message);
    }

    public TaskWithSigningException(final String message, final Exception cause) {
        super(message, cause);
    }
}
