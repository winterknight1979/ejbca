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
package org.ejbca.core.model.services;

/**
 * Exception throws when a service work method fails for some reason
 * It should contain a message used in logging.
 * 
 *
 * @version $Id: ServiceExecutionFailedException.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class ServiceExecutionFailedException extends Exception {

	private static final long serialVersionUID = 383213793956902294L;

    public ServiceExecutionFailedException(String message, Throwable cause) {
		super(message, cause);
	}

	public ServiceExecutionFailedException(String message) {
		super(message);
	}

	public ServiceExecutionFailedException(Throwable cause) {
		super(cause);
	}
}
