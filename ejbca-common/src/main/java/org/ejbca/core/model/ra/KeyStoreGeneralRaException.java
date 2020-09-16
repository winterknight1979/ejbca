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
 
package org.ejbca.core.model.ra;

import org.cesecore.NonSensitiveException;
import org.ejbca.core.EjbcaException;

/**
 * Wraps the original java.lang.Exception thrown with {@link #KeyStoreCreateSessionBean.generateOrKeyRecoverToken}.
 *
 * @version $Id: KeyStoreGeneralRaException.java 25763 2017-04-27 11:01:31Z henriks $
 */
@NonSensitiveException
public class KeyStoreGeneralRaException extends EjbcaException {
    
    private static final long serialVersionUID = 1L;

    public KeyStoreGeneralRaException(Exception exception){
        super(exception);
    }
}
