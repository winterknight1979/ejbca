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
package org.cesecore.keybind;

/**
 * Operational status representation of an InternalKeyBinding
 * 
 * @version $Id: InternalKeyBindingOperationalStatus.java 27598 2017-12-20 13:37:58Z aminkh $
 *
 */
public enum InternalKeyBindingOperationalStatus {
    ONLINE, PENDING, OFFLINE;
}
