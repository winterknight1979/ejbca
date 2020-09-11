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
 * This enum represents a callback to a data table, allowing a session or managed bean to fill a DynamicUiProperty with values from the database.  
 * 
 * @version $Id: DynamicUiPropertyCallback.java 28562 2018-03-27 14:07:49Z undulf $
 *
 */
public enum DynamicUiPropertyCallback {
    NONE, ROLES, ROLES_VIEW;
}
