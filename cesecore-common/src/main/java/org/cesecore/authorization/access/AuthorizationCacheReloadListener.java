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
package org.cesecore.authorization.access;

/**
 * Interface for subscriber to AuthorizationCacheReload events.
 * 
 * @version $Id: AuthorizationCacheReloadListener.java 25591 2017-03-23 13:13:02Z jeklund $
 */
public interface AuthorizationCacheReloadListener {

    /** Invoked when the authorization system has been modified. */
    void onReload(AuthorizationCacheReload event);

    /** @return a human readable name for logging of who is subscribing to events. */
    String getListenerName();
}
