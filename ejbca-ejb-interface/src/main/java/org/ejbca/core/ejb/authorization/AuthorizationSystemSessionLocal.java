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
package org.ejbca.core.ejb.authorization;

import java.util.Map;

import javax.ejb.Local;

/**
 * @see AuthorizationSystemSession
 * @version $Id: AuthorizationSystemSessionLocal.java 25480 2017-03-14 17:28:27Z jeklund $
 */
@Local
public interface AuthorizationSystemSessionLocal extends AuthorizationSystemSession {

    /** @return a Map<category name, Map<resource,resourceName>> */
    Map<String, Map<String, String>> getAllResourceAndResourceNamesByCategory();

    /** @return a Map of all <resource,resourceName>, on this installation (optionally ignoring if certain resources is not in use) */
    Map<String,String> getAllResources(boolean ignoreLimitations);

    /**
     * Setup the initial Role with the a single EJBCA CLI RoleMember under the condition that this is system is
     * connected to a database that has not been used for an installation so far.
     * (Actual check for a "fresh" system is to confirm that there exists no Roles or CAs.)
     * 
     * @return true if this was a fresh system and the authorization module has now been initialized.
     */
    boolean initializeAuthorizationModule();
}
