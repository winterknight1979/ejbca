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
package org.cesecore.roles.member;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * CRUD session bean for managing RoleMemberData objects
 * 
 * @version $Id: RoleMemberDataSessionLocal.java 26449 2017-08-28 20:05:53Z mikekushner $
 */
@Local
public interface RoleMemberDataSessionLocal extends RoleMemberDataSession {

    /**
     * Saves a RoleMember object to the database, either overwriting an existing one with the same primary key or editing an existing instance.
     * 
     * @param roleMember the RoleMember entity to persist.
     * 
     * @return the RoleMember representing what was actually persisted
     */
    RoleMember persistRoleMember(RoleMember roleMember);

    /**
     * Finds an RoleMemberData by its primary key.
     * 
     * @param primaryKey
     *            Primary key of the sought instance.
     * @return the sought RoleMember, otherwise null. .
     */
    RoleMemberData find(final int primaryKey);

    
    /**
     * Removes an RoleMemberData from the database.
     * 
     * @param primaryKey
     *            The ID of the RoleMemberData to remove.
     * @return true if removal was successful, false if no such role member was found
     */
    boolean remove(final int primaryKey);
    
    /**
     * 
     * @param roleId the ID of a role
     * @return a list of members to the given role
     */
    List<RoleMemberData> findByRoleId(int roleId);
    
    /**
     * Finds an RoleMember by its primary key from the cache.
     * 
     * @param primaryKey
     *            Primary key of the sought instance.
     * @return the sought RoleMember, otherwise null. .
     */
    RoleMember findRoleMember(final int primaryKey);

    /**
     * Finds all role members belonging to a specific role.
     * 
     * 
     * @param roleId the ID of a role
     * @return a list of members to the given role
     */
    List<RoleMember> findRoleMemberByRoleId(int roleId);

    /** @return all roleId matching the specified valid AuthenticationToken or an empty list otherwise */
    Set<Integer> getRoleIdsMatchingAuthenticationToken(AuthenticationToken authenticationToken);

    /** 
     * @return all roleId matching the specified valid AuthenticationToken or an empty list otherwise
     * @throws AuthenticationFailedException if there is problem matching the AuthenticationToken to a RoleMember
     */
    Set<Integer> getRoleIdsMatchingAuthenticationTokenOrFail(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    /** @return roleId,tokenMatchType values for legacy priority matching  */
    @Deprecated // Keep for as long as we need to support upgrades to 6.8.0
    Map<Integer, Integer> getRoleIdsAndTokenMatchKeysMatchingAuthenticationToken(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    /** @return all role members matching the specified valid AuthenticationToken or an empty list otherwise */
    Set<RoleMember> getRoleMembersMatchingAuthenticationToken(AuthenticationToken authenticationToken);
}
