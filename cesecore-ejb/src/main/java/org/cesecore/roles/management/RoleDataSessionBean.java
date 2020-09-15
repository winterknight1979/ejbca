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
package org.cesecore.roles.management;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.util.ProfileID;
import org.cesecore.util.QueryResultWrapper;

/**
 * Implementation of the RoleDataSession local interface.
 * 
 * @version $Id: RoleDataSessionBean.java 26493 2017-09-05 13:31:40Z anatom $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleDataSessionBean implements RoleDataSessionLocal, RoleDataSessionRemote {

    private static final Logger log = Logger.getLogger(RoleDataSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Role> getAllRoles() {
        final TypedQuery<RoleData> query = entityManager.createQuery("SELECT a FROM RoleData a", RoleData.class);
        final List<Role> ret = new ArrayList<>();
        for (final RoleData roleData : query.getResultList()) {
            ret.add(roleData.getRole());
        }
        return ret;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final String nameSpace, final String roleName) {
        final Integer roleId = RoleCache.INSTANCE.getNameToIdMap().get(Role.getRoleNameFullAsCacheName(nameSpace, roleName));
        if (roleId != null) {
            return getRole(roleId.intValue());
        }
        final RoleData result = getRoleData(nameSpace, roleName);
        final Role role = result==null ? null : result.getRole();
        if (role!=null) {
            RoleCache.INSTANCE.updateWith(role.getRoleId(), role.hashCode(), Role.getRoleNameFullAsCacheName(role.getNameSpace(), role.getRoleName()), role);
        }
        return role;
    }

    private RoleData getRoleData(final String nameSpace, final String roleName) {
        if (StringUtils.isEmpty(nameSpace)) {
            final Query query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.roleName=:roleName AND a.nameSpaceColumn IS NULL");
            query.setParameter("roleName", roleName);
            return QueryResultWrapper.getSingleResult(query);
        } else {
            final Query query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.roleName=:roleName AND a.nameSpaceColumn=:nameSpace");
            query.setParameter("roleName", roleName);
            query.setParameter("nameSpace", nameSpace);
            return QueryResultWrapper.getSingleResult(query);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final int roleId) {
        if (roleId==Role.ROLE_ID_UNASSIGNED) {
            // The reserved ID will never have a database entry, so return quickly with what we know will be the result
            return null;
        }
        // 1. Check cache if it is time to sync-up with database
        if (RoleCache.INSTANCE.shouldCheckForUpdates(roleId)) {
            if (log.isDebugEnabled()) {
                log.debug("Object with ID " + roleId + " will be checked for updates.");
            }
            // 2. If cache is expired or missing, first thread to discover this reloads item from database and sends it to the cache
            final RoleData roleData = getRoleData(roleId);
            if (roleData==null) {
                if (log.isDebugEnabled()) {
                    log.debug("Requested object did not exist in database and will be purged from cache if present: " + roleId);
                }
                // Ensure that it is removed from cache when the object is no longer present in the database
                RoleCache.INSTANCE.removeEntry(roleId);
            } else {
                final Role role = roleData.getRole();
                final int digest = role.hashCode();
                // 3. The cache compares the database data with what is in the cache
                // 4. If database is different from cache, replace it in the cache
                RoleCache.INSTANCE.updateWith(roleId, digest, Role.getRoleNameFullAsCacheName(role.getNameSpace(), role.getRoleName()), role);
                // Return role, working even if the cache is disabled
                return role;
            }
        }
        // 5. Get object from cache now (or null) and be merry
        return RoleCache.INSTANCE.getEntry(roleId);
    }

    private RoleData getRoleData(final int roleId) {
        final TypedQuery<RoleData> query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.id=:id", RoleData.class);
        query.setParameter("id", roleId);
        return QueryResultWrapper.getSingleResult(query);
    }

    @Override
    public Role persistRole(final Role role) {
        if (role==null) {
            // Successfully did nothing
            return null;
        }
        boolean authorizationMightHaveChanged = true;
        if (role.getRoleId()==Role.ROLE_ID_UNASSIGNED) {
            role.setRoleId(findFreeRoleId());
            entityManager.persist(new RoleData(role));
        } else {
            final RoleData roleData = getRoleData(role.getRoleId());
            if (roleData==null) {
                // Must have been removed by another process, but caller wants to persist it, so we proceed (keeping the requested Role ID)
                entityManager.persist(new RoleData(role));
            } else {
                final Role oldRole = roleData.getRole();
                if (role.getAccessRules().equals(oldRole.getAccessRules())) {
                    // We will not care if the role has any members, since there is no change to the access rules
                    authorizationMightHaveChanged = false;
                }
                // Since the entity is managed, we just update its values
                roleData.setRole(role);
            }
        }
        RoleCache.INSTANCE.updateWith(role.getRoleId(), role.hashCode(), Role.getRoleNameFullAsCacheName(role.getNameSpace(), role.getRoleName()), role);
        // If we only created a new Role that has no members yet or the access rules did no change, the authorization would not have changed
        authorizationMightHaveChanged &= isRoleMembersPresent(role.getRoleId());
        if (authorizationMightHaveChanged) {
            accessTreeUpdateSession.signalForAccessTreeUpdate();
        }
        return role;
    }

    /** @return a integer Id that is currently unused in the database */
    private int findFreeRoleId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(final int candidate) {
                return candidate!=Role.ROLE_ID_UNASSIGNED && getRole(candidate) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @Override
    public boolean deleteRoleNoAuthorizationCheck(final int roleId) {
        // Use an DELETE query instead of entityManager.remove to tolerate concurrent deletion better
        final Query query = entityManager.createQuery("DELETE FROM RoleData a WHERE a.id=:id");
        query.setParameter("id", roleId);
        final boolean ret = query.executeUpdate()==1;
        if (ret && isRoleMembersPresent(roleId)) {
            accessTreeUpdateSession.signalForAccessTreeUpdate();
        }
        return ret;
    }
    
    private boolean isRoleMembersPresent(final int roleId) {
        return !roleMemberDataSession.findByRoleId(roleId).isEmpty();
    }

    @Override
    public void forceCacheExpire() {
        RoleCache.INSTANCE.flush();
    }
}
