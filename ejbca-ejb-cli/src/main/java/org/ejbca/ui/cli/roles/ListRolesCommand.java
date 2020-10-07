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

package org.ejbca.ui.cli.roles;

import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Lists admin roles
 * @version $Id: ListRolesCommand.java 29175 2018-06-08 13:38:23Z jeklund $
 */
public class ListRolesCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(ListRolesCommand.class);

    @Override
    public String getMainCommand() {
        return "listroles";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final List<Role> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getAuthorizedRoles(getAuthenticationToken());
        Collections.sort(roles);
        final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
        for (final Role role : roles) {
            List<RoleMember> roleMembers;
            try {
                roleMembers = roleMemberSession.getRoleMembersByRoleId(getAuthenticationToken(), role.getRoleId());
                final String roleMembersString = " (" + roleMembers.size() + " member"+(roleMembers.size()==1?"":"s")+")";
                getLogger().info(super.getFullRoleName(role.getNameSpace(), role.getRoleName()) + " " + roleMembersString);
            } catch (AuthorizationDeniedException e) {
                getLogger().info(super.getFullRoleName(role.getNameSpace(), role.getRoleName()) + " (? members)");
            }
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Lists admin roles";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
