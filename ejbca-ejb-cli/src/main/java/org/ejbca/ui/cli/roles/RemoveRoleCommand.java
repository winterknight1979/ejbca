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

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Remove admin role.
 * 
 * @version $Id: RemoveRoleCommand.java 29197 2018-06-11 09:28:26Z jeklund $
 */
public class RemoveRoleCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(RemoveRoleCommand.class);

    private static final String ROLE_NAME_KEY = "--role";
    private static final String ROLE_NAMESPACE_KEY = "--namespace";

    {
        registerParameter(new Parameter(ROLE_NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Role to remove."));
        registerParameter(new Parameter(ROLE_NAMESPACE_KEY, "Role Namespace", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The namespace the role belongs to."));
    }

    @Override
    public String getMainCommand() {
        return "removerole";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final String roleName = parameters.get(ROLE_NAME_KEY);
        final String namespace = parameters.get(ROLE_NAMESPACE_KEY);
        final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
        try {
            final Role role = roleSession.getRole(getAuthenticationToken(), namespace, roleName);
            if (role == null) {
                getLogger().error("No such role " + super.getFullRoleName(namespace, roleName) + ".");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            if (!roleSession.deleteRoleIdempotent(getAuthenticationToken(), role.getRoleId())) {
                getLogger().error("No such role " + super.getFullRoleName(namespace, roleName) + ".");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to remove role " + super.getFullRoleName(namespace, roleName));
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Remove admin role";
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
