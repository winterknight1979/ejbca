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

package org.ejbca.ui.cli.ra;

import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Revokes an end entity in the database, and also revokes all that end entity's
 * certificates.
 *
 * @version $Id: RevokeEndEntityCommand.java 24892 2016-12-13 20:22:21Z
 *     mikekushner $
 */
public class RevokeEndEntityCommand extends BaseRaCommand {

      /** Param. */
  private static final Logger LOG =
      Logger.getLogger(RevokeEndEntityCommand.class);

  /** Param. */
  private static final String COMMAND = "revokeendentity";
  /** Param. */
  private static final String OLD_COMMAND = "revokeuser";

  /** Param. */
  private static final Set<String> ALIASES = new HashSet<String>();

  static {
    ALIASES.add(OLD_COMMAND);
  }

  /** Param. */
  private static final String USERNAME_KEY = "--username";
  /** Param. */
  private static final String REASON_KEY = "-r";

  {
    registerParameter(
        new Parameter(
            USERNAME_KEY,
            "Username",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "Username for the end entity to revoke."));
    registerParameter(
        new Parameter(
            REASON_KEY,
            "Reason",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "Reason: unused(0), keyCompromise(1), cACompromise(2),"
                + " affiliationChanged(3), superseded(4),"
                + " cessationOfOperation(5), certficateHold(6),"
                + " removeFromCRL(8), privilegeWithdrawn(9), aACompromise(10)."
                + " Normal reason is 0"));
  }

  @Override
  public Set<String> getMainCommandAliases() {
    return ALIASES;
  }

  @Override
  public String getMainCommand() {
    return COMMAND;
  }

  @Override
  public CommandResult execute(final ParameterContainer parameters) {
    String username = parameters.get(USERNAME_KEY);
    int reason;
    try {
      reason = Integer.parseInt(parameters.get(REASON_KEY));
    } catch (NumberFormatException e) {
      LOG.error("ERROR: " + parameters.get(REASON_KEY) + " was not a number.");
      return CommandResult.FUNCTIONAL_FAILURE;
    }
    final int invalid = 7;
    if ((reason == invalid) || (reason < 0) || (reason > 10)) {
      getLogger().error("Reason must be an integer between 0 and 10 except 7.");
    } else {
      EndEntityInformation data;
      try {
        data =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityAccessSessionRemote.class)
                .findUser(getAuthenticationToken(), username);
      } catch (AuthorizationDeniedException e) {
        LOG.error(
            "ERROR: CLI user not authorized to end entity with username "
                + username);
        return CommandResult.FUNCTIONAL_FAILURE;
      }
      if (data == null) {
        getLogger().error("User not found.");
        return CommandResult.FUNCTIONAL_FAILURE;
      }
      getLogger().info("Found user:");
      getLogger().info("username=" + data.getUsername());
      getLogger().info("dn=\"" + data.getDN() + "\"");
      getLogger().info("Old status=" + data.getStatus());
      // Revoke users certificates
      try {
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class)
            .revokeUser(getAuthenticationToken(), username, reason);
        data =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityAccessSessionRemote.class)
                .findUser(getAuthenticationToken(), username);
        getLogger().info("New status=" + data.getStatus());
        return CommandResult.SUCCESS;
      } catch (AuthorizationDeniedException e) {
        getLogger().error("Not authorized to revoke user.");
      } catch (ApprovalException e) {
        getLogger().error("Revocation already requested.");
      } catch (WaitingForApprovalException e) {
        getLogger().info("Revocation request has been sent for approval.");
      } catch (AlreadyRevokedException e) {
        LOG.error("ERROR: " + e.getMessage());
      } catch (NoSuchEndEntityException e) {
        LOG.error("ERROR: " + e.getMessage());
      }
    }
    return CommandResult.FUNCTIONAL_FAILURE;
  }

  @Override
  public String getCommandDescription() {
    return "Revokes an end enity and all certificates for that end entity.";
  }

  @Override
  public String getFullHelpText() {
    return getCommandDescription();
  }

  @Override
  protected Logger getLogger() {
    return LOG;
  }
}
