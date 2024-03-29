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

package org.ejbca.ui.cli.ca;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Lists the fields of a CA.
 *
 * @version $Id: CaListFieldsCommand.java 27740 2018-01-05 07:24:53Z mikekushner
 *     $
 */
public class CaListFieldsCommand extends BaseCaAdminCommand {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(CaListFieldsCommand.class);

  /** Param. */
  private static final String CA_NAME_KEY = "--caname";

  {
    registerParameter(
        new Parameter(
            CA_NAME_KEY,
            "CA Name",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The name of the CA to list fields from."));
  }

  @Override
  public String getMainCommand() {
    return "listcafields";
  }

  @Override
  public CommandResult execute(final ParameterContainer parameters) {
    FieldEditor fieldEditor = new FieldEditor(LOG);
    CryptoProviderUtil.installBCProviderIfNotAvailable();
    final String name = parameters.get(CA_NAME_KEY);
    try {
      final CAInfo cainfo =
          EjbRemoteHelper.INSTANCE
              .getRemoteSession(CaSessionRemote.class)
              .getCAInfo(getAuthenticationToken(), name);
      if (cainfo == null) {
        LOG.info("CA '" + name + "' does not exist.");
        return CommandResult.FUNCTIONAL_FAILURE;
      }
      // List fields
      fieldEditor.listSetMethods(cainfo);
      return CommandResult.SUCCESS;
    } catch (AuthorizationDeniedException e) {
      LOG.error("CLI User was not authorized to CA " + name);
      return CommandResult.AUTHORIZATION_FAILURE;
    }
  }

  @Override
  public String getCommandDescription() {
    return "Lists the fields of a CA.";
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
