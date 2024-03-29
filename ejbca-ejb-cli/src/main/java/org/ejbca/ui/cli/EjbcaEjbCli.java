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

package org.ejbca.ui.cli;

import org.cesecore.util.CryptoProviderUtil;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.library.CommandLibrary;

/**
 * Main entry point for the EJBCA EJB CLI.
 *
 * @version $Id: EjbcaEjbCli.java 19902 2014-09-30 14:32:24Z anatom $
 */
public final class EjbcaEjbCli {

    private EjbcaEjbCli() { }

    /**
     * @param args Arguments
     */
  public static void main(final String[] args) {
    if (args.length == 0 || !CommandLibrary.INSTANCE.doesCommandExist(args)) {
      CommandLibrary.INSTANCE.listRootCommands();
    } else {
      CryptoProviderUtil.installBCProvider();
      CommandResult result =
          CommandLibrary.INSTANCE.findAndExecuteCommandFromParameters(args);
      if (result != CommandResult.SUCCESS) {
        System.exit(result.getReturnCode());
      }
    }
  }
}
