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

package org.ejbca.ui.cli.config.scep;

import org.ejbca.config.ScepConfiguration;
import org.ejbca.ui.cli.config.ConfigBaseCommand;

/**
 * Shows the current server configuration.
 *
 * @version $Id: BaseScepConfigCommand.java 26057 2017-06-22 08:08:34Z anatom $
 */
public abstract class BaseScepConfigCommand extends ConfigBaseCommand {

    /** Param. */
  private ScepConfiguration scepConfiguration = null;

  @Override
  public String[] getCommandPath() {
    return new String[] {super.getCommandPath()[0], "scep"};
  }

  /**
   * @return Config.
   */
  protected ScepConfiguration getScepConfiguration() {
    if (scepConfiguration == null) {
      scepConfiguration =
          (ScepConfiguration)
              getGlobalConfigurationSession()
                  .getCachedConfiguration(
                      ScepConfiguration.SCEP_CONFIGURATION_ID);
    }
    return scepConfiguration;
  }
}
