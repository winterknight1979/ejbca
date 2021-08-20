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

package org.ejbca.ui.cli.service;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Base for service commands, contains common functions for service operations.
 *
 * @version $Id: BaseServiceCommand.java 19902 2014-09-30 14:32:24Z anatom $
 */
public abstract class BaseServiceCommand extends EjbcaCliUserCommandBase {

/** Param. */
  protected final String serviceNameKey = "--service";

  {
    registerParameter(
        new Parameter(
            serviceNameKey,
            "Service Name",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The name of the service"));
  }

  @Override
  public String[] getCommandPath() {
    return new String[] {"service"};
  }

  @Override
  public final CommandResult execute(final ParameterContainer parameters) {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
    int serviceId = 0;
    if (acceptsServiceName()) {
      final ServiceSessionRemote serviceSession =
          EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
      serviceId = serviceSession.getServiceId(parameters.get(serviceNameKey));
      if (serviceId == 0 && failIfServiceMissing()) {
        getLogger()
            .info("Unknown Service: " + parameters.get(serviceNameKey));
        return CommandResult.FUNCTIONAL_FAILURE;
      }
    }
    return execute(parameters, serviceId);
  }

  /**
   * @param parameters Params
   * @param serviceId ID
   * @return result
   */
  public abstract CommandResult execute(
      ParameterContainer parameters, int serviceId);

  /**
   * @return bool
   */
  protected boolean acceptsServiceName() {
    return true;
  }

  /**
   * @return bool
   */
  protected boolean failIfServiceMissing() {
    return true;
  }

  /** @return the EJB CLI admin */
  protected AuthenticationToken getAdmin() {
    return getAuthenticationToken();
  }

  /**
   * Activates timers for services which change from not active to active.
   *
   * @param serviceName Name
   * @param wasActive bool
   */
  public void handleServiceActivation(
      final String serviceName, final boolean wasActive) {
    if (!wasActive) {
      final ServiceSessionRemote serviceSession =
          EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
      final boolean isActive =
          serviceSession.getService(serviceName).isActive();
      if (isActive) {
        serviceSession.activateServiceTimer(getAdmin(), serviceName);
      }
    }
  }

  @Override
  protected abstract Logger getLogger();
}
