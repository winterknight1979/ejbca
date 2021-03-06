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
package org.ejbca.ui.cli.config.est;

import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/** @version $Id: UpdateCommand.java 27965 2018-01-15 16:20:53Z anatom $ */
public class UpdateCommand extends BaseEstConfigCommand {

      /** Param. */
  private static final String ALIAS_KEY = "--alias";
  /** Param. */
  private static final String KEY_KEY = "--key"; // Hue hue hue
  /** Param. */
  private static final String VALUE_KEY = "--value";

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(UpdateCommand.class);

  {
    registerParameter(
        new Parameter(
            ALIAS_KEY,
            "Alias",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The alias of the configuration to update."));
    registerParameter(
        new Parameter(
            KEY_KEY,
            "Key",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The key of the configuration to update (alias not included)."));
    registerParameter(
        new Parameter(
            VALUE_KEY,
            "Value",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The new value of the configuration to update."));
  }

  @Override
  public String getMainCommand() {
    return "updatealias";
  }

  @Override
  public CommandResult execute(final ParameterContainer parameters) {

    String alias = parameters.get(ALIAS_KEY);
    String key = parameters.get(KEY_KEY);
    String value = parameters.get(VALUE_KEY);
    List<String> bkeys = EstConfiguration.EST_BOOLEAN_KEYS;

    if (bkeys.contains(key)) {
      value = Boolean.toString(StringUtils.equalsIgnoreCase(value, "true"));
    }

    key = alias + "." + key;
    LOG.info(
        "Configuration was: "
            + key
            + "="
            + getEstConfiguration().getValue(key, alias));
    getEstConfiguration().setValue(key, value, alias);
    try {
      getGlobalConfigurationSession()
          .saveConfiguration(getAuthenticationToken(), getEstConfiguration());
      LOG.info(
          "Configuration updated: "
              + key
              + "="
              + getEstConfiguration().getValue(key, alias));
      getGlobalConfigurationSession()
          .flushConfigurationCache(EstConfiguration.EST_CONFIGURATION_ID);
      return CommandResult.SUCCESS;
    } catch (AuthorizationDeniedException e) {
      LOG.info("Failed to update configuration: " + e.getLocalizedMessage());
      return CommandResult.AUTHORIZATION_FAILURE;
    }
  }

  @Override
  public String getCommandDescription() {
    return "Updates one configuration value.";
  }

  @Override
  public String getFullHelpText() {
    StringBuilder sb = new StringBuilder();
    sb.append(getCommandDescription() + "\n\n");
    sb.append("The key could be any of the following:\n");
    StringBuilder existingCas = new StringBuilder();
    final String divider = " | ";
    for (String ca
        : EjbRemoteHelper.INSTANCE
            .getRemoteSession(CaSessionRemote.class)
            .getActiveCANames(getAuthenticationToken())) {
      existingCas.append((existingCas.length() == 0 ? "" : divider) + ca);
    }
    sb.append(
        "    "
            + EstConfiguration.CONFIG_DEFAULTCA
            + " - possible values: "
            + existingCas
            + "\n");
    Map<Integer, String> endentityprofileidtonamemap =
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityProfileSessionRemote.class)
            .getEndEntityProfileIdToNameMap();
    StringBuilder existingEeps = new StringBuilder();
    for (Integer profileId
        : EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityProfileSessionRemote.class)
            .getAuthorizedEndEntityProfileIds(
                getAuthenticationToken(),
                AccessRulesConstants.CREATE_END_ENTITY)) {
      existingEeps.append(
          (existingEeps.length() == 0 ? "" : divider)
              + profileId
              + " ("
              + endentityprofileidtonamemap.get(profileId)
              + ")");
    }
    sb.append(
        "    "
            + EstConfiguration.CONFIG_EEPROFILE
            + " - available IDs: "
            + existingEeps
            + "\n");
    Map<Integer, String> certificateprofileidtonamemap =
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class)
            .getCertificateProfileIdToNameMap();
    StringBuilder existingCps = new StringBuilder();
    for (Integer profileId
        : EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class)
            .getAuthorizedCertificateProfileIds(
                getAuthenticationToken(),
                CertificateConstants.CERTTYPE_ENDENTITY)) {
      existingCps.append(
          (existingCps.length() == 0 ? "" : " | ")
              + certificateprofileidtonamemap.get(profileId));
    }
    sb.append(
        "    "
            + EstConfiguration.CONFIG_CERTPROFILE
            + " - possible values: ProfileDefault | "
            + existingCps
            + "\n");
    sb.append(
        "    "
            + EstConfiguration.CONFIG_REQCERT
            + " - possible values: true | false"
            + "\n");
    sb.append(
        "    "
            + EstConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY
            + " - possible values: true | false"
            + "\n");
    sb.append(
        "    "
            + EstConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY
            + " - possible values: true | false"
            + "\n");
    sb.append(
        "    "
            + EstConfiguration.CONFIG_REQUSERNAME
            + " - possible values: a username you define"
            + "\n");
    sb.append(
        "    "
            + EstConfiguration.CONFIG_REQPASSWORD
            + " - possible values: a password you define"
            + "\n");
    return sb.toString();
  }

  @Override
  protected Logger getLogger() {
    return LOG;
  }
}
