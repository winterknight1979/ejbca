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

import java.util.List;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CLI command to consolidate the referenced PKCS#11 Crypto Tokens.
 *
 * <p>The command will look for other CAs that reference the same HSM slot and
 * use the specified CA's CryptoToken id for all the CAs.
 *
 * @version $Id: CaMergeCryptoTokenCommand.java 20457 2014-12-12 14:38:32Z
 *     jeklund $
 */
public class CaMergeCryptoTokenCommand extends BaseCaAdminCommand {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CaMergeCryptoTokenCommand.class);
  /** Param. */
  private static final String CA_NAME_KEY = "--caname";
  /** Param. */
  private static final String EXECUTE_KEY = "--execute";

  {
    registerParameter(
        new Parameter(
            CA_NAME_KEY,
            "CA Name",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The name of the CA."));
    registerParameter(
        Parameter.createFlag(
            EXECUTE_KEY,
            "Make the change instead of displaying what would change."));
  }

  @Override
  public String getMainCommand() {
    return "mergecatokens";
  }

  @Override
  public CommandResult execute(final ParameterContainer parameters) {
    LOG.trace(">execute()");
    CryptoProviderUtil.installBCProvider(); // need this for CVC certificate
    final String caName = parameters.get(CA_NAME_KEY);
    final boolean force = parameters.containsKey(EXECUTE_KEY);
    try {
      final CaSessionRemote caSession =
          EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
      final CryptoTokenManagementSessionRemote cryptoTokenManagementSession =
          EjbRemoteHelper.INSTANCE.getRemoteSession(
              CryptoTokenManagementSessionRemote.class);
      final CAInfo caInfo =
          caSession.getCAInfo(getAuthenticationToken(), caName);
      final int cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
      final CryptoTokenInfo cryptoTokenInfo =
          cryptoTokenManagementSession.getCryptoTokenInfo(
              getAuthenticationToken(), cryptoTokenId);
      if (!cryptoTokenInfo
          .getType()
          .equals(PKCS11CryptoToken.class.getSimpleName())) {
        LOG.error(
            "CA with name "
                + caName
                + " does not reference a PKCS#11 Crypto Token. Merge is not"
                + " possible.");
        return CommandResult.FUNCTIONAL_FAILURE;
      }
      LOG.info(
          "CA '"
              + caInfo.getName()
              + "' references crypto token '"
              + cryptoTokenInfo.getName()
              + "'");
      LOG.info(" PKCS#11 Library: " + cryptoTokenInfo.getP11Library());
      LOG.info(" SlotLabelType:   " + cryptoTokenInfo.getP11SlotLabelType());
      LOG.info(" SlotLabel:       " + cryptoTokenInfo.getP11Slot());
      LOG.info(" Attribute file:  " + cryptoTokenInfo.getP11AttributeFile());
      LOG.info("");
      int mergeCount = 0;
      final List<Integer> caIds =
          caSession.getAuthorizedCaIds(getAuthenticationToken());
      for (final int currentCaId : caIds) {
        if (currentCaId == caInfo.getCAId()) {
          // Skip the target CA
          continue;
        }
        final CAInfo currentCaInfo =
            caSession.getCAInfo(getAuthenticationToken(), currentCaId);
        final int currentCryptoTokenId =
            currentCaInfo.getCAToken().getCryptoTokenId();
        if (currentCryptoTokenId == cryptoTokenId) {
          // Skip CA when the cryptoToken already is the same
          continue;
        }
        final CryptoTokenInfo currentCryptoTokenInfo =
            cryptoTokenManagementSession.getCryptoTokenInfo(
                getAuthenticationToken(), currentCryptoTokenId);
        if (currentCryptoTokenInfo == null
            || !currentCryptoTokenInfo
                .getType()
                .equals(PKCS11CryptoToken.class.getSimpleName())) {
          // Skip non PKCS#11 crypto token CAs
          continue;
        }
        if (!currentCryptoTokenInfo
            .getP11Library()
            .equals(cryptoTokenInfo.getP11Library())) {
          // Skip when HSM driver isn't the same
          continue;
        }
        if (!currentCryptoTokenInfo
            .getP11SlotLabelType()
            .equals(cryptoTokenInfo.getP11SlotLabelType())) {
          // Skip when the slot label isn't referenced the same way
          continue;
        }
        if (!currentCryptoTokenInfo
            .getP11Slot()
            .equals(cryptoTokenInfo.getP11Slot())) {
          // Skip when the same slot isn't referenced
          continue;
        }
        LOG.info(
            (force ? "Merging " : "Would merge")
                + " CA '"
                + currentCaInfo.getName()
                + "' that currently references crypto token '"
                + currentCryptoTokenInfo.getName()
                + "' to instead reference '"
                + cryptoTokenInfo.getName()
                + "'.");
        LOG.info(
            " Current PKCS#11 Library: "
                + currentCryptoTokenInfo.getP11Library());
        LOG.info(
            " Current SlotLabelType:   "
                + currentCryptoTokenInfo.getP11SlotLabelType());
        LOG.info(
            " Current SlotLabel:       " + currentCryptoTokenInfo.getP11Slot());
        LOG.info(
            " Current Attribute file:  "
                + currentCryptoTokenInfo.getP11AttributeFile());
        if (!currentCryptoTokenInfo
            .getP11AttributeFile()
            .equals(cryptoTokenInfo.getP11AttributeFile())) {
          LOG.warn(" Ignoring that attribute file is different.");
        }
        if (force) {
          final CAToken currentCaToken = currentCaInfo.getCAToken();
          currentCaToken.setCryptoTokenId(cryptoTokenId);
          caSession.editCA(getAuthenticationToken(), currentCaInfo);
          LOG.info(" Merged.");
        }
        LOG.info("");
        mergeCount++;
      }
      if (force) {
        LOG.info("Modified referenced CryptoToken for " + mergeCount + " CAs.");
      } else {
        LOG.info(
            "Will modify referenced CryptoToken for "
                + mergeCount
                + " CAs if '"
                + EXECUTE_KEY
                + "' option is used.");
      }
      LOG.trace("<execute()");
    } catch (AuthorizationDeniedException e) {
      LOG.error("CLI User was not authorized to modify CA " + caName);
      LOG.trace("<execute()");
      return CommandResult.AUTHORIZATION_FAILURE;
    } catch (CADoesntExistsException e) {
      LOG.error("No such CA with by name " + caName);
      LOG.error(getCaList());
      return CommandResult.FUNCTIONAL_FAILURE;
    }
    LOG.trace("<execute()");
    return CommandResult.SUCCESS;
  }

  @Override
  public String getCommandDescription() {
    return "Merge all CA's sharing a PKCS#11 slot to use the same Crypto Token";
  }

  @Override
  public String getFullHelpText() {
    return getCommandDescription()
        + "\n\n"
        + "The specified CA's Crypto Token will be the one referenced by other"
        + " CAs that have the same HSM configuration.\n\n"
        + "The default behavior is to only show what would have changed since"
        + " this command is potentially very dangerous.\n"
        + "Use the "
        + EXECUTE_KEY
        + " switch to execute modifications."
        + "\n\n"
        + getCaList();
  }

  @Override
  protected Logger getLogger() {
    return LOG;
  }
}
