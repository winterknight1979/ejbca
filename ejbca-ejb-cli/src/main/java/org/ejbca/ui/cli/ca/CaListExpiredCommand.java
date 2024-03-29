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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.EJBUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * List certificates that will expire within the given number of days.
 *
 * @version $Id: CaListExpiredCommand.java 21956 2015-09-30 16:23:43Z jeklund $
 */
public class CaListExpiredCommand extends EjbcaCommandBase {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CaListExpiredCommand.class);

  /** Param. */
  private static final String DAYS_KEY = "-d";

  {
    registerParameter(
        new Parameter(
            DAYS_KEY,
            "Days",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "Expire time in days"));
  }

  @Override
  public String getMainCommand() {
    return "listexpired";
  }

  @Override
  public String[] getCommandPath() {
    return new String[] {"ca"};
  }

  @Override
  public CommandResult execute(final ParameterContainer parameters) {
    CryptoProviderUtil.installBCProvider();
    long days;
    try {
      days = Long.parseLong(parameters.get(DAYS_KEY));
    } catch (NumberFormatException e) {
      LOG.error(parameters.get(DAYS_KEY) + " was not a number.");
      return CommandResult.FUNCTIONAL_FAILURE;
    }
    Date findDate = new Date();
    final long oneDay = 24 * 3600 * 1000;
    long millis = (days * oneDay);
    findDate.setTime(findDate.getTime() + millis);
    getLogger()
        .info("Looking for certificates that expire before " + findDate + ".");

    for (Certificate cert : getExpiredCerts(findDate)) {
      Date retDate;
      if (cert instanceof CardVerifiableCertificate) {
        try {
          retDate =
              ((CardVerifiableCertificate) cert)
                  .getCVCertificate()
                  .getCertificateBody()
                  .getValidTo();
        } catch (NoSuchFieldException e) {
          throw new IllegalStateException("Dependent library failure.", e);
        }
      } else {
        retDate = ((X509Certificate) cert).getNotAfter();
      }
      String subjectDN = CertTools.getSubjectDN(cert);
      String serNo = CertTools.getSerialNumberAsString(cert);
      getLogger()
          .info(
              "Certificate with subjectDN '"
                  + subjectDN
                  + "' and serialNumber '"
                  + serNo
                  + "' expires at "
                  + retDate
                  + ".");
    }
    return CommandResult.SUCCESS;
  }

  private Collection<Certificate> getExpiredCerts(final Date findDate) {
    try {
      getLogger().debug("Looking for cert with expireDate=" + findDate);
      Collection<Certificate> certs =
          EJBUtil.unwrapCertCollection(
              EjbRemoteHelper.INSTANCE
                  .getRemoteSession(CertificateStoreSessionRemote.class)
                  .findCertificatesByExpireTimeWithLimit(findDate));
      getLogger().debug("Found " + certs.size() + " certs.");
      return certs;
    } catch (Exception e) {
      getLogger().error("Error getting list of certificates", e);
    }
    return null;
  }

  @Override
  public String getCommandDescription() {
    return "List certificates that will expire within the given number of days";
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
