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

package org.ejbca.core.model.ca.publisher;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.EJBTools;

/**
 * This is a class used for testing and example purposes. It is supposed to
 * illustrate how to implement a custom publisher in EJBCA 3.
 *
 * @version $Id: DummyCustomPublisher.java 23421 2016-05-12 13:16:22Z
 *     mikekushner $
 */
public class DummyCustomPublisher implements ICustomPublisher, Serializable {

  private static final long serialVersionUID = 1L;

  private static Logger log = Logger.getLogger(DummyCustomPublisher.class);

  private CertificateWrapper certificate = null;

  /** Creates a new instance of DummyCustomPublisher */
  public DummyCustomPublisher() {}

  /**
   * @see
   *     org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
   */
  public void init(final Properties properties) {
    log.debug(
        "Initializing DummyCustomPublisher "
            + properties.getProperty(BasePublisher.DESCRIPTION, ""));
  }

  /**
   * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate
   */
  public boolean storeCertificate(
      final AuthenticationToken admin,
      final Certificate incert,
      final String username,
      final String password,
      final String userDN,
      final String cafp,
      final int status,
      final int type,
      final long revocationDate,
      final int revocationReason,
      final String tag,
      final int certificateProfileId,
      final long lastUpdate,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    log.debug(
        "DummyCustomPublisher, Storing Certificate for user: " + username);
    this.certificate = EJBTools.wrap(incert);
    return true;
  }

  public Certificate getStoredCertificate() {
    return EJBTools.unwrap(certificate);
  }
  /** @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL */
  public boolean storeCRL(
      final AuthenticationToken admin,
      final byte[] incrl,
      final String cafp,
      final int number,
      final String userDN)
      throws PublisherException {
    log.debug("DummyCustomPublisher, Storing CRL");
    return true;
  }

  /**
   * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
   */
  public void testConnection() throws PublisherConnectionException {
    log.debug("DummyCustomPublisher, Testing connection");
  }

  @Override
  public boolean willPublishCertificate(
      final int status, final int revocationReason) {
    return true;
  }

  @Override
  public boolean isReadOnly() {
    return false;
  }
}
