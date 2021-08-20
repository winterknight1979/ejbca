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
import org.cesecore.util.EJBUtil;

/**
 * This is a class used for testing and example purposes. It is supposed to
 * illustrate how to implement a custom publisher in EJBCA 3.
 *
 * @version $Id: DummyCustomPublisher.java 23421 2016-05-12 13:16:22Z
 *     mikekushner $
 */
public class DummyCustomPublisher implements ICustomPublisher, Serializable {

  private static final long serialVersionUID = 1L;

  /** Logger. */
  private static Logger log = Logger.getLogger(DummyCustomPublisher.class);

  /** Cert. */
  private CertificateWrapper certificate = null;

  /** Creates a new instance of DummyCustomPublisher. */
  public DummyCustomPublisher() { }

  /**
   * @param properties props
   * @see
   *     org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
   */
  public void init(final Properties properties) {
    log.debug(
        "Initializing DummyCustomPublisher "
            + properties.getProperty(BasePublisher.DESCRIPTION, ""));
  }

  /**
   *
   * @param admin admin
   * @param incert The certificate to be stored.
   * @param username Username of end entity owning the certificate.
   * @param password Password given to the user, may be null if no password
   *     exists for the user.
   * @param userDN if a DN object is not found in the certificate use object
   *     from user data instead, can be null.
   * @param cafp Fingerprint (hex) of the CAs certificate.
   * @param status Status of the certificate (from
   *     CertificateDataBean.CERT_ACTIVE, CERT_REVOKED etc).
   * @param type Type of certificate (from
   *     CertificateDataBean.CERTTYPE_ENDENTITY etc).
   * @param revocationDate Date for revocation (of revoked), like
   *     System.currentTimeMillis(), or -1 if not revoked.
   * @param revocationReason reason for revocation from RevokedCertInfo,
   *     RevokedCertInfo.NOT_REVOKED if not revoked.
   * @param tag TAg
   * @param certificateProfileId Profile
   * @param lastUpdate Date
   * @param extendedinformation contains extended information about the user,
   *     like picture, is null if no extendedinformation exists about the user.
   * @return true if storage was successful.
   * @throws PublisherException if a communication or other error occurs.
   *
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
    this.certificate = EJBUtil.wrap(incert);
    return true;
  }
  /** @return cert */
  public Certificate getStoredCertificate() {
    return EJBUtil.unwrap(certificate);
  }
  /** @param admin token
   * @param incrl The DER coded CRL to be stored.
   * @param cafp Fingerprint (hex) of the CAs certificate.
   * @param number CRL number.
   * @param userDN if an DN object is not found in the certificate use object
   *     from user data instead, can be null.
   * @return true if storage was successful.
   * @throws PublisherException if a communication or other error occurs.
   *  @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL */
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
