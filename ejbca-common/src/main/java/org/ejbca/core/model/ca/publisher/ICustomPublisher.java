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

import java.security.cert.Certificate;
import java.util.Properties;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;

/**
 * Interface containing methods that need to be implemented in order to have a
 * custom publisher. All Custom publishers must implement this interface.
 *
 * @version $Id: ICustomPublisher.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public interface ICustomPublisher {

  /**
   * Method called to all newly created ICustomPublishers to set it up with
   * saved configuration.
   *
   * @param properties Properties
   */
  void init(Properties properties);

  /**
   * @param admin Admin
   * @param incert Cert
   * @param username User
   * @param password PWD
   * @param userDN DN
   * @param cafp FP
   * @param status Ststus
   * @param type Type
   * @param revocationDate CRL date
   * @param revocationReason Reasin
   * @param tag Tag
   * @param certificateProfileId Profile
   * @param lastUpdate Date
   * @param extendedinformation Info
   * @return Cert
   * @throws PublisherException fail
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#storeCertificate
   */
  boolean storeCertificate(
      AuthenticationToken admin,
      Certificate incert,
      String username,
      String password,
      String userDN,
      String cafp,
      int status,
      int type,
      long revocationDate,
      int revocationReason,
      String tag,
      int certificateProfileId,
      long lastUpdate,
      ExtendedInformation extendedinformation)
      throws PublisherException;

  /**
   * @param admin Admin
   * @param incrl CRL
   * @param cafp FP
   * @param number Number
   * @param userDN DN
   * @return CRL
   * @throws PublisherException fail
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#storeCRL
   */
  boolean storeCRL(
      AuthenticationToken admin,
      byte[] incrl,
      String cafp,
      int number,
      String userDN)
      throws PublisherException;

  /**
   * @throws PublisherConnectionException Fail
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#testConnection
   */
  void testConnection() throws PublisherConnectionException;

  /**
   * Asks the publisher if the certificate with these parameters will be
   * published. Used by the publisher queue to avoid storing things that will
   * never be published in the publisher queue.
   *
   * @param status Status
   * @param revocationReason Reason
   * @return true if the certificate should be published.
   */
  boolean willPublishCertificate(int status, int revocationReason);

  /** @return true if this publisher type shouldn't be editable */
  boolean isReadOnly();
}
