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

package org.ejbca.core.protocol.acme;

import java.util.LinkedHashMap;

/**
 * An ACME Authorization is the right to issue certificates for an identifier
 * (e.g. a DNS Name).
 *
 * @version $Id: AcmeAuthorization.java 29141 2018-06-07 12:52:44Z aminkh $
 */
public interface AcmeAuthorization {

    /**
     * @return ID
     */
  String getOrderId();

  /**
   * @param orderId ID
   */
  void setOrderId(String orderId);

  /**
   * @return ID
   */
  String getAuthorizationId();

  /**
   * @param authorizationId ID
   */
  void setAuthorizationId(String authorizationId);

  /**
   * @return ID
   */
  String getAccountId();

  /**
   * @param accountId IS
   */
  void setAccountId(String accountId);

  /**
   * @return ID
   */
  AcmeIdentifier getAcmeIdentifier();

  /**
   * @param acmeIdentifier ID
   */
  void setAcmeIdentifier(AcmeIdentifier acmeIdentifier);

  /**
   * @return expiry
   */
  long getExpires();

  /**
   * @param expires expiry
   */
  void setExpires(long expires);

  /**
   * @return Wildcard
   */
  boolean getWildcard();

  /**
   * @param wildcard Wildcard
   */
  void setWildcard(boolean wildcard);

  /**
   * @return Status
   */
  AcmeAuthorizationStatus getStatus();

  /**
   * @param acmeAuthorizationStatus Status
   */
  void setStatus(AcmeAuthorizationStatus acmeAuthorizationStatus);

  /**
   * @return Version.
   */
  float getLatestVersion();

  /** Upgrade. */
  void upgrade();

  /**
   * @return data
   */
  LinkedHashMap<Object, Object> getRawData();
}
