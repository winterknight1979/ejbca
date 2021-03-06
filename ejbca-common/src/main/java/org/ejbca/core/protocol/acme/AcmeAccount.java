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

import java.io.Serializable;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import org.cesecore.internal.IUpgradeableData;

/**
 * Interface for AcmeAccount implementations.
 *
 * @version $Id: AcmeAccount.java 29797 2018-09-04 07:37:48Z tarmo_r_helmes $
 */
public interface AcmeAccount extends Serializable, IUpgradeableData {

    /** Config. */
  String URL_PROTOCOL_MAILTO_START = "mailto:";

  /**
   * @return key
   */
  PublicKey getPublicKey();

  /**
   * @param publicKey key
   */
  void setPublicKey(PublicKey publicKey);

  /**
   * @return ID
   */
  String getAccountId();

  /**
   * @param accountId IS
   */
  void setAccountId(String accountId);

  /**
   * @return The status of this account. Possible values are: "valid",
   *     "deactivated", and "revoked". ...
   */
  String getStatus();

  /**
   * @param status Status
   */
  void setStatus(String status);

  /**
   * @return vontact
   */
  List<String> getContact();

  /**
   * @param contact Contact
   */
  void setContact(List<String> contact);

  /**
   * @return binding
   */
  String getExternalAccountBinding();

  /**
   * @param externalAccountBinding binding
   */
  void setExternalAccountBinding(String externalAccountBinding);

  /**
   * @return the version of Terms Of Service that the account holder has agreed
   *     to
   */
  String getTermsOfServiceAgreedVersion();

  /**
   * @param termsOfServiceAgreedVersion version
   */
  void setTermsOfServiceAgreedVersion(String termsOfServiceAgreedVersion);

  /**
   * @return ID
   */
  String getConfigurationId();

  /** @param configurationId the configurationId of this account */
  void setConfigurationId(String configurationId);

  /**
   * @return the first email address registered under this account or null if
   *     none exists (which should not happen since we require one)
   * @throws AcmeProblemException fail
   */
  String getContactEmail() throws AcmeProblemException;

  /**
   * @return version
   */
  float getLatestVersion();

  /** Upgrade. */
  void upgrade();

  /**
   * @return data
   */
  LinkedHashMap<Object, Object> getRawData();
}
