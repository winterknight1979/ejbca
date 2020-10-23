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
import org.ejbca.core.protocol.acme.AcmeIdentifier.AcmeIdentifierTypes;

/**
 * An ACME Challenge is a proof a client needs to provide in order to be
 * authorized to get a certificate for an identifier.
 *
 * <p>PROCESSING constant in AcmeChallengeStatus ENUM is a requirement imposed
 * by draft-ietf-acme-acme-12 and is preserved for future use.
 *
 * @version $Id: AcmeChallenge.java 30434 2018-11-08 07:40:52Z andrey_s_helmes $
 */
public interface AcmeChallenge {

    /**
     * @return ID
     */
  String getChallengeId();

  /**
   * @param challengeId ID
   */
  void setChallengeId(String challengeId);

  /**
   * @return ID
   */
  String getAuthorizationId();

  /**
   * @param authorizationId ID
   */
  void setAuthorizationId(String authorizationId);

  /**
   * @return type
   */
  String getType();

  /**
   * @param type type
   */
  void setType(String type);

  /**
   * @return URL
   */
  String getUrl();

  /**
   * @param url URL
   */
  void setUrl(String url);

  /**
   * @return Status
   */
  AcmeChallengeStatus getStatus();

  /**
   * @param status Status
   */
  void setStatus(AcmeChallengeStatus status);

  /**
   * @return Val
   */
  String getValidated();

  /**
   * @param validated val
   */
  void setValidated(String validated);

  /**
   * @return token
   */
  String getToken();

  /**
   * @param token token
   */
  void setToken(String token);

  /**
   * @return auth
   */
  String getKeyAuthorization();

  /**
   * @param keyAuthorization Auth
   */
  void setKeyAuthorization(String keyAuthorization);

  /**
   * @return Version
   */
  float getLatestVersion();

  /** Upgrade. */
  void upgrade();

  /**
   * @return Data
   */
  LinkedHashMap<Object, Object> getRawData();

  enum AcmeChallengeType {
      /** HTTP. */
    DNS_HTTP_01(AcmeIdentifierTypes.DNS, "http-01"),
    /** DNS. */
    DNS_DNS_01(AcmeIdentifierTypes.DNS, "dns-01");

      /** ID. */
    private final AcmeIdentifierTypes acmeIdentifierType;
    /** Challenge. */
    private final String challengeType;

    /**
     * @param anacmeIdentifierType ID
     * @param achallengeType Chammenge
     */
    AcmeChallengeType(
        final AcmeIdentifierTypes anacmeIdentifierType,
        final String achallengeType) {
      this.acmeIdentifierType = anacmeIdentifierType;
      this.challengeType = achallengeType;
    }

    /**
     * @return Type
     */
    public AcmeIdentifierTypes getAcmeIdentifierType() {
      return acmeIdentifierType;
    }

    /**
     * @return Type
     */
    public String getChallengeType() {
      return challengeType;
    }
  }
}
