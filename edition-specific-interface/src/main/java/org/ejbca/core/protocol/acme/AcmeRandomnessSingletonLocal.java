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

/**
 * Source of required randomness used in the ACME protocol.
 *
 * @version $Id: AcmeRandomnessSingletonLocal.java 29657 2018-08-15 14:18:12Z
 *     tarmo_r_helmes $
 */
public interface AcmeRandomnessSingletonLocal {

  /**
   * https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-8.3
   *
   * <p>" token (required, string): A random value that uniquely identifies the
   * challenge. This value MUST have at least 128 bits of entropy. It MUST NOT
   * contain any characters outside the base64url alphabet, and MUST NOT include
   * base64 padding characters ("=")."
   *
   * <p>128 bits = 16 bytes
   *
   * @return token
   */
  String generateAcmeChallengeToken();

  /** @return the end entity password used to finalize the ACME order */
  String generateAcmeOrderEnrollmentCode();

  /**
   * @param byteCount count
   * @return a new unique identity for this local node (of the requested size)
   */
  byte[] generateAcmeNodeId(int byteCount);

  /**
   * @return ID
   */
  String generateAcmeAccountId();

  /**
   * @return ID
   */
  String generateAcmeChallengeId();

  /**
   * @param byteCount count
   * @return secret
   */
  byte[] generateReplayNonceSharedSecret(int byteCount);
}
