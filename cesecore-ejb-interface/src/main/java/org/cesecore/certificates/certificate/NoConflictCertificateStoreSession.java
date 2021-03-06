/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.util.Collection;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Interface for NoConflictCertificateStoreSession.
 *
 * <p>These methods call CertificateStoreSession for certificates that are plain
 * CertificateData entities. See {@link CertificateStoreSession} for method
 * descriptions.
 *
 * <p>For NoConflictCertificateData the methods perform additional logic to
 * check that it gets the most recent entry if there's more than one (taking
 * permanent revocations into account), and for updates it appends new entries
 * instead of updating existing ones.
 *
 * @version $Id: NoConflictCertificateStoreSession.java 29433 2018-07-02
 *     16:55:26Z mikekushner $
 */
public interface NoConflictCertificateStoreSession {

  /**
   * @param issuerDN issuer DN of the desired certificate.
   * @param serno serial number of the desired certificate!
   * @return Status
   * @see CertificateStoreSession#getStatus
   */
  CertificateStatus getStatus(String issuerDN, BigInteger serno);

  /**
   * Gets full certificate meta data for the cert specified by issuer DN and
   * serial number.
   *
   * @param issuerdn issuer DN of the desired certificate.
   * @param certserno serial number of the desired certificate!
   * @return the sought certificate, or null if not found
   */
  CertificateDataWrapper getCertificateDataByIssuerAndSerno(
      String issuerdn, BigInteger certserno);

  /**
   * EJBCA expects all certificate entities to have a fingerprint. This method
   * generates a dummy fingerprint, to be used in NoConflictCertificateData and
   * for associated publisher queue entries.
   *
   * @param issuerdn issuer DN of the desired certificate.
   * @param certserno serial number of the desired certificate!
   * @return Hex encoded fingerprint. It is unique per issuerdn/serial.
   */
  String generateDummyFingerprint(String issuerdn, BigInteger certserno);

  /**
   * @param issuerdn issuerdn issuer DN of the desired certificate
   * @param lastbasecrldate Date of last CRL
   * @return List if revoked certs
   * @see CertificateStoreSession#listRevokedCertInfo
   */
  Collection<RevokedCertInfo> listRevokedCertInfo(
      String issuerdn, long lastbasecrldate);

  /**
   * @param admin Auth token
   * @param fingerprint FP
   * @param status Status
   * @return Success/fail
   * @throws AuthorizationDeniedException If unauthorized
   * @see CertificateStoreSession#setStatus
   */
  boolean setStatus(AuthenticationToken admin, String fingerprint, int status)
      throws AuthorizationDeniedException;

  /**
   * @return true if the CA is a throw-away CA which allow revocation of
   *     non-existing entries.
   * @param issuerDN Subject DN of CA to check.
   */
  boolean canRevokeNonExisting(String issuerDN);
}
