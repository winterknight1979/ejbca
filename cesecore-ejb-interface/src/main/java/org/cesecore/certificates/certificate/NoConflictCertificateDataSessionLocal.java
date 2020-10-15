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

import java.util.Collection;
import java.util.List;
import javax.ejb.Local;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Local interface for NoConflictCertificateDataSession.
 *
 * @version $Id: NoConflictCertificateDataSessionLocal.java 28777 2018-04-26
 *     17:42:43Z samuellb $
 */
@Local
public interface NoConflictCertificateDataSessionLocal
    extends NoConflictCertificateDataSession {

  List<NoConflictCertificateData> findByFingerprint(String fingerprint);

  /**
   * @param serialNumber SN
   * @return return the query results as a List.
   */
  List<NoConflictCertificateData> findBySerialNumber(String serialNumber);

  /**
   * @param issuerDN DN
   * @param serialNumber SN
   * @return return the query results as a List.
   */
  List<NoConflictCertificateData> findByIssuerDNSerialNumber(
      String issuerDN, String serialNumber);

  /**
   * Returns a list with information about revoked certificates. Since the
   * NoConflictCertificateData table is append-only, the result may contain
   * duplicate entries, that should be filtered by date and revocation status.
   *
   * @param issuerDN DN
   * @param lastbasecrldate Date
   * @return revoked certs
   */
  Collection<RevokedCertInfo> getRevokedCertInfosWithDuplicates(
      String issuerDN, long lastbasecrldate);
}
