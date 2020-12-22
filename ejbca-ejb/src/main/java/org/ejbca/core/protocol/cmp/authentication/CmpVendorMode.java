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

package org.ejbca.core.protocol.cmp.authentication;

import java.security.cert.X509Certificate;
import java.util.List;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.ejbca.config.CmpConfiguration;

/**
 * Check the authentication of the PKIMessage by verifying the signature from a
 * Vendor CA (3GPP mode).
 *
 * @version $Id: CmpVendorMode.java 26078 2017-06-26 13:13:17Z anatom $
 */
public interface CmpVendorMode {

    /**
     * @param caSession session
     */
  void setCaSession(CaSession caSession);

  /**
   * @param cmpConfiguration Config
   */
  void setCmpConfiguration(CmpConfiguration cmpConfiguration);

  /**
   * Checks if the certificate is issued by a configured Vendor CA, and that it
   * can be verified using that Vendor CA certificate.
   *
   * @param admin administrator making the call, must have access to get CAInfo
   *     for the Vendor CA
   * @param confAlias the CMP alias in use
   * @param extraCerts certificates from the extraCert field of the CMP request,
   *     a certificate path ordered with leaf certificate first (pos 0) and CA
   *     certificate(s) after
   * @return CAInfo if the Vendor CA, in the specified CMP alias, that issues
   *     the extraCert, null if no issuing Vendor CA was found.
   */
  CAInfo isExtraCertIssuedByVendorCA(
      AuthenticationToken admin,
      String confAlias,
      List<X509Certificate> extraCerts);

  /**
   * Checks whether authentication by vendor-issued-certificate should be used.
   * It can be used only in client mode and with initialization/certification
   * requests.
   *
   * @param reqType type
   * @param confAlias alias
   * @return 'True' if authentication by vendor-issued-certificate is used.
   *     'False' otherwise
   */
  boolean isVendorCertificateMode(int reqType, String confAlias);
}
