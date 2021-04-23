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
package org.cesecore.certificates.ca;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * CvcPlugin is an interface for CVC CA implementation. There can be different
 * types of CVCCAs.
 *
 * @version $Id: CvcPlugin.java 27346 2017-11-28 16:14:30Z samuellb $
 */
public interface CvcPlugin {

  /** @return A string representing the type of CVC CA this is */
  String getCvcType();

  /**
   * @param cryptoToken Token
   * @param attributes Attrs
   * @param signAlg Algorithm
   * @param cacert CA Certificate
   * @param signatureKeyPurpose Purpose
   * @param certificateProfile Profile
   * @param cceConfig Config
   * @return Request
   * @throws CryptoTokenOfflineException if offline
   * @throws CertificateExtensionException if certificate has invalid extensions
   * @see org.cesecore.certificates.ca.CA#createRequest(CryptoToken, Collection,
   *     String, Certificate, int, CertificateProfile,
   *     AvailableCustomCertificateExtensionsConfiguration)
   */
  byte[] createRequest(
      CryptoToken cryptoToken,
      Collection<ASN1Encodable> attributes,
      String signAlg,
      Certificate cacert,
      int signatureKeyPurpose,
      CertificateProfile certificateProfile,
      AvailableCustomCertificateExtensionsConfiguration cceConfig)
      throws CryptoTokenOfflineException, CertificateExtensionException;

  /**
   * @param cryptoToken Token
   * @param request Request
   * @return Response
   * @throws CryptoTokenOfflineException if offline
   * @see org.cesecore.certificates.ca.CA#createAuthCertSignRequest(CryptoToken,
   *     byte[])
   */
  byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request)
      throws CryptoTokenOfflineException;

  /**
   * @param cryptoToken Token
   * @param createLinkCertificate bool
   * @param certProfile Profile
   * @param cceConfig Config
   * @param oldCaCert Old certificate
   * @throws CryptoTokenOfflineException if offline
   * @see
   *     org.cesecore.certificates.ca.CA#createOrRemoveLinkCertificate(CryptoToken,
   *     boolean, CertificateProfile,
   *     AvailableCustomCertificateExtensionsConfiguration, Certificate)
   */
  void createOrRemoveLinkCertificate(
      CryptoToken cryptoToken,
      boolean createLinkCertificate,
      CertificateProfile certProfile,
      AvailableCustomCertificateExtensionsConfiguration cceConfig,
      Certificate oldCaCert)
      throws CryptoTokenOfflineException;

  /**
   * @param cryptoToken Token
   * @param subject Subject
   * @param request Request
   * @param publicKey Public key
   * @param keyusage Usage
   * @param notBefore start date
   * @param notAfter End date
   * @param certProfile Profile
   * @param extensions extensions
   * @param sequence sequence
   * @param cceConfig config
   * @return certificate
   * @throws Exception on error
   * @see org.cesecore.certificates.ca.CA#generateCertificate(CryptoToken,
   *     EndEntityInformation, RequestMessage, PublicKey, int, 
   *     CA.CaCertValidity,
   *    CA.CaCertConfig)
   */
  Certificate generateCertificate(
      CryptoToken cryptoToken,
      EndEntityInformation subject,
      RequestMessage request,
      PublicKey publicKey,
      int keyusage,
      Date notBefore,
      Date notAfter,
      CertificateProfile certProfile,
      Extensions extensions,
      String sequence,
      AvailableCustomCertificateExtensionsConfiguration cceConfig)
      throws Exception;
}
