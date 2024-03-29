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
package org.cesecore.certificates.certificate.certextensions.standard;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * AuthorityInformationAccess
 *
 * <p>Class for standard X509 certificate extension. See rfc3280 or later for
 * spec of this extension.
 *
 * @version $Id: AuthorityInformationAccess.java 24591 2016-10-28 08:32:17Z
 *     anatom $
 */
public class AuthorityInformationAccess extends StandardCertificateExtension {
  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AuthorityInformationAccess.class);

  @Override
  public void init(final CertificateProfile certProf) {
    super.setOID(Extension.authorityInfoAccess.getId());
    super.setCriticalFlag(false);
  }

  @Override
  public ASN1Encodable getValue(
      final EndEntityInformation subject,
      final CA ca,
      final CertificateProfile certProfile,
      final PublicKey userPublicKey,
      final PublicKey caPublicKey,
      final CertificateValidity val)
      throws CertificateExtensionException {
    final X509CA x509ca = (X509CA) ca;
    List<String> caIssuerUris = new ArrayList<String>();
    List<String> ocspServiceLocatorUrls = new ArrayList<String>();

    // Get AIA by CAs default AIA section or by the certificate profiles
    // configuration.
    caIssuerUris = getIssuerUris(certProfile, x509ca);

    // Get OCSP by CAs default OCSP Service Locator section or by the
    // certificate profiles configuration.
    getOcsp(certProfile, x509ca, ocspServiceLocatorUrls);

    if (LOG.isDebugEnabled()) {
      LOG.debug("Using certificate AIA (CA Issuer URIs): " + caIssuerUris);
      LOG.debug(
          "Using certificate AIA (OCSP Service Locators): "
              + ocspServiceLocatorUrls);
    }

    final ASN1EncodableVector aia = new ASN1EncodableVector();
    for (String uri : caIssuerUris) {
      if (StringUtils.isNotEmpty(uri)) {
        aia.add(
            new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    new DERIA5String(uri))));
      }
    }
    for (String url : ocspServiceLocatorUrls) {
      if (StringUtils.isNotEmpty(url)) {
        aia.add(
            new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    new DERIA5String(url))));
      }
    }
    org.bouncycastle.asn1.x509.AuthorityInformationAccess ret = null;
    if (aia.size() > 0) {
      ret =
          org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
              new DERSequence(aia));
    }
    if (ret == null) {
      LOG.error(
          "AIA extension was used, but neither CA issuer URIs or OCSP service"
              + " locator URLs was defined!");
    }
    return ret;
  }

/**
 * @param certProfile Profilr
 * @param x509ca CA
 * @param ocspServiceLocatorUrls URLs
 */
private void getOcsp(final CertificateProfile certProfile,
        final X509CA x509ca, final List<String> ocspServiceLocatorUrls) {
    if (certProfile.getUseDefaultOCSPServiceLocator()) {
      if (StringUtils.isNotBlank(x509ca.getDefaultOCSPServiceLocator())) {
        ocspServiceLocatorUrls.add(x509ca.getDefaultOCSPServiceLocator());
      }
    } else {
      if (StringUtils.isNotBlank(certProfile.getOCSPServiceLocatorURI())) {
        ocspServiceLocatorUrls.add(certProfile.getOCSPServiceLocatorURI());
      }
    }
}

/**
 * @param certProfile Profile
 * @param x509ca CA
 * @return URIs
 */
private List<String> getIssuerUris(final CertificateProfile certProfile,
        final X509CA x509ca) {
    List<String> caIssuerUris;
    if (certProfile.getUseDefaultCAIssuer()) {
      caIssuerUris = x509ca.getCertificateAiaDefaultCaIssuerUri();
    } else {
      caIssuerUris = certProfile.getCaIssuers();
    }
    return caIssuerUris;
}
}
