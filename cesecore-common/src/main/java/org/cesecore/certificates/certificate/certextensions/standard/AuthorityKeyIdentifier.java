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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.util.CertTools;

/**
 * Class for standard X509 certificate extension. See rfc3280 or later for spec
 * of this extension.
 *
 * @version $Id: AuthorityKeyIdentifier.java 22618 2016-01-20 15:00:45Z marko $
 */
public class AuthorityKeyIdentifier extends StandardCertificateExtension {
  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AuthorityKeyIdentifier.class);

  @Override
  public void init(final CertificateProfile certProf) {
    super.setOID(Extension.authorityKeyIdentifier.getId());
    super.setCriticalFlag(certProf.getAuthorityKeyIdentifierCritical());
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
    org.bouncycastle.asn1.x509.AuthorityKeyIdentifier ret = null;
    // Default value is that we calculate it from scratch!
    // (If this is a root CA we must calculate the AuthorityKeyIdentifier from
    // scratch)
    // (If the CA signing this cert does not have a SubjectKeyIdentifier we must
    // calculate the AuthorityKeyIdentifier from scratch)
    JcaX509ExtensionUtils extensionUtils =
        new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
    ret = extensionUtils.createAuthorityKeyIdentifier(caPublicKey);
    // If we have a CA-certificate (i.e. this is not a Root CA), we must take
    // the authority key identifier from
    // the CA-certificates SubjectKeyIdentifier if it exists. If we don't do
    // that we will get the wrong identifier if the
    // CA does not follow RFC3280 (guess if MS-CA follows RFC3280?)
    final X509Certificate cacert = getCACertificate(ca, caPublicKey);
    final boolean isRootCA =
        certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA;
    if (cacert != null && !isRootCA) {
      byte[] akibytes;
      akibytes = CertTools.getSubjectKeyId(cacert);
      if (akibytes != null) {
        // TODO: The code below is snipped from AuthorityKeyIdentifier.java in
        // BC 1.36, because there is no method there
        // to set only a pre-computed key identifier
        // This should be replaced when such a method is added to BC
        final ASN1OctetString keyidentifier = new DEROctetString(akibytes);
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 0, keyidentifier));
        final ASN1Sequence seq = new DERSequence(v);
        ret =
            org.bouncycastle.asn1.x509.AuthorityKeyIdentifier.getInstance(seq);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Using AuthorityKeyIdentifier from CA-certificates"
                  + " SubjectKeyIdentifier.");
        }
      }
    }
    return ret;
  }

  private X509Certificate getCACertificate(
      final CA ca, final PublicKey caPublicKey) {
    final List<Certificate> rolloverChain = ca.getRolloverCertificateChain();
    if (rolloverChain != null
        && rolloverChain.get(0).getPublicKey().equals(caPublicKey)) {
      return (X509Certificate) rolloverChain.get(0);
    } else {
      return (X509Certificate) ca.getCACertificate();
    }
  }
}
