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
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;

/**
 * Class for standard X509 certificate extension. See rfc3280 or later for spec
 * of this extension.
 *
 * @version $Id: SubjectAltNames.java 22092 2015-10-26 13:58:55Z mikekushner $
 */
public class SubjectAltNames extends StandardCertificateExtension {
  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(SubjectAltNames.class);

  @Override
  public void init(final CertificateProfile certProf) {
    super.setOID(Extension.subjectAlternativeName.getId());
    super.setCriticalFlag(certProf.getSubjectAlternativeNameCritical());
  }

  @Override
  public ASN1Encodable getValue(
      final EndEntityInformation subject,
      final CA ca,
      final CertificateProfile certProfile,
      final PublicKey userPublicKey,
      final PublicKey caPublicKey,
      final CertificateValidity val) {
    GeneralNames ret = null;
    String altName = subject.getSubjectAltName();
    if (certProfile.getUseSubjectAltNameSubSet()) {
      altName = certProfile.createSubjectAltNameSubSet(altName);
    }
    if (altName != null && altName.length() > 0) {
      ret = CertTools.getGeneralNamesFromAltName(altName);
    }
    if (ret == null
        && LOG.isDebugEnabled()) {
        LOG.debug(
            "No altnames trying to make SubjectAltName extension: " + altName);

    }
    return ret;
  }
}
