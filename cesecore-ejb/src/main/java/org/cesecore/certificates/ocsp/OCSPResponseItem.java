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

package org.cesecore.certificates.ocsp;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;

/**
 * Class used to encapsulate the data that goes into a OCSP response.
 *
 * @version $Id: OCSPResponseItem.java 28881 2018-05-08 18:18:11Z anatom $
 */
public class OCSPResponseItem implements Serializable {

  /**
   * Constants capturing the OCSP response status. These are the return codes
   * defined in the RFC. The codes are just used for simple access to the OCSP
   * return value.
   */
  public static final int OCSP_GOOD = 0;

  /** Tevoked. */
  public static final int OCSP_REVOKED = 1;
  /** Inknown. */
  public static final int OCSP_UNKNOWN = 2;

  private static final long serialVersionUID = 8520379864183774863L;

  /** ID. */
  private final CertificateID certID;
  /** Status. */
  private final CertificateStatus certStatus;
  /** RFC 2560 2.4: The time at which the status being
   * indicated is known to be correct. */
  private final Date thisUpdate;
  /**
   * RFC 2560 2.4: The time at or before which newer information
   *  will be available about the status of the certificate.
   *   If nextUpdate is not set,
   * the responder is indicating that newer revocation
   * information is available all the time.
   */
  private Date nextUpdate = null;

  /** Extensions. */
  private final Map<ASN1ObjectIdentifier, Extension> singleExtensions =
      new HashMap<ASN1ObjectIdentifier, Extension>();

  /**
   * @param aCertID ID
   * @param aCertStatus Status
   * @param untilNextUpdate Time
   */
  public OCSPResponseItem(
      final CertificateID aCertID,
      final CertificateStatus aCertStatus,
      final long untilNextUpdate) {
    this.certID = aCertID;
    this.certStatus = aCertStatus;
    this.thisUpdate = new Date();
    if (untilNextUpdate > 0) {
      this.nextUpdate = new Date(this.thisUpdate.getTime() + untilNextUpdate);
    }
  }

  /**
   * @return ID
   */
  public CertificateID getCertID() {
    return certID;
  }

  /**
   * @return status
   */
  public CertificateStatus getCertStatus() {
    return certStatus;
  }

  /**
   * @return date
   */
  public Date getThisUpdate() {
    return thisUpdate;
  }

  /**
   * @return date
   */
  public Date getNextUpdate() {
    return nextUpdate;
  }

  /**
   * @param extensions extensions
   */
  public void addExtensions(
      final Map<ASN1ObjectIdentifier, Extension> extensions) {
    singleExtensions.putAll(extensions);
  }

  /**
   * @return extensions
   */
  public Extensions buildExtensions() {
    Collection<Extension> extensionValues = singleExtensions.values();
    Extension[] extensions =
        extensionValues.toArray(new Extension[singleExtensions.size()]);
    return new Extensions(extensions);
  }
}
