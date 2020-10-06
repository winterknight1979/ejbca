/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.Serializable;
import java.security.cert.Certificate;

/**
 * Richer version of the standard CertificateStatus object which also contains
 * the sought certificate, in order to avoid extra database lookups when both
 * are required.
 *
 * @version $Id: CertificateStatusHolder.java 20496 2014-12-22 06:41:16Z
 *     mikekushner $
 */
public class CertificateStatusHolder implements Serializable {

  private static final long serialVersionUID = -2881054831054645112L;
  /** Certificate. */
  private final Certificate certificate;
  /** Status. */
  private final CertificateStatus certificateStatus;

  /** Constructor.
   *
   * @param cert Cert
   * @param status Status
   */
  public CertificateStatusHolder(
      final Certificate cert,
      final CertificateStatus status) {
    this.certificate = cert;
    this.certificateStatus = status;
  }

  /** @return the sought certificate. May be null if status was unknown. */
  public Certificate getCertificate() {
    return certificate;
  }

  /** @return Status. */
  public CertificateStatus getCertificateStatus() {
    return certificateStatus;
  }
}
