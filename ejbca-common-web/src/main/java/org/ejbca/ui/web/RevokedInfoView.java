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

package org.ejbca.ui.web;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.ejbca.core.model.SecConst;

/**
 * View of certificate revocation status.
 *
 * @version $Id: RevokedInfoView.java 22925 2016-03-03 22:25:34Z samuellb $
 */
public class RevokedInfoView implements Serializable {

  private static final long serialVersionUID = 1L;

  // Private fields.
  /** Param. */
  private final CertificateStatus revokedcertinfo;
  /** Param. */
  private final BigInteger certserno;

  /**
   * Creates a new instance of RevokedInfoView.
   *
   * @param arevokedcertinfo DOCUMENT ME!
   * @param certSerno SN
   */
  public RevokedInfoView(
      final CertificateStatus arevokedcertinfo, final BigInteger certSerno) {
    this.revokedcertinfo = arevokedcertinfo;
    this.certserno = certSerno;
  }

  // Public methods.
  /**
   * @return SN
   */
  public String getCertificateSerialNumberAsString() {
    return this.certserno.toString(16);
  }

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public BigInteger getCertificateSerialNumber() {
    return this.certserno;
  }

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  public Date getRevocationDate() {
    return this.revokedcertinfo.getRevocationDate();
  }

  /** @return the text key for the revocation reason if any, null otherwise */
  public String getRevocationReason() {
    String ret = null;
    final int reason = this.revokedcertinfo.getRevocationReason();
    if ((reason >= 0) && (reason < SecConst.HIGN_REASON_BOUNDRARY)) {
      ret = SecConst.REASONTEXTS[reason];
    }
    return ret;
  }
  /**
   * @return bool
   */
  public boolean isRevokedAndOnHold() {
    return this.revokedcertinfo.getRevocationReason()
        == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
  }

  /**
   * @return bool
   */
  public boolean isRevoked() {
    return this.revokedcertinfo.isRevoked();
  }
}
