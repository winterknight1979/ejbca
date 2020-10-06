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

package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.util.Date;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Simple class encapsulating the certificate status information needed when
 * making revocation checks.
 *
 * @version $Id: CertificateStatus.java 22920 2016-03-03 17:44:03Z samuellb $
 */
public class CertificateStatus implements Serializable {

  private static final long serialVersionUID = 1515679904853388419L;

  /** Revoked. */
  public static final CertificateStatus REVOKED =
      new CertificateStatus(
          "REVOKED",
          -1L,
          RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
          CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
  /** OK. */
  public static final CertificateStatus OK =
      new CertificateStatus(
          "OK",
          -1L,
          RevokedCertInfo.NOT_REVOKED,
          CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
  /** Unavailable. */
  public static final CertificateStatus NOT_AVAILABLE =
      new CertificateStatus(
          "NOT_AVAILABLE",
          -1L,
          RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
          CertificateProfileConstants.CERTPROFILE_NO_PROFILE);

  /** Name. */
  private final String name;
  /** Date. */
  private final Date revocationDate;
  /** @see RevocationReasons */
  private final int revocationReason;
  /** ID. */
  private final int certificateProfileId;

  /** @return ID */
  public int getCertificateProfileId() {
    return certificateProfileId;
}

/**
   * Constructor.
   * @param aName Name
   * @param aDate Date
   * @param aReason Reason
   * @param aCertProfileId ID
   */
  public CertificateStatus(
      final String aName,
      final long aDate,
      final int aReason,
      final int aCertProfileId) {
    this.name = aName;
    this.revocationDate = new Date(aDate);
    this.revocationReason = aReason;
    this.certificateProfileId = aCertProfileId;
  }

  @Override
  public String toString() {
    return this.name;
  }

  @Override
  public boolean equals(final Object obj) {
    return obj instanceof CertificateStatus
        && this.equals((CertificateStatus) obj);
  }

  @Override
  public int hashCode() {
      return this.toString().hashCode();
  }


  /**
   * @param obj status
   * @return boolean
   */
  public boolean equals(final CertificateStatus obj) {
    return this.name.equals(obj.toString());
  }

  /** @return boolean */
  public boolean isRevoked() {
    return getRevocationReason() != RevokedCertInfo.NOT_REVOKED
        && getRevocationReason()
            != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
  }

/**
 * @return the revocationReason
 */
public int getRevocationReason() {
    return revocationReason;
}

/**
 * @return the revocationDate
 */
public Date getRevocationDate() {
    return revocationDate;
}
}
