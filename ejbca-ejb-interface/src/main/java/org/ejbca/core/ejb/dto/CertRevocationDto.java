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
package org.ejbca.core.ejb.dto;

import java.io.Serializable;
import java.util.Date;

/**
 * Wrapper class for holding input parameters of revokeCertWithMetadata
 * operation.
 *
 * @version $Id: CertRevocationDto.java 28674 2018-05-03 10:17:34Z
 *     tarmo_r_helmes $
 */
public class CertRevocationDto implements Serializable {

  private static final long serialVersionUID = 1L;

  String issuerDN;
  String certificateSN;
  Integer reason;
  Date revocationDate;
  Integer certificateProfileId;
  boolean checkDate;

  public CertRevocationDto(
      final String issuerDN, final String certificateSN, final int reason) {
    this.issuerDN = issuerDN;
    this.certificateSN = certificateSN;
    this.reason = reason;
  }

  public CertRevocationDto(final String issuerDN, final String certificateSN) {
    this.issuerDN = issuerDN;
    this.certificateSN = certificateSN;
  }

  public String getIssuerDN() {
    return issuerDN;
  }

  public void setIssuerDN(final String issuerDN) {
    this.issuerDN = issuerDN;
  }

  public String getCertificateSN() {
    return certificateSN;
  }

  public void setCertificateSN(final String certificateSN) {
    this.certificateSN = certificateSN;
  }

  public Integer getReason() {
    return reason;
  }

  public void setReason(final Integer reason) {
    this.reason = reason;
  }

  public Date getRevocationDate() {
    return revocationDate;
  }

  public void setRevocationDate(final Date revocationDate) {
    this.revocationDate = revocationDate;
  }

  public Integer getCertificateProfileId() {
    return certificateProfileId;
  }

  public void setCertificateProfileId(final Integer certificateProfileId) {
    this.certificateProfileId = certificateProfileId;
  }

  public boolean isCheckDate() {
    return checkDate;
  }

  public void setCheckDate(final boolean checkDate) {
    this.checkDate = checkDate;
  }
}
