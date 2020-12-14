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

  /** param. */
  private String issuerDN;
  /** param. */
  private String certificateSN;
  /** param. */
  private Integer reason;
  /** param. */
  private Date revocationDate;
  /** param. */
  private Integer certificateProfileId;
  /** param. */
  private boolean checkDate;

  /**
   * @param anissuerDN DN
   * @param acertificateSN Serial
   * @param areason Reason
   */
  public CertRevocationDto(
      final String anissuerDN, final String acertificateSN, final int areason) {
    this.issuerDN = anissuerDN;
    this.certificateSN = acertificateSN;
    this.reason = areason;
  }

  /**
   * @param anissuerDN DN
   * @param acertificateSN Serial
   */
  public CertRevocationDto(
          final String anissuerDN, final String acertificateSN) {
    this.issuerDN = anissuerDN;
    this.certificateSN = acertificateSN;
  }

  /**
   * @return DN
   */
  public String getIssuerDN() {
    return issuerDN;
  }

  /**
   * @param anissuerDN DN
   */
  public void setIssuerDN(final String anissuerDN) {
    this.issuerDN = anissuerDN;
  }

  /**
   * @return Serial
   */
  public String getCertificateSN() {
    return certificateSN;
  }

  /**
   * @param acertificateSN Serial
   */
  public void setCertificateSN(final String acertificateSN) {
    this.certificateSN = acertificateSN;
  }

  /**
   * @return Reason
   */
  public Integer getReason() {
    return reason;
  }

  /**
   * @param areason Reason
   */
  public void setReason(final Integer areason) {
    this.reason = areason;
  }

  /**
   * @return Date
   */
  public Date getRevocationDate() {
    return revocationDate;
  }

  /**
   * @param arevocationDate Date
   */
  public void setRevocationDate(final Date arevocationDate) {
    this.revocationDate = arevocationDate;
  }

  /**
   * @return ID
   */
  public Integer getCertificateProfileId() {
    return certificateProfileId;
  }

  /**
   * @param acertificateProfileId ID
   */
  public void setCertificateProfileId(final Integer acertificateProfileId) {
    this.certificateProfileId = acertificateProfileId;
  }

  /**
   * @return bool
   */
  public boolean isCheckDate() {
    return checkDate;
  }

  /**
   * @param acheckDate bool
   */
  public void setCheckDate(final boolean acheckDate) {
    this.checkDate = acheckDate;
  }
}
