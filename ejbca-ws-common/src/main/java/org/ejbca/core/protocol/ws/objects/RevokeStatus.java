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
package org.ejbca.core.protocol.ws.objects;

import java.util.GregorianCalendar;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Class used when checking the revocation status of a certificate.
 *
 * <p>Contains the following data: IssuerDN CertificateSN (hex) RevokationDate
 * Reason (One of the REVOKATION_REASON constants)
 *
 * @author Philip Vendil
 * @version $Id: RevokeStatus.java 19902 2014-09-30 14:32:24Z anatom $
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(
    name = "revokeStatus",
    propOrder = {"certificateSN", "issuerDN", "reason", "revocationDate"})
public class RevokeStatus {

  /** Constants defining different revocation reasons. */
  public static final int NOT_REVOKED = RevokedCertInfo.NOT_REVOKED;

  /** Param. */
  public static final int REVOKATION_REASON_UNSPECIFIED =
      RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
  /** Param. */
  public static final int REVOKATION_REASON_KEYCOMPROMISE =
      RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE;
  /** Param. */
  public static final int REVOKATION_REASON_CACOMPROMISE =
      RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
  /** Param. */
  public static final int REVOKATION_REASON_AFFILIATIONCHANGED =
      RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED;
  /** Param. */
  public static final int REVOKATION_REASON_SUPERSEDED =
      RevokedCertInfo.REVOCATION_REASON_SUPERSEDED;
  /** Param. */
  public static final int REVOKATION_REASON_CESSATIONOFOPERATION =
      RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION;
  /** Param. */
  public static final int REVOKATION_REASON_CERTIFICATEHOLD =
      RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
  /** Param. */
  public static final int REVOKATION_REASON_REMOVEFROMCRL =
      RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
  /** Param. */
  public static final int REVOKATION_REASON_PRIVILEGESWITHDRAWN =
      RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN;
  /** Param. */
  public static final int REVOKATION_REASON_AACOMPROMISE =
      RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE;

  /** Param. */
  private String issuerDN;
  /** Param. */
  private String certificateSN;

  /** Param. */
  @XmlSchemaType(name = "dateTime")
  private XMLGregorianCalendar revocationDate;

  /** Param. */
  private int reason;

  /** Default Web Service Constuctor. */
  public RevokeStatus() { }

  /**
   * @param info info
   * @param anissuerDN DN
   * @throws DatatypeConfigurationException fail
   */
  public RevokeStatus(RevokedCertInfo info, String anissuerDN)
      throws DatatypeConfigurationException {
    certificateSN = info.getUserCertificate().toString(16);
    this.issuerDN = anissuerDN;
    GregorianCalendar cal = new GregorianCalendar();
    cal.setTime(info.getRevocationDate());
    revocationDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
    reason = info.getReason();
  }

  /**
   * @param info info
   * @param anissuerDN dn
   * @param serno sn
   * @throws DatatypeConfigurationException fail
   */
  public RevokeStatus(CertificateStatus info, String anissuerDN, String serno)
      throws DatatypeConfigurationException {
    certificateSN = serno;
    this.issuerDN = anissuerDN;
    GregorianCalendar cal = new GregorianCalendar();
    cal.setTime(info.getRevocationDate());
    revocationDate = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
    reason = info.getRevocationReason();
  }

  /** @return Returns the reason. */
  public int getReason() {
    return reason;
  }

  /** @param areason The reason to set. */
  public void setReason(int areason) {
    this.reason = areason;
  }

  /** @return Returns the revocationDate. */
  public XMLGregorianCalendar getRevocationDate() {
    return revocationDate;
  }

  /** @param arevocationDate The revocationDate to set. */
  public void setRevocationDate(XMLGregorianCalendar arevocationDate) {
    this.revocationDate = arevocationDate;
  }

  /** @return Returns the certificateSN in hex format. */
  public String getCertificateSN() {
    return certificateSN;
  }

  /** @param acertificateSN The certificateSN to set in hex format */
  public void setCertificateSN(String acertificateSN) {
    this.certificateSN = acertificateSN;
  }

  /** @return Returns the issuerDN. */
  public String getIssuerDN() {
    return issuerDN;
  }

  /** @param anissuerDN The issuerDN to set. */
  public void setIssuerDN(String anissuerDN) {
    this.issuerDN = anissuerDN;
  }
}
