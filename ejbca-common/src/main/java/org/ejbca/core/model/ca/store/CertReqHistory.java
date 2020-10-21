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
package org.ejbca.core.model.ca.store;

import java.io.Serializable;
import java.util.Date;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Value object class containing the data stored in the CertReqHistory Entity
 * Bean. See constructor for details of its fields.
 *
 * @version $Id: CertReqHistory.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class CertReqHistory implements Serializable {
  private static final long serialVersionUID = -5449568418691275341L;
  /** FP. */
  private final String fingerprint;
/** SN. */
  private final String serialNumber;
  /** DN. */
  private final String issuerDN;
  /** User. */
  private final String username;
  /** Time. */
  private final Date timestamp;
  /** Info. */
  private final EndEntityInformation endEntityInformation;

  /**
   * @param aFingerprint the PK of the certificate in the CertificateDataBean
   * @param aSerialNumber of the certificate
   * @param anIssuerDN DN of the CA issuing the certificate
   * @param aUsername of the user used in the certificate request.
   * @param aTimestamp when the certicate was created.
   * @param theEndEntityInformation the userdata used to create the certificate.
   */
  public CertReqHistory(
      final String aFingerprint,
      final String aSerialNumber,
      final String anIssuerDN,
      final String aUsername,
      final Date aTimestamp,
      final EndEntityInformation theEndEntityInformation) {
    super();
    this.fingerprint = aFingerprint;
    this.serialNumber = aSerialNumber;
    this.issuerDN = anIssuerDN;
    this.username = aUsername;
    this.timestamp = aTimestamp;
    this.endEntityInformation = theEndEntityInformation;
  }
  /** @return Returns the issuerDN. */
  public String getFingerprint() {
    return fingerprint;
  }
  /** @return Returns the issuerDN. */
  public String getIssuerDN() {
    return issuerDN;
  }
  /** @return Returns the serialNumber. */
  public String getSerialNumber() {
    return serialNumber;
  }
  /** @return Returns the timestamp. */
  public Date getTimestamp() {
    return timestamp;
  }
  /** @return Returns the EndEntityInformation. */
  public EndEntityInformation getEndEntityInformation() {
    return endEntityInformation;
  }
  /** @return Returns the username. */
  public String getUsername() {
    return username;
  }
}
