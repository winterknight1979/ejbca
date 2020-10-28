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

package org.ejbca.core.ejb.keyrecovery;

import java.io.Serializable;

/**
 * Primary key for KeyRecoveryData.
 *
 * @version $Id: KeyRecoveryDataPK.java 25631 2017-04-03 09:55:10Z mikekushner $
 */
public class KeyRecoveryDataPK implements Serializable {

  private static final long serialVersionUID = 1L;

  /** SN. */
  private String certSN;
  /** Param. */
  private String issuerDN;

  /** Empty. */
  public KeyRecoveryDataPK()  { }

  /**
   * @param acertSN SN
   * @param anissuerDN DN
   */
  public KeyRecoveryDataPK(final String acertSN, final String anissuerDN) {
    setCertSN(acertSN);
    setIssuerDN(anissuerDN);
  }

  // @Column
  /**
   * Certificate serial number in hexa decimal format, of the certificate this
   * entry was stored for.
   *
   * @return SN
   */
  public String getCertSN() {
    return certSN;
  }

  /**
   * @param acertSN SN
   */
  public void setCertSN(final String acertSN) {
    this.certSN = acertSN;
  }

  /**
   * @return DN
   */
  // @Column
  public String getIssuerDN() {
    return issuerDN;
  }

  /**
   * @param anissuerDN DN
   */
  public void setIssuerDN(final String anissuerDN) {
    this.issuerDN = anissuerDN;
  }

  @Override
  public int hashCode() {
    int hashCode = 0;
    if (certSN != null) {
      hashCode += certSN.hashCode();
    }
    if (issuerDN != null) {
      hashCode += issuerDN.hashCode();
    }
    return hashCode;
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof KeyRecoveryDataPK)) {
      return false;
    }
    KeyRecoveryDataPK pk = (KeyRecoveryDataPK) obj;
    if (certSN == null || !certSN.equals(pk.certSN)) {
      return false;
    }
    if (issuerDN == null || !issuerDN.equals(pk.issuerDN)) {
      return false;
    }
    return true;
  }
}
