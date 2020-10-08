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
package org.cesecore.keybind;

import java.io.Serializable;
import java.math.BigInteger;
import org.apache.commons.lang.StringUtils;

/**
 * (JavaBean-) XML Serializable representation of a trust anchor (CA Id) or
 * trusted certificate (CA Id and certificate serialnumber).
 *
 * <p>An undefined (null) serialnumber means ANY serialnumber.
 *
 * @version $Id: InternalKeyBindingTrustEntry.java 28587 2018-03-28 11:33:09Z
 *     henriks $
 */
public class InternalKeyBindingTrustEntry implements Serializable {

  private static final long serialVersionUID = 1L;

  /** ID. */
  private int caId = 0;
  /** SN. */
  private String certificateSerialNumberDecimal = null;
  /** Desc. */
  private String trustEntryDescription = null;

  /** Default constructor. */
  public InternalKeyBindingTrustEntry() { }

  /**
   * @param aCaId ID
   * @param certificateSerialNumber SN
   */
  public InternalKeyBindingTrustEntry(
      final int aCaId, final BigInteger certificateSerialNumber) {
    setCaId(aCaId);
    putCertificateSerialNumber(certificateSerialNumber);
  }

  /**
   * @param aCaId ID
   * @param aCertificateSerialNumber SN
   * @param description Desc
   */
  public InternalKeyBindingTrustEntry(
      final int aCaId,
      final BigInteger aCertificateSerialNumber,
      final String description) {
    setCaId(aCaId);
    putCertificateSerialNumber(aCertificateSerialNumber);
    // We don't want to put empty Strings. Use null instead
    if (!StringUtils.isEmpty(description)) {
      this.trustEntryDescription = description;
    }
  }

  /**
   * @return ID
   */
  public int getCaId() {
    return caId;
  }

  /**
   * @param aCaId ID
   */
  public void setCaId(final int aCaId) {
    this.caId = aCaId;
  }

  /**
   * @return SN
   */
  public String getCertificateSerialNumberDecimal() {
    return certificateSerialNumberDecimal;
  }

  /**
   * @param aCertificateSerialNumberDecimal SN
   */
  public void setCertificateSerialNumberDecimal(
      final String aCertificateSerialNumberDecimal) {
    this.certificateSerialNumberDecimal = aCertificateSerialNumberDecimal;
  }

  /**
   * @return desc
   */
  public String getTrustEntryDescription() {
    return trustEntryDescription;
  }

  /**
   * @param description desc.
   */
  public void setTrustEntryDescription(final String description) {
    this.trustEntryDescription = description;
  }

  /** NOTE: The getter and setter for a BigInteger must not
   * comply with the JavaBean spec for this to work with java.beans.XMLEncoder
   * NO_NOT_RENAME_TO get.
 * @return  sn*/
  public BigInteger fetchCertificateSerialNumber() {
    if (certificateSerialNumberDecimal == null) {
      return null;
    } else {
      return new BigInteger(certificateSerialNumberDecimal);
    }
  }

  /**
   *  NOTE: The getter and setter for a BigInteger must not
   * comply with the JavaBean spec for this to work with java.beans.XMLEncoder
   * NO_NOT_RENAME_TO set.
 * @param certificateSerialNumber SN */
  public void putCertificateSerialNumber(
          final BigInteger certificateSerialNumber) {
    if (certificateSerialNumber == null) {
      this.certificateSerialNumberDecimal = null;
    } else {
      this.certificateSerialNumberDecimal = certificateSerialNumber.toString();
    }
  }

  @Override
  public String toString() {
    final BigInteger certificateSerialNumber = fetchCertificateSerialNumber();
    if (certificateSerialNumber == null) {
      return Integer.valueOf(caId).toString();
    } else {
      return Integer.valueOf(caId).toString()
          + ";"
          + certificateSerialNumber.toString(16);
    }
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + caId;
    result = prime * result
            + ((certificateSerialNumberDecimal == null)
                    ? 0
                    : certificateSerialNumberDecimal.hashCode());
    result = prime * result + ((trustEntryDescription == null)
            ? 0
            : trustEntryDescription.hashCode());
    return result;
}

  @Override
  public boolean equals(final Object object) {
    if (!(object instanceof InternalKeyBindingTrustEntry)) {
        return false;
    }
    final InternalKeyBindingTrustEntry other =
            (InternalKeyBindingTrustEntry) object;
    if (caId != other.caId) {
        return false;
    }
    if (certificateSerialNumberDecimal == null
            && other.certificateSerialNumberDecimal == null) {
        return true;
    }
    return certificateSerialNumberDecimal != null
            && certificateSerialNumberDecimal.equals(
                    other.certificateSerialNumberDecimal);
}


}
