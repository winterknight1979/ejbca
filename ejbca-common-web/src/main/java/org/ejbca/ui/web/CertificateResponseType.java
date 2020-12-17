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

/**
 * Used by the RequestHelper.pkcs10CertRequest method and as a HTTP parameter to
 * result_download.jsp page.
 *
 * @version $Id: CertificateResponseType.java 22139 2015-11-03 10:41:56Z
 *     mikekushner $
 */
public enum CertificateResponseType {
      /** Type. */
  UNSPECIFIED(0),
  /** Type. */
  ENCODED_CERTIFICATE(1),
  /** Type. */
  ENCODED_PKCS7(2),
  /** Type. */
  BINARY_CERTIFICATE(3),
  /** Type. */
  ENCODED_CERTIFICATE_CHAIN(4);

    /** PAram. */
  private final int number;

  /**
   * @param anumber ID
   */
  CertificateResponseType(final int anumber) {
    this.number = anumber;
  }

  /**
   * @return ID
   */
  public int getNumber() {
    return number;
  }

  /**
   * @param number ID
   * @return Type
   */
  public static CertificateResponseType fromNumber(final int number) {
    for (CertificateResponseType resptype : CertificateResponseType.values()) {
      if (resptype.getNumber() == number) {
        return resptype;
      }
    }
    throw new IllegalArgumentException(
        "No such certificate response type: " + number);
  }

  /**
   * @param number ID
   * @return Type
   */
  public static CertificateResponseType fromNumber(final String number) {
    return fromNumber(Integer.parseInt(number));
  }
}
