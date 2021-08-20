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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;

/**
 * Holds certificate WS response data.
 *
 * @version $Id: CertificateResponse.java 22553 2016-01-11 13:06:46Z mikekushner
 *     $
 */
public class CertificateResponse {


  /** Param. */
  private String responseType;
  /** Param. */
  private byte[] data = null;

  /** WS Constructor. */
  public CertificateResponse() { }

  /**
   * Main constructor.
   *
   * @param aresponseType one of the CertificateHelper.RESPONSETYPE_ constants
   * @param thedata non-base64 encoded
   */
  public CertificateResponse(String aresponseType, byte[] thedata) {
    this.data = Base64Util.encode(thedata);
    this.responseType = aresponseType;
  }

  /** @return responseType one of CertificateHelper.RESPONSETYPE_ constants */
  public String getResponseType() {
    return responseType;
  }

  /** @param aresponseType one of CertificateHelper.RESPONSETYPE_ constants */
  public void setResponseType(String aresponseType) {
    this.responseType = aresponseType;
  }

  /**
   * Returns Base64 encoded data.
   *
   * @return the data, Base64 encoded
   */
  public byte[] getData() {
    return data;
  }

  /**
   * Sets Base64 encode data.
   *
   * @param thedata of the type set in responseType, should be Base64 encoded
   */
  public void setData(byte[] thedata) {
    this.data = thedata;
  }

  /**
   * Returns a certificate from the data in the WS response.
   *
   * @return X.509
   * @throws CertificateException fail
   */
  public X509Certificate getCertificate() throws CertificateException {
    return CertTools.getCertfromByteArray(getRawData(), X509Certificate.class);
  }

  /**
   * Returns raw PKCS #7 or X509 data instead of the Base64 contained in the WS
   * response.
   *
   * @return fail
   */
  public byte[] getRawData() {
    return Base64Util.decode(data);
  }
}
