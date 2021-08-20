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

import java.security.cert.CertificateEncodingException;
import org.cesecore.util.Base64Util;

/**
 * Holds certificate WS elements.
 *
 * @version $Id: Certificate.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class Certificate extends TokenCertificateResponseWS {

    /** Param. */
  private byte[] certificateData = null;

  /** WS Constructor.  */
  public Certificate() { }

  /**
   * @param cert certificate
   * @throws CertificateEncodingException f
   */
  public Certificate(java.security.cert.Certificate cert)
      throws CertificateEncodingException {
    certificateData = Base64Util.encode(cert.getEncoded());
  }

  /**
   * @param certData data
   */
  public Certificate(byte[] certData) {
    certificateData = Base64Util.encode(certData);
  }

  /**
   * Returns the certificateData in binary format.
   *
   * @return the certificateData in binary format
   */
  public byte[] getRawCertificateData() {
    return Base64Util.decode(certificateData);
  }

  /**
   * Returns the certificateData in Base64 encoded format.
   *
   * @return the certificateData in Base64 encoded format
   */
  public byte[] getCertificateData() {
    return certificateData;
  }

  /**
   * Sets certificateData in Base64 encoded format.
   *
   * @param acertificateData The certificateData to set, in Base64 encoded
   *     format.
   */
  public void setCertificateData(byte[] acertificateData) {
    this.certificateData = acertificateData;
  }
}
