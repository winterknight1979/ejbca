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

import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * base class that this is a certificate response of either a Certificate or
 * KeyStore.
 *
 * @author Philip Vendil 2007 feb 8
 * @version $Id: TokenCertificateResponseWS.java 19902 2014-09-30 14:32:24Z
 *     anatom $
 */
public class TokenCertificateResponseWS {

      /** Param. */
  private int type = 0;
  /** Param. */
  private Certificate certificate;
  /** Param. */
  private KeyStore keyStore;

  /**
   * @param acertificate cert
   */
  public TokenCertificateResponseWS(Certificate acertificate) {
    super();
    this.type = HardTokenConstants.RESPONSETYPE_CERTIFICATE_RESPONSE;
    this.certificate = acertificate;
  }

  /**
   * @param akeyStore store
   */
  public TokenCertificateResponseWS(KeyStore akeyStore) {
    super();
    this.type = HardTokenConstants.RESPONSETYPE_KEYSTORE_RESPONSE;
    this.keyStore = akeyStore;
  }

  /** WS Constructor. */
  public TokenCertificateResponseWS() {
    super();
  }

  /**
   * @return cert
   */
  public Certificate getCertificate() {
    return certificate;
  }

  /**
   * @param acertificate ccert
   */
  public void setCertificate(Certificate acertificate) {
    this.certificate = acertificate;
  }

  /**
   * @return store
   */
  public KeyStore getKeyStore() {
    return keyStore;
  }

  /**
   * @param akeyStore store
   */
  public void setKeyStore(KeyStore akeyStore) {
    this.keyStore = akeyStore;
  }

  /**
   * @return type
   */
  public int getType() {
    return type;
  }

  /**
   * @param atype type
   */
  public void setType(int atype) {
    this.type = atype;
  }
}
