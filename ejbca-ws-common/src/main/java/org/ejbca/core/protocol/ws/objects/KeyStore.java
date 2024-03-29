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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.cesecore.util.Base64Util;

/**
 * Wrapper class for holding WS keystore data.
 *
 * @version $Id: KeyStore.java 29193 2018-06-11 06:24:34Z andresjakobs $
 */
public class KeyStore extends TokenCertificateResponseWS {

      /** Param. */
  private byte[] keystoreData = null;

  /** WS Constructor. */
  public KeyStore() { }

  /**
   * Creates a keystore by raw byte data with password.
   *
   * @param rawKeystoreData the raw keystore data.
   * @param password the password.
   */
  public KeyStore(byte[] rawKeystoreData, String password) {
    keystoreData = Base64Util.encode(rawKeystoreData);
  }

  /**
   * @param keystore KS
   * @param password PWD
   * @throws KeyStoreException fail
   * @throws NoSuchAlgorithmException fail
   * @throws IOException fail
   * @throws CertificateException fail
   */
  public KeyStore(java.security.KeyStore keystore, String password)
      throws KeyStoreException, NoSuchAlgorithmException, IOException,
          CertificateException {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      keystore.store(baos, password.toCharArray());
      keystoreData = Base64Util.encode(baos.toByteArray());
    }
  }

  /**
   * Returns the keystoreData in Base64 format.
   *
   * @return Returns the keystoreData, in Base64 encoded format.
   */
  public byte[] getKeystoreData() {
    return keystoreData;
  }

  /**
   * Returns the keystoreData in binary format.
   *
   * @return the keystoreData in binary format
   */
  public byte[] getRawKeystoreData() {
    return Base64Util.decode(keystoreData);
  }

  /**
   * Set keystore data in Base64 format.
   *
   * @param akeystoreData The keystoreData to set, in Base64 encoded format.
   */
  public void setKeystoreData(byte[] akeystoreData) {
    this.keystoreData = akeystoreData;
  }
}
