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

package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.KeyPair;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;

/**
 * Class used when delevering key recovery service response from a CA.
 *
 * @version $Id: KeyRecoveryCAServiceResponse.java 19901 2014-09-30 14:29:38Z
 *     anatom $
 */
public class KeyRecoveryCAServiceResponse extends ExtendedCAServiceResponse
    implements Serializable {

  private static final long serialVersionUID = -6164842390930090876L;
  /** Config. */
  public static final int TYPE_ENCRYPTKEYSRESPONSE = 1;
  /** Config. */
  public static final int TYPE_DECRYPTKEYSRESPONSE = 1;
  /** Type. */
  private final int type;
  /** Data. */
  private byte[] keydata;
  /** Data. */
  private KeyPair keypair;
  /** Alias. */
  private final String keyAlias;
  /** ID. */
  private final int cryptoTokenId;
  /** Key ID. */
  private final String publicKeyId;

  /**
   * Used when decrypting key recovery data, keydata is read from the database.
   *
   * @param aType Type
   * @param aKeydata key
   * @param aCryptoTokenId ID
   * @param aKeyAlias Key
   * @param aPublicKeyId Key ID
   */
  public KeyRecoveryCAServiceResponse(
      final int aType,
      final byte[] aKeydata,
      final int aCryptoTokenId,
      final String aKeyAlias,
      final String aPublicKeyId) {
    this.type = aType;
    this.keydata = aKeydata;
    this.cryptoTokenId = aCryptoTokenId;
    this.keyAlias = aKeyAlias;
    this.publicKeyId = aPublicKeyId;
  }

  /**
   * Used when encrypting data, keypair is encrypted to be stored in the
   * database.
   *
   * @param aType Type
   * @param aKeypair Key
   * @param aCryptoTokenId OD
   * @param aKeyAlias Key
   * @param aPublicKeyId Key ID
   */
  public KeyRecoveryCAServiceResponse(
      final int aType,
      final KeyPair aKeypair,
      final int aCryptoTokenId,
      final String aKeyAlias,
      final String aPublicKeyId) {
    this.type = aType;
    this.keypair = aKeypair;
    this.cryptoTokenId = aCryptoTokenId;
    this.keyAlias = aKeyAlias;
    this.publicKeyId = aPublicKeyId;
  }

  /** @return type of response, one of the TYPE_ constants. */
  public int getType() {
    return type;
  }

  /**
   * Method returning the encrypted key data if the type of response is
   * TYPE_ENCRYPTRESPONSE, null otherwise.
   *
   * @return data
   */
  public byte[] getKeyData() {
    byte[] ret = null;
    if (type == TYPE_ENCRYPTKEYSRESPONSE) {
      ret = keydata;
    }
    return ret;
  }

  /**
   * Method returning the decrypted keypair if the type of response is
   * TYPE_DECRYPTRESPONSE, null otherwise.
   *
   * @return Key
   */
  public KeyPair getKeyPair() {
    KeyPair ret = null;
    if (type == TYPE_DECRYPTKEYSRESPONSE) {
      ret = keypair;
    }
    return ret;
  }

  /**
   * @return Alias
   */
  public String getKeyAlias() {
    return keyAlias;
  }

  /**
   * @return ID
   */
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }

  /**
   * @return ID
   */
  public String getPublicKeyId() {
    return publicKeyId;
  }
}
