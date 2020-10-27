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
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;

/**
 * Class used when requesting key recovery related services from a CA.
 *
 * @version $Id: KeyRecoveryCAServiceRequest.java 19901 2014-09-30 14:29:38Z
 *     anatom $
 */
public class KeyRecoveryCAServiceRequest extends ExtendedCAServiceRequest
    implements Serializable {

  private static final long serialVersionUID = -5686267640542389771L;
  /** Config. */
  public static final int COMMAND_ENCRYPTKEYS = 1;
  /** Config. */
  public static final int COMMAND_DECRYPTKEYS = 2;

  /** Command.*/
  private final int command;
  /** Data. */
  private byte[] keydata;
  /** Key. */
  private KeyPair keypair;
  /** ID. */
  private int cryptoTokenId;
  /** Alias. */
  private String keyAlias;

  /**
   * Constructor for KeyRecoveryCAServiceRequest used to decrypt data.
   *
   * @param aCommand Command
   * @param theKeydata Data
   * @param aCryptoTokenId ID
   * @param aKeyAlias key
   */
  public KeyRecoveryCAServiceRequest(
      final int aCommand,
      final byte[] theKeydata,
      final int aCryptoTokenId,
      final String aKeyAlias) {
    this.command = aCommand;
    this.keydata = theKeydata;
    this.cryptoTokenId = aCryptoTokenId;
    this.keyAlias = aKeyAlias;
  }

  /**
   * Constructor for KeyRecoveryCAServiceRequest used to encrypt data.
   *
   * @param aCommand Command
   * @param aKeypair Key
   */
  public KeyRecoveryCAServiceRequest(
          final int aCommand, final KeyPair aKeypair) {
    this.command = aCommand;
    this.keypair = aKeypair;
  }

  /**
   * @return command
   */
  public int getCommand() {
    return command;
  }

  /**
   * @return data belonging to the decrypt keys request, returns null otherwise.
   */
  public byte[] getKeyData() {
    byte[] ret = null;
    if (command == COMMAND_DECRYPTKEYS) {
      ret = keydata;
    }
    return ret;
  }

  /**
   * @return data belonging to the encrypt keys request, returns null otherwise.
   */
  public KeyPair getKeyPair() {
    KeyPair ret = null;
    if (command == COMMAND_ENCRYPTKEYS) {
      ret = keypair;
    }
    return ret;
  }

  /**
   * @return ID
   */
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }

  /**
   * @return Alias
   */
  public String getKeyAlias() {
    return keyAlias;
  }

  @Override
  public int getServiceType() {
    return ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE;
  }
}
