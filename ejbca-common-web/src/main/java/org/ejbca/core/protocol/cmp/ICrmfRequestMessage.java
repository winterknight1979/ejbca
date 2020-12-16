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
package org.ejbca.core.protocol.cmp;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;

/**
 * The {link IRequestMessage} parameter must implement this to when calling
 * {link CrmfRequestMessage#createResponseMessage(Class, IRequestMessage,
 * java.security.cert.Certificate, java.security.PrivateKey, String)}
 *
 * @version $Id: ICrmfRequestMessage.java 26542 2017-09-14 10:36:30Z anatom $
 */
public interface ICrmfRequestMessage extends RequestMessage {

  int getPbeIterationCount();

  String getPbeDigestAlg();

  String getPbeMacAlg();

  String getPbeKeyId();

  String getPbeKey();

  boolean isImplicitConfirm();

  /**
   * Returns the protocolEncrKey, as sent by the client to encrypt server
   * generated private keys with
   *
   * @return PublicKey to be used to encrypt a private key set by {@link
   *     #setServerGenKeyPair(KeyPair)}
   * @throws InvalidKeyException Fail
   * @throws NoSuchAlgorithmException Fail
   * @throws NoSuchProviderException Fail
   */
  PublicKey getProtocolEncrKey()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException;

  /**
   * Gets a SubjectPublicKeyInfo form the request. This is separate from the
   * {@link #getRequestPublicKey()}, because the SubjectPublicKeyInfo can be
   * empty, contain only and algorithmIdentifier in case when server generated
   * keys are requested.
   *
   * @return SubjectPublicKeyInfo, with the same public key as
   *     getRequestPublicKey, or null, or only an algorithmIdentifier.
   */
  SubjectPublicKeyInfo getRequestSubjectPublicKeyInfo();

  /**
   * Sets a key pair generated by the CA, in case the client request such keys
   * (protocol dependent).
   *
   * @param serverGenKeyPair a KeyPair with a private and public key generated
   *     by the CA, where the private key is to be returned to the client in the
   *     response
   */
  void setServerGenKeyPair(KeyPair serverGenKeyPair);

  /**
   * @return The server generated key pair set with {@link
   *     #setServerGenKeyPair(KeyPair)}
   */
  KeyPair getServerGenKeyPair();
}
