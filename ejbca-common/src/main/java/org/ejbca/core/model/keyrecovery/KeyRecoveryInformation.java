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

package org.ejbca.core.model.keyrecovery;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import org.cesecore.keys.util.KeyPairWrapper;
import org.cesecore.util.StringUtil;

/**
 * This is a value class containing the data relating to key saved for recovery
 * for a user, sent between server and clients.
 *
 * @version $Id: KeyRecoveryInformation.java 20728 2015-02-20 14:55:55Z
 *     mikekushner $
 */
public class KeyRecoveryInformation implements Serializable {

  private static final long serialVersionUID = -7473386427889757839L;

  // Private fields
  /** Serial. */
  private BigInteger certificatesn;
  /** DN. */
  private String issuerdn;
  /** User. */
  private String username;
  /** Bool. */
  private boolean markedasrecoverable;
  /** Keys. */
  private KeyPairWrapper keypair;
  /** cert. **/
  private Certificate certificate;

  // Public Constructors
  /**
   * @param acertificatesn serial
   * @param anissuerdn DN
   * @param ausername User
   * @param ismarkedasrecoverable bool
   * @param akeypair keys
   * @param acertificate cert
   */
  public KeyRecoveryInformation(
      final BigInteger acertificatesn,
      final String anissuerdn,
      final String ausername,
      final boolean ismarkedasrecoverable,
      final KeyPair akeypair,
      final Certificate acertificate) {
    this.certificatesn = acertificatesn;
    this.issuerdn = anissuerdn;
    this.username = StringUtil.stripUsername(ausername);
    this.markedasrecoverable = ismarkedasrecoverable;
    this.keypair = new KeyPairWrapper(akeypair);
    this.certificate = acertificate;
  }

  /** Creates a new KeyRecoveryData object. */
  public KeyRecoveryInformation() { }

  // Public Methods
  /**
   * @return serial
   */
  public BigInteger getCertificateSN() {
    return this.certificatesn;
  }

  /**
   * @param acertificatesn serial
   */
  public void setCertificateSN(final BigInteger acertificatesn) {
    this.certificatesn = acertificatesn;
  }

  /**
   * @return dn
   */
  public String getIssuerDN() {
    return this.issuerdn;
  }

  /**
   * @param anissuerdn DN
   */
  public void setIssuerDN(final String anissuerdn) {
    this.issuerdn = anissuerdn;
  }

  /**
   * @return user
   */
  public String getUsername() {
    return this.username;
  }

  /**
   * @param ausername user
   */
  public void setUsername(final String ausername) {
    this.username = StringUtil.stripUsername(ausername);
  }

  /**
   * @return bool
   */
  public boolean getMarkedAsRecoverable() {
    return this.markedasrecoverable;
  }

  /**
   * @param ismarkedasrecoverable bool
   */
  public void setMarkedAsRecoverable(final boolean ismarkedasrecoverable) {
    this.markedasrecoverable = ismarkedasrecoverable;
  }

  /**
   * @return keys
   */
  public KeyPair getKeyPair() {
    return keypair.getKeyPair();
  }

  /**
   * @param akeypair keys
   */
  public void setKeyPair(final KeyPair akeypair) {
    this.keypair = new KeyPairWrapper(akeypair);
  }

  /** @return Returns the certificate. */
  public Certificate getCertificate() {
    return certificate;
  }
  /** @param acertificate The certificate to set. */
  public void setCertificate(final Certificate acertificate) {
    this.certificate = acertificate;
  }
}
