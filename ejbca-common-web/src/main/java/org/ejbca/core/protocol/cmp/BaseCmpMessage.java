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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.cesecore.util.Base64Util;

/**
 * Base class for CMP request messages.
 *
 * @version $Id: BaseCmpMessage.java 28286 2018-02-14 20:51:41Z bastianf $
 */
public abstract class BaseCmpMessage implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private transient PKIMessage pkiMessage = null;
  /** Param. */
  private String b64SenderNonce = null;
  /** Param. */
  private String b64RecipientNonce = null;
  /** Param. */
  private String b64TransId = null;
  /** Param. */
  private transient GeneralName recipient =
      null; // GeneralName is not Serializable
  /** Param. */
  private byte[] recipientBytes = null;
  /** Param. */
  private transient GeneralName sender =
      null; // GeneralName is not Serializable
  /** Param. */
  private byte[] senderBytes = null;
  /** Param. */
  private String protectionType = null;
  /** Param. */
  private String pbeDigestAlg = null;
  /** Param. */
  private String pbeMacAlg = null;
  /** Param. */
  private final int defaultCount = 1024;
  /** Param. */
  private int pbeIterationCount = defaultCount;
  /** Param. */
  private String pbeKeyId = null;
  /** Param. */
  private String pbeKey = null;

  /** Param. */
  private List<Certificate> additionalCaCertificates =
      new ArrayList<Certificate>();

  /** Param. */
  private List<Certificate> additionalExtraCerts = new ArrayList<Certificate>();

  /**
   * @param asn1OctetString Octets
   * @return the ASN.1 encoded octets as a bas64 encoded String or null if no
   *     such data is available
   */
  protected String getBase64FromAsn1OctetString(
      final ASN1OctetString asn1OctetString) {
    if (asn1OctetString != null) {
      final byte[] val = asn1OctetString.getOctets();
      if (val != null) {
        return new String(Base64Util.encode(val));
      }
    }
    return null;
  }
  /**
   * @param asn1Encodable ASN.1
   * @return the byte array representation of the ASN.1 object
   * @throws IllegalStateException fail
   */
  private byte[] getByteArrayFromAsn1Encodable(
      final ASN1Encodable asn1Encodable) throws IllegalStateException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      new ASN1OutputStream(baos).writeObject(asn1Encodable);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  /**
   * @param b64nonce nonce
   */
  public void setSenderNonce(final String b64nonce) {
    this.b64SenderNonce = b64nonce;
  }

  /**
   * @return nonce
   */
  public String getSenderNonce() {
    return b64SenderNonce;
  }

  /**
   * @param b64nonce nonce
   */
  public void setRecipientNonce(final String b64nonce) {
    this.b64RecipientNonce = b64nonce;
  }

  /**
   * @return nonce
   */
  public String getRecipientNonce() {
    return b64RecipientNonce;
  }

  /**
   * @param b64transid ID
   */
  public void setTransactionId(final String b64transid) {
    this.b64TransId = b64transid;
  }

  /**
   * @return ID
   */
  public String getTransactionId() {
    return b64TransId;
  }

  /**
   * @return Recip
   */
  public GeneralName getRecipient() {
    if (recipient == null && recipientBytes != null) {
      recipient = GeneralName.getInstance(recipientBytes);
    }
    return recipient;
  }

  /**
   * @param arecipient recip
   */
  public void setRecipient(final GeneralName arecipient) {
    this.recipient = arecipient;
    recipientBytes = getByteArrayFromAsn1Encodable(arecipient);
  }

  /**
   * @return sender
   */
  public GeneralName getSender() {
    if (sender == null && senderBytes != null) {
      sender = GeneralName.getInstance(senderBytes);
    }
    return sender;
  }

  /**
   * @param asender sender
   */
  public void setSender(final GeneralName asender) {
    this.sender = asender;
    senderBytes = getByteArrayFromAsn1Encodable(asender);
  }

  /**
   * @return header
   */
  public PKIHeader getHeader() {
    return pkiMessage.getHeader();
  }

  /**
   * @return Message
   */
  public PKIMessage getMessage() {
    return pkiMessage;
  }

  /**
   * @param apkiMessage Message
   */
  public void setMessage(final PKIMessage apkiMessage) {
    this.pkiMessage = apkiMessage;
  }

  /**
   * @return Type
   */
  public String getProtectionType() {
    return protectionType;
  }

  /**
   * @param aprotectionType type
   */
  public void setProtectionType(final String aprotectionType) {
    this.protectionType = aprotectionType;
  }

  /**
   * @param keyId IF
   * @param key Key
   * @param digestAlg Digest
   * @param macAlg Mac
   * @param iterationCount Count
   */
  public void setPbeParameters(
      final String keyId,
      final String key,
      final String digestAlg,
      final String macAlg,
      final int iterationCount) {
    this.pbeKeyId = keyId;
    this.pbeKey = key;
    this.pbeDigestAlg = digestAlg;
    this.pbeMacAlg = macAlg;
    this.pbeIterationCount = iterationCount;
  }

  /**
   * @return Alg
   */
  public String getPbeDigestAlg() {
    return pbeDigestAlg;
  }

  /**
   * @return Key
   */
  public String getPbeKey() {
    return pbeKey;
  }

  /**
   * @return ID
   */
  public String getPbeKeyId() {
    return pbeKeyId;
  }

  /**
   * @return Alg
   */
  public String getPbeMacAlg() {
    return pbeMacAlg;
  }

  /**
   * @return Count
   */
  public int getPbeIterationCount() {
    return pbeIterationCount;
  }

  /**
   * Gets the list of additional CA certificates (i.e. to be appended to the
   * user certificates CA certificate returned in the CMP response message
   * caPubs field).
   *
   * @return the list of CA certificates.
   */
  public List<Certificate> getAdditionalCaCertificates() {
    return additionalCaCertificates;
  }

  /**
   * Sets the list of additional CA certificates (i.e. to be appended to the
   * user certificates CA certificate returned in the CMP response message
   * caPubs field).
   *
   * @param certificates the list of CA certificates.
   */
  public void setAdditionalCaCertificates(
      final List<Certificate> certificates) {
    this.additionalCaCertificates = certificates;
  }

  /**
   * Gets the list of additional CA certificates to be appended to the PKI
   * response message extraCerts field.
   *
   * @return the list of CA certificates.
   */
  public List<Certificate> getAdditionalExtraCertsCertificates() {
    return additionalExtraCerts;
  }

  /**
   * Sets the list of additional CA certificates to be appended to the PKI
   * response message extraCerts field.
   *
   * @param certificates the list of CA certificates.
   */
  public void setAdditionalExtraCertsCertificates(
      final List<Certificate> certificates) {
    this.additionalExtraCerts = certificates;
  }
}
