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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.util.CertTools;

/**
 * A very simple confirmation message, no protection and a nullbody.
 *
 * @author tomas
 * @version $Id: CmpConfirmResponseMessage.java 28875 2018-05-08 13:44:40Z
 *     anatom $
 */
public class CmpConfirmResponseMessage extends BaseCmpMessage
    implements ResponseMessage {

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  static final long serialVersionUID = 10003L;

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CmpConfirmResponseMessage.class);

  /** Default digest algorithm for CMP response message, can be overridden. */
  private String digestAlg = CMSSignedGenerator.DIGEST_SHA1;
  /**
   * The default provider is BC, if nothing else is specified when setting
   * SignKeyInfo.
   */
  private String provider = "BC";
  /** Certificate for the signer of the response message (CA). */
  private transient Collection<Certificate> signCertChain = null;
  /** Private key used to sign the response message. */
  private transient PrivateKey signKey = null;

  /** The encoded response message. */
  private byte[] responseMessage = null;

  @Override
  public void setCrl(final CRL crl) { }

  @Override
  public void setIncludeCACert(final boolean incCACert) { }

  @Override
  public void setCACert(final Certificate cACert) { }

  @Override
  public byte[] getResponseMessage() {
    return responseMessage;
  }

  @Override
  public void setStatus(final ResponseStatus status) { }

  @Override
  public ResponseStatus getStatus() {
    return ResponseStatus.SUCCESS;
  }

  @Override
  public void setFailInfo(final FailInfo failInfo) { }

  @Override
  public FailInfo getFailInfo() {
    return null;
  }

  @Override
  public void setFailText(final String failText) { }

  @Override
  public String getFailText() {
    return null;
  }

  @Override
  public boolean create()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException {
    final PKIHeaderBuilder myPKIHeader =
        CmpMessageHelper.createPKIHeaderBuilder(
            getSender(),
            getRecipient(),
            getSenderNonce(),
            getRecipientNonce(),
            getTransactionId());
    final PKIBody myPKIBody = new PKIBody(19, DERNull.INSTANCE);
    PKIMessage myPKIMessage = null;

    if ((getPbeDigestAlg() != null)
        && (getPbeMacAlg() != null)
        && (getPbeKeyId() != null)
        && (getPbeKey() != null)) {
      myPKIHeader.setProtectionAlg(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(getPbeDigestAlg())));
      myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
      responseMessage =
          CmpMessageHelper.protectPKIMessageWithPBE(
              myPKIMessage,
              getPbeKeyId(),
              getPbeKey(),
              getPbeDigestAlg(),
              getPbeMacAlg(),
              getPbeIterationCount());
    } else {
      if ((signCertChain != null)
          && (signCertChain.size() > 0)
          && (signKey != null)) {
        try {
          myPKIHeader.setProtectionAlg(
              new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlg)));
          if (CollectionUtils.isNotEmpty(signCertChain)) {
            // set sender Key ID as well when the response is signed, so the
            // signer (CA) can have multiple certificates out there
            // with the same DN but different keys
            myPKIHeader.setSenderKID(
                CertTools.getSubjectKeyId(signCertChain.iterator().next()));
          }
          myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
          responseMessage =
              CmpMessageHelper.signPKIMessage(
                  myPKIMessage, signCertChain, signKey, digestAlg, provider);
        } catch (CertificateEncodingException e) {
          LOG.error("Error creating CmpConfirmMessage: ", e);
        } catch (SecurityException e) {
          LOG.error("Error creating CmpConfirmMessage: ", e);
        } catch (SignatureException e) {
          LOG.error("Error creating CmpConfirmMessage: ", e);
        }
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Not signing CMP Confirm Response, because signCert or signKey"
                  + " is not set.");
        }
      }
      // If we could not create the signed response message, create a
      // non-protected one instead.
      if (responseMessage == null) {
        myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        responseMessage = CmpMessageHelper.pkiMessageToByteArray(myPKIMessage);
      }
    }
    return true;
  }

  @Override
  public boolean requireSignKeyInfo() {
    return false;
  }

  @Override
  public void setSignKeyInfo(
      final Collection<Certificate> certs,
      final PrivateKey key,
      final String aprovider) {
    this.signCertChain = certs;
    this.signKey = key;
    if (aprovider != null) {
      this.provider = aprovider;
    }
  }

  @Override
  public void setRecipientKeyInfo(final byte[] recipientKeyInfo) { }

  @Override
  public void setPreferredDigestAlg(final String digest) {
    if (StringUtils.isNotEmpty(digest)) {
      this.digestAlg = digest;
    }
  }

  @Override
  public void setRequestType(final int reqtype) { }

  @Override
  public void setRequestId(final int reqid) { }

  @Override
  public void setProtectionParamsFromRequest(final RequestMessage reqMsg) { }
}
