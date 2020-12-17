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
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Collection;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;

/**
 * A very simple error message, no protection, or PBE protection.
 *
 * @version $Id: CmpErrorResponseMessage.java 22139 2015-11-03 10:41:56Z
 *     mikekushner $
 */
public class CmpErrorResponseMessage extends BaseCmpMessage
    implements ResponseMessage {

      /** Param. */
  private static Logger log = Logger.getLogger(CmpErrorResponseMessage.class);
  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  static final long serialVersionUID = 10003L;

  /** The encoded response message. */
  private byte[] responseMessage = null;

  /** Param. */
  private String failText = null;
  /** Param. */
  private FailInfo failInfo = null;
  /** Param. */
  private int requestId = 0;
  /** Param. */
  private final int generalError = 23;
  /** Param. */
  private int requestType = generalError; // 23 is general error message

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
    // Not used by CMP (create method of this class), but this message is
    // definitely a failure...
    return ResponseStatus.FAILURE;
  }

  @Override
  public void setFailInfo(final FailInfo thefailInfo) {
    this.failInfo = thefailInfo;
  }

  @Override
  public FailInfo getFailInfo() {
    return failInfo;
  }

  @Override
  public void setFailText(final String thefailText) {
    this.failText = thefailText;
  }

  @Override
  public String getFailText() {
    return failText;
  }

  @Override
  public boolean create()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException {
    final PKIHeaderBuilder myPKIHeaderBuilder =
        CmpMessageHelper.createPKIHeaderBuilder(
            getSender(),
            getRecipient(),
            getSenderNonce(),
            getRecipientNonce(),
            getTransactionId());
    boolean pbeProtected =
        (getPbeDigestAlg() != null)
            && (getPbeMacAlg() != null)
            && (getPbeKeyId() != null)
            && (getPbeKey() != null);
    if (pbeProtected) {
      myPKIHeaderBuilder.setProtectionAlg(
          new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac));
    }
    final PKIHeader myPKIHeader = myPKIHeaderBuilder.build();

    PKIStatusInfo myPKIStatusInfo = new PKIStatusInfo(PKIStatus.rejection);
    if (failInfo != null && failText != null) {
      myPKIStatusInfo =
          new PKIStatusInfo(
              PKIStatus.rejection,
              new PKIFreeText(new DERUTF8String(failText)),
              CmpMessageHelper.getPKIFailureInfo(failInfo.intValue()));
    } else if (failText != null) {
      myPKIStatusInfo =
          new PKIStatusInfo(
              PKIStatus.rejection,
              new PKIFreeText(new DERUTF8String(failText)));
    }

    PKIBody myPKIBody = null;
    log.debug("Create error message from requestType: " + requestType);
    if (requestType == 0 || requestType == 2) {
      myPKIBody =
          CmpMessageHelper.createCertRequestRejectBody(
              myPKIStatusInfo, requestId, requestType);
    } else {
      ErrorMsgContent myErrorContent = new ErrorMsgContent(myPKIStatusInfo);
      myPKIBody = new PKIBody(generalError, myErrorContent); // 23 = error
    }
    PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
    if (pbeProtected) {
      responseMessage =
          CmpMessageHelper.protectPKIMessageWithPBE(
              myPKIMessage,
              getPbeKeyId(),
              getPbeKey(),
              getPbeDigestAlg(),
              getPbeMacAlg(),
              getPbeIterationCount());
    } else {
      responseMessage = CmpMessageHelper.pkiMessageToByteArray(myPKIMessage);
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
      final String provider) { }

  @Override
  public void setRecipientKeyInfo(final byte[] recipientKeyInfo) { }

  @Override
  public void setPreferredDigestAlg(final String digest) { }

  @Override
  public void setRequestType(final int reqtype) {
    this.requestType = reqtype;
  }

  @Override
  public void setRequestId(final int reqid) {
    this.requestId = reqid;
  }

  @Override
  public void setProtectionParamsFromRequest(final RequestMessage reqMsg) { }
}
