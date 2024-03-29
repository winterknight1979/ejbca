/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.request;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Utility class to gather a few functions.
 *
 * @version $Id: RequestMessageUtils.java 27126 2017-11-13 09:28:54Z anatom $
 */
public abstract class RequestMessageUtils {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(RequestMessageUtils.class);

  /**
   * Tries to parse the byte array to create a request message of the correct
   * type. Currently handles PKCS10 request messages and CVC request messages.
   *
   * @param request byte array
   * @return IRequestMessage
   */
  public static RequestMessage parseRequestMessage(final byte[] request) {
    RequestMessage ret = null;
    try {
      ret = genPKCS10RequestMessage(request);
    } catch (IllegalArgumentException e) {
      LOG.debug(
          "Can not parse PKCS10 request, trying CVC instead: "
              + e.getMessage());
      ret = genCVCRequestMessage(request);
    }
    return ret;
  }

  /**
   * @param bytes PEM
   * @return Request message
   */
  public static PKCS10RequestMessage genPKCS10RequestMessage(
          final byte[] bytes) {
    byte[] buffer = getDecodedBytes(bytes);
    if (buffer == null) {
      return null;
    }
    return new PKCS10RequestMessage(buffer);
  } // genPKCS10RequestMessageFromPEM

  /**
   * @param bytes PEM
   * @return Request message
   */
  public static CVCRequestMessage genCVCRequestMessage(final byte[] bytes) {
    byte[] buffer = getDecodedBytes(bytes);
    if (buffer == null) {
      return null;
    }
    return new CVCRequestMessage(buffer);
  } // genCvcRequestMessageFromPEM

  /**
   * Tries to get decoded, if needed, bytes from a certificate request or
   * certificate.
   *
   * @param bytes pem (with headers), plain base64, or binary bytes with a CSR
   *     of certificate
   * @return binary bytes
   */
  public static byte[] getDecodedBytes(final byte[] bytes) {
    byte[] buffer = null;
    try {
      buffer = getRequestBytes(bytes);
    } catch (IOException e) {
      LOG.debug(
          "Message not base64 encoded? Trying as binary: " + e.getMessage());
      buffer = bytes;
    }
    return buffer;
  }

  /**
   * Tries to get decoded bytes from a certificate request or certificate.
   *
   * @param b64Encoded pem (with headers) or plain base64 with a CSR of
   *     certificate
   * @return binary bytes
   * @throws IOException on error
   */
  public static byte[] getRequestBytes(
          final byte[] b64Encoded) throws IOException {
    byte[] buffer = null;
    if (b64Encoded != null && b64Encoded.length > 0) {
      String str = new String(b64Encoded);
      // A real PKCS10 PEM request
      String beginKey = CertTools.BEGIN_CERTIFICATE_REQUEST;
      String endKey = CertTools.END_CERTIFICATE_REQUEST;
      if (!str.contains(beginKey)) {
        // Keytool PKCS10 PEM request
        beginKey = CertTools.BEGIN_KEYTOOL_CERTIFICATE_REQUEST;
        endKey = CertTools.END_KEYTOOL_CERTIFICATE_REQUEST;
        if (!str.contains(beginKey)) {
          // CSR can be a PEM encoded certificate instead of "certificate
          // request"
          beginKey = CertTools.BEGIN_CERTIFICATE;
          endKey = CertTools.END_CERTIFICATE;
          if (!str.contains(beginKey)) {
            // IE PKCS10 Base64 coded request
            try {
              buffer = Base64Util.decode(b64Encoded);
              if (buffer == null) {
                throw new IOException("Base64 decode of buffer returns null");
              }
            } catch (DecoderException de) {
              throw new IOException(
                  "Base64 decode fails, message not base64 encoded: "
                      + de.getMessage());
            }
          }
        }
      }
      if (buffer == null) {
        buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
      }
    } else {
      throw new IOException("Base64 decode fails, message is empty");
    }
    return buffer;
  }

  /**
   *
   * @param username User
   * @param password Pass
   * @param req Request
   * @param reqType Type
   * @return Request message
   * @throws SignRequestSignatureException faik
   * @throws InvalidKeyException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws IOException fail
   * @throws SignatureException fail
   * @throws InvalidKeySpecException fail
   * @throws ParseException fail
   * @throws ConstructionException fail
   * @throws NoSuchFieldException fail
   */
  public static RequestMessage getRequestMessageFromType(
      final String username,
      final String password,
      final String req,
      final int reqType)
      throws SignRequestSignatureException, InvalidKeyException,
          NoSuchAlgorithmException, NoSuchProviderException, IOException,
          SignatureException, InvalidKeySpecException, ParseException,
          ConstructionException, NoSuchFieldException {
    RequestMessage ret = null;
    if (reqType == CertificateConstants.CERT_REQ_TYPE_PKCS10) {
      ret = handlePKCS10(username, password, req);
    } else if (reqType == CertificateConstants.CERT_REQ_TYPE_SPKAC) {
      ret = handleSPKAC(username, password, req);
      if (ret == null) {
          return null;
      }
    } else if (reqType == CertificateConstants.CERT_REQ_TYPE_CRMF) {
      ret = handleCRMF(username, password, req);
    } else if (reqType == CertificateConstants.CERT_REQ_TYPE_PUBLICKEY) {
      ret = handlePublicKey(username, password, req);
    } else if (reqType == CertificateConstants.CERT_REQ_TYPE_CVC) {
      ret = handleCVC(username, password, req);
    }
    return ret;
  }

/**
 * @param username User
 * @param password Pwd
 * @param req Reeq
 * @return Message
 * @throws ParseException Fail
 * @throws ConstructionException Fail
 * @throws NoSuchFieldException Fail
 * @throws IOException Fail
 * @throws InvalidKeyException Fail
 * @throws NoSuchAlgorithmException Fail
 * @throws NoSuchProviderException Fail
 * @throws SignRequestSignatureException Fail
 */
private static RequestMessage handleCVC(final String username,
        final String password, final String req)
        throws ParseException, ConstructionException,
        NoSuchFieldException, IOException, InvalidKeyException,
        NoSuchAlgorithmException, NoSuchProviderException,
        SignRequestSignatureException {
    RequestMessage ret;
    CVCObject parsedObject =
          CertificateParser.parseCVCObject(Base64Util.decode(req.getBytes()));
      // We will handle both the case if the request is an authenticated
      // request, i.e. with an outer signature
      // and when the request is missing the (optional) outer signature.
      CVCertificate cvccert = null;
      if (parsedObject instanceof CVCAuthenticatedRequest) {
        CVCAuthenticatedRequest cvcreq = (CVCAuthenticatedRequest) parsedObject;
        cvccert = cvcreq.getRequest();
      } else {
        cvccert = (CVCertificate) parsedObject;
      }
      CVCRequestMessage reqmsg = new CVCRequestMessage(cvccert.getDEREncoded());
      reqmsg.setUsername(username);
      reqmsg.setPassword(password);
      // Popo is really actually verified by the CA (in SignSessionBean) as well
      if (!reqmsg.verify()) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("CVC POPO verification Failed");
        }
        throw new SignRequestSignatureException(
            "Invalid inner signature in CVCRequest, popo-verification failed.");
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug("POPO verification successful");
        }
      }
      ret = reqmsg;
    return ret;
}

/**
 * @param username User
 * @param password Pass
 * @param req Req
 * @return Message
 * @throws IOException Fail
 */
private static RequestMessage handlePublicKey(final String username,
        final String password, final String req)
        throws IOException {
    RequestMessage ret;
    byte[] request;
      // Request can be Base64 encoded or in PEM format
      try {
        request =
            FileTools.getBytesFromPEM(
                req.getBytes(),
                CertTools.BEGIN_PUBLIC_KEY,
                CertTools.END_PUBLIC_KEY);
      } catch (IOException ex) {
        try {
          request = Base64Util.decode(req.getBytes());
          if (request == null) {
            throw new IOException("Base64 decode of buffer returns null");
          }
        } catch (DecoderException de) {
          throw new IOException(
              "Base64 decode fails, message not base64 encoded: "
                  + de.getMessage());
        }
      }
      final PublicKey pubKey = KeyUtil.getPublicKeyFromBytes(request);
      ret = new SimpleRequestMessage(pubKey, username, password);
    return ret;
}

/**
 * @param username User
 * @param password Pass
 * @param req Req
 * @return Mess
 * @throws IOException Fail
 * @throws IllegalStateException Fail
 * @throws SignRequestSignatureException Fail
 */
private static RequestMessage handleCRMF(final String username,
        final String password, final String req) throws IOException,
        IllegalStateException, SignRequestSignatureException {
    RequestMessage ret = null;
    final byte[] certificateRequestMessages = Base64Util.decode(req.getBytes());
      final CertReqMsg certReqMsg =
          CertReqMsg.getInstance(
              ((ASN1Sequence)
                      ASN1Sequence.fromByteArray(certificateRequestMessages))
                  .getObjectAt(0));
      final JcaCertificateRequestMessage jcrm =
          new JcaCertificateRequestMessage(certReqMsg);
      try {
        final PublicKey publicKey = jcrm.getPublicKey();
        if (jcrm.hasProofOfPossession()) {
          switch (jcrm.getProofOfPossessionType()) {
            case JcaCertificateRequestMessage.popRaVerified:
                // The requestor claims that it is verified by an RA
                break;

            case JcaCertificateRequestMessage.popSigningKey:
                // RFC 4211 Section 4.1
                final POPOSigningKey popoSigningKey =
                    POPOSigningKey.getInstance(
                        jcrm.toASN1Structure().getPopo().getObject());
                if (LOG.isDebugEnabled()) {
                  doPopoLog(popoSigningKey);
                }
                final ContentVerifierProvider cvp =
                    CertTools.genContentVerifierProvider(publicKey);
                // Work around for bug in BC where
                // jcrm.hasSigningKeyProofOfPossessionWithPKMAC() will throw NPE
                // if PoposkInput is null
                if (popoSigningKey.getPoposkInput() != null
                    && jcrm.hasSigningKeyProofOfPossessionWithPKMAC()) {
                  final PKMACBuilder pkmacBuilder =
                      new PKMACBuilder(
                          new JcePKMACValuesCalculator()
                              .setProvider(BouncyCastleProvider.PROVIDER_NAME));
                  if (!jcrm.isValidSigningKeyPOP(
                      cvp, pkmacBuilder, password.toCharArray())) {
                    throw new SignRequestSignatureException(
                        "CRMF POP with PKMAC failed signature or MAC"
                            + " validation.");
                  } else {
                    if (LOG.isDebugEnabled()) {
                      LOG.debug(
                          "CRMF POP with PKMAC passed signature and PKMAC"
                              + " validation.");
                    }
                  }
                } else {
                  if (!jcrm.isValidSigningKeyPOP(cvp)) {
                    throw new SignRequestSignatureException(
                        "CRMF POP failed signature validation.");
                  } else {
                    if (LOG.isDebugEnabled()) {
                      LOG.debug("CRMF POP passed signature validation.");
                    }
                  }
                }
                break;

            case JcaCertificateRequestMessage.popKeyEncipherment:
                // RFC 4211 Section 4.2 (Not implemented)
                LOG.info(
                    "CRMF RFC4211 Section 4.2 KeyEncipherment POP validation"
                        + " is not implemented. Will try to use the request's"
                        + " public key anyway.");
                break;

            case JcaCertificateRequestMessage.popKeyAgreement:
                // RFC 4211 Section 4.3 (Not implemented)
                LOG.info(
                    "CRMF RFC4211 Section 4.3 KeyAgreement POP validation is"
                        + " not implemented. Will try to use the request's"
                        + " public key anyway.");
                break;

            default:
              throw new SignRequestSignatureException(
                  "CRMF POP of type "
                      + jcrm.getProofOfPossessionType()
                      + " is unknown.");
          }
        }
        final SimpleRequestMessage simpleRequestMessage =
            new SimpleRequestMessage(publicKey, username, password);
        simpleRequestMessage.setRequestExtensions(
            jcrm.getCertTemplate().getExtensions());
        ret = simpleRequestMessage;
      } catch (CRMFException e) {
        throw new SignRequestSignatureException(
            "CRMF POP verification failed.", e);
      } catch (OperatorCreationException e) {
        throw new SignRequestSignatureException(
            "CRMF POP verification failed.", e);
      }
    return ret;
}

/**
 * @param popoSigningKey key
 */
private static void doPopoLog(final POPOSigningKey popoSigningKey) {
    if (popoSigningKey != null) {
        LOG.debug(
            "CRMF POPOSigningKey poposkInput:                      "
                + popoSigningKey.getPoposkInput());
        if (popoSigningKey.getPoposkInput() != null) {
          LOG.debug(
              "CRMF POPOSigningKey poposkInput PublicKey:         "
                  + "   "
                  + popoSigningKey.getPoposkInput().getPublicKey());
          LOG.debug(
              "CRMF POPOSigningKey poposkInput PublicKeyMAC:      "
                  + "   "
                  + popoSigningKey
                      .getPoposkInput()
                      .getPublicKeyMAC());
        }
        LOG.debug(
            "CRMF POPOSigningKey algorithmIdentifier.algorithm.id: "
                + popoSigningKey
                    .getAlgorithmIdentifier()
                    .getAlgorithm()
                    .getId());
        LOG.debug(
            "CRMF POPOSigningKey signature:                        "
                + popoSigningKey.getSignature());
      } else {
        LOG.debug(
            "CRMF POPOSigningKey is not defined even though POP"
                + " type is popSigningKey. Validation will fail.");
      }
}

/**
 * @param username Usae
 * @param password Pass
 * @param req Req
 * @return Ret
 * @throws IOException Fail
 * @throws NoSuchAlgorithmException Fail
 * @throws InvalidKeyException Fail
 * @throws SignatureException Fail
 * @throws NoSuchProviderException Fail
 * @throws SignRequestSignatureException Fail
 */
private static RequestMessage handleSPKAC(final String username,
        final String password, final String req)
                throws IOException, NoSuchAlgorithmException,
                InvalidKeyException, SignatureException,
        NoSuchProviderException, SignRequestSignatureException {
    RequestMessage ret = null;
    byte[] reqBytes = req.getBytes();
      if (reqBytes != null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Received NS request: " + new String(reqBytes));
        }
        byte[] buffer = Base64Util.decode(reqBytes);
        if (buffer == null) {
          return null;
        }
        ASN1InputStream in =
            new ASN1InputStream(new ByteArrayInputStream(buffer));
        ASN1Sequence spkacSeq = (ASN1Sequence) in.readObject();
        in.close();
        NetscapeCertRequest nscr = new NetscapeCertRequest(spkacSeq);
        // Verify POPO, we don't care about the challenge, it's not important.
        nscr.setChallenge("challenge");
        if (!nscr.verify("challenge")) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("SPKAC POPO verification Failed");
          }
          throw new SignRequestSignatureException(
              "Invalid signature in NetscapeCertRequest, popo-verification"
                  + " failed.");
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug("POPO verification successful");
        }
        PublicKey pubKey = nscr.getPublicKey();
        ret = new SimpleRequestMessage(pubKey, username, password);
      }
    return ret;
}

/**
 * @param username User
 * @param password Pass
 * @param req Req
 * @return Message
 */
private static RequestMessage handlePKCS10(final String username,
        final String password, final String req) {
    RequestMessage ret;
    final PKCS10RequestMessage pkcs10RequestMessage =
          RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
      pkcs10RequestMessage.setUsername(username);
      pkcs10RequestMessage.setPassword(password);
      ret = pkcs10RequestMessage;
    return ret;
}
}
