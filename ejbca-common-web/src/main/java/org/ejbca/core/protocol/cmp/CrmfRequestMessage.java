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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.cmp.authentication.RegTokenPasswordExtractor;

/**
 * Certificate request message (crmf) according to RFC4211. - Supported POPO: --
 * raVerified (null), i.e. no POPO verification is done, it should be
 * configurable if the CA should allow this or require a real POPO -- Self
 * signature, using the key in CertTemplate, or POPOSigningKeyInput (name and
 * public key), option 2 and 3 in RFC4211, section "4.1. Signature Key POP"
 *
 * @version $Id: CrmfRequestMessage.java 26542 2017-09-14 10:36:30Z anatom $
 */
public class CrmfRequestMessage extends BaseCmpMessage
    implements ICrmfRequestMessage {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(CrmfRequestMessage.class);

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  static final long serialVersionUID = 1002L;

  /** Param. */
  public static final ASN1ObjectIdentifier ID_REGCTRL_PROTOCOL_ENCRKEY =
      CRMFObjectIdentifiers.id_regCtrl.branch("6");

  /** Param. */
  private int requestType = 0;
  /** Param. */
  private int requestId = 0;
  /** Param. */
  private String b64SenderNonce = null;
  /** Param. */
  private String b64TransId = null;
  /** Default CA DN. */
  private String defaultCADN = null;

  /** Param. */
  private boolean allowRaVerifyPopo = false;
  /** Param. */
  private String extractUsernameComponent = null;
  /** manually set username. */
  private String username = null;
  /** manually set password. */
  private String password = null;
  /** manually set public and private key,
   * if keys have been server generated. */
  private transient KeyPair serverGenKeyPair;

  /**
   * Because PKIMessage is not serializable we need to have the serializable
   * bytes save as well, so we can restore the PKIMessage after
   * serialization/deserialization.
   */
  private byte[] pkimsgbytes = null;

  /** Param. */
  private transient CertReqMsg req = null;

  /**
   * Because CertReqMsg is not serializable we may need to encode/decode bytes
   * if the object is lost during deserialization.
   *
   * @return message
   */
  private CertReqMsg getReq() {
    if (req == null) {
      init();
    }
    return this.req;
  }

  /** preferred digest algorithm to use in replies, if applicable. */
  private String preferredDigestAlg = CMSSignedGenerator.DIGEST_SHA1;

  /** Default. */
  public CrmfRequestMessage() { }

  /**
   * @param apkiMessage PKIMessage
   * @param adefaultCADN possibility to enforce a certain CA, instead of taking
   *     the CA subject DN from the request, if set to null the CA subject DN is
   *     taken from the request
   * @param anallowRaVerifyPopo true if we allows the user/RA to specify the POP
   *     should not be verified
   * @param theextractUsernameComponent Defines which component from the DN
   *      should
   *     be used as username in EJBCA. Can be CN, UID or nothing. Null means
   *     that the username should have been pre-set, or that here it is the same
   *     as CN.
   */
  public CrmfRequestMessage(
      final PKIMessage apkiMessage,
      final String adefaultCADN,
      final boolean anallowRaVerifyPopo,
      final String theextractUsernameComponent) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">CrmfRequestMessage");
    }
    setPKIMessage(apkiMessage);
    this.defaultCADN = adefaultCADN;
    this.allowRaVerifyPopo = anallowRaVerifyPopo;
    this.extractUsernameComponent = theextractUsernameComponent;
    init();
    if (LOG.isTraceEnabled()) {
      LOG.trace("<CrmfRequestMessage");
    }
  }

  /**
   * @return Message
   */
  public PKIMessage getPKIMessage() {
    if (getMessage() == null) {
      setMessage(PKIMessage.getInstance(pkimsgbytes));
    }
    return getMessage();
  }

  /**
   * @param msg Message
   */
  public void setPKIMessage(final PKIMessage msg) {
    try {
      this.pkimsgbytes = msg.toASN1Primitive().getEncoded();
    } catch (IOException e) {
      LOG.error("Error getting encoded bytes from PKIMessage: ", e);
    }
    setMessage(msg);
  }

  private void init() {
    final PKIBody pkiBody = getPKIMessage().getBody();
    final PKIHeader pkiHeader = getPKIMessage().getHeader();
    requestType = pkiBody.getType();
    final CertReqMessages msgs = getCertReqFromTag(pkiBody, requestType);
    try {
      this.req = msgs.toCertReqMsgArray()[0];
    } catch (Exception e) {
      this.req = CmpMessageHelper.getNovosecCertReqMsg(msgs);
    }
    requestId = this.req.getCertReq().getCertReqId().getValue().intValue();
    setTransactionId(
        getBase64FromAsn1OctetString(pkiHeader.getTransactionID()));
    setSenderNonce(getBase64FromAsn1OctetString(pkiHeader.getSenderNonce()));
    setRecipient(pkiHeader.getRecipient());
    setSender(pkiHeader.getSender());
  }

  @Override
  public PublicKey getRequestPublicKey()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException {
    // If we have generated a key pair by the server, we should use this one
    if (serverGenKeyPair != null) {
      return serverGenKeyPair.getPublic();
    }
    // Else, see if we can find one in the request
    final SubjectPublicKeyInfo keyInfo = getRequestSubjectPublicKeyInfo();
    if (keyInfo == null) {
      // No public key, which may be OK if we are requesting server generated
      // keys
      return null;
    }
    final PublicKey pk =
        getPublicKey(keyInfo, BouncyCastleProvider.PROVIDER_NAME);
    return pk;
  }

  @Override
  public SubjectPublicKeyInfo getRequestSubjectPublicKeyInfo() {
    final CertRequest request = getReq().getCertReq();
    final CertTemplate templ = request.getCertTemplate();
    final SubjectPublicKeyInfo keyInfo = templ.getPublicKey();
    return keyInfo;
  }

  @SuppressWarnings("unlikely-arg-type")
  private PublicKey getPublicKey(
      final SubjectPublicKeyInfo subjectPKInfo, final String provider)
      throws NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException {
    // If there is no public key here, but only an empty bit string, it means we
    // have called for server generated keys
    // i.e. no public key to see here...
    if (subjectPKInfo.getPublicKeyData().equals(DERNull.INSTANCE)) {
      return null;
    }
    try {
      final X509EncodedKeySpec xspec =
          new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getBytes());
      final AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();
      return KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), provider)
          .generatePublic(xspec);
    } catch (InvalidKeySpecException | IOException e) {
      final InvalidKeyException newe =
          new InvalidKeyException("Error decoding public key.");
      newe.initCause(e);
      throw newe;
    }
  }

  @Override
  public PublicKey getProtocolEncrKey()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException {
    final CertRequest request = getReq().getCertReq();
    Controls controls = request.getControls();
    if (controls != null) {
      AttributeTypeAndValue[] avs = controls.toAttributeTypeAndValueArray();
      if (avs != null) {
        for (int i = 0; i < avs.length; i++) {
          if (avs[i]
              .getType()
              .equals(CrmfRequestMessage.ID_REGCTRL_PROTOCOL_ENCRKEY)) {
            ASN1Encodable asn1 = avs[i].getValue();
            if (asn1 != null) {
              SubjectPublicKeyInfo spi = SubjectPublicKeyInfo.getInstance(asn1);
              if (spi != null) {
                return getPublicKey(spi, BouncyCastleProvider.PROVIDER_NAME);
              }
            }
          }
        }
      }
    }
    return null;
  }

  @Override
  public KeyPair getServerGenKeyPair() {
    return serverGenKeyPair;
  }

  @Override
  public void setServerGenKeyPair(final KeyPair aserverGenKeyPair) {
    this.serverGenKeyPair = aserverGenKeyPair;
  }

  /**
   * force a password, i.e. ignore the password in the request
   *
   * @param pwd PWD
   */
  public void setPassword(final String pwd) {
    this.password = pwd;
  }

  @Override
  public String getPassword() {
    if (password != null) {
      return this.password;
    }

    RegTokenPasswordExtractor regTokenExtractor =
        new RegTokenPasswordExtractor();

    if (regTokenExtractor.verifyOrExtract(getPKIMessage(), null)) {
      this.password = regTokenExtractor.getAuthenticationString();
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug(regTokenExtractor.getErrorMessage());
      }
    }
    return this.password;
  }

  /**
   * force a username, i.e. ignore the DN/username in the request
   *
   * @param ausername User
   */
  public void setUsername(final String ausername) {
    this.username = ausername;
  }

  @Override
  public String getUsername() {
    String ret = null;
    if (username != null) {
      ret = username;
    } else {
      // We can configure which part of the users DN should be used as username
      // in EJBCA, for example CN or UID
      String component = extractUsernameComponent;
      if (StringUtils.isEmpty(component)) {
        component = "CN";
      }
      String name = CertTools.getPartFromDN(getRequestDN(), component);
      if (name == null) {
        LOG.error("No component " + component + " in DN: " + getRequestDN());
      } else {
        ret = name;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Username is: " + ret);
    }
    return ret;
  }

  /**
   * @param issuer issuer
   */
  public void setIssuerDN(final String issuer) {
    this.defaultCADN = issuer;
  }

  @Override
  public String getIssuerDN() {
    String ret = null;
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    final X500Name name = templ.getIssuer();
    if (name != null) {
      ret = CertTools.stringToBCDNString(name.toString());
    } else {
      ret = defaultCADN;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Issuer DN is: " + ret);
    }
    return ret;
  }

  @Override
  public BigInteger getSerialNo() {
    return null;
  }

  @Override
  public String getCRLIssuerDN() {
    return null;
  }

  @Override
  public BigInteger getCRLSerialNo() {
    return null;
  }

  /**
   * Gets a requested certificate serial number of the subject. This is a
   * standard field in the CertTemplate in the request. However the standard RFC
   * 4211, section 5 (CertRequest syntax) says it MUST not be used. Requesting
   * custom certificate serial numbers is a very non-standard procedure anyhow,
   * so we use it anyway.
   *
   * @return BigInteger the requested custom certificate serial number or null,
   *     normally this should return null.
   */
  public BigInteger getSubjectCertSerialNo() {
    BigInteger ret = null;
    final CertRequest request = getReq().getCertReq();
    final CertTemplate templ = request.getCertTemplate();
    final ASN1Integer serno = templ.getSerialNumber();
    if (serno != null) {
      ret = serno.getValue();
    }
    return ret;
  }

  @Override
  public String getRequestDN() {
    String ret = null;
    final X500Name name = getRequestX500Name();
    if (name != null) {
      ret = CertTools.stringToBCDNString(name.toString());
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Request DN is: " + ret);
    }
    return ret;
  }

  @Override
  public X500Name getRequestX500Name() {
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    X500Name name = templ.getSubject();
    if (name != null) {
      name = X500Name.getInstance(new CeSecoreNameStyle(), name);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Request X500Name is: " + name);
    }
    return name;
  }

  @Override
  public String getRequestAltNames() {
    String ret = null;
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    final Extensions exts = templ.getExtensions();
    if (exts != null) {
      final Extension ext = exts.getExtension(Extension.subjectAlternativeName);
      if (ext != null) {
        ret = CertTools.getAltNameStringFromExtension(ext);
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Request altName is: " + ret);
    }
    return ret;
  }

  @Override
  public Date getRequestValidityNotBefore() {
    Date ret = null;
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    final OptionalValidity val = templ.getValidity();
    if (val != null) {
      final Time time = val.getNotBefore();
      if (time != null) {
        ret = time.getDate();
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Request validity notBefore is: "
              + (ret == null ? "null" : ret.toString()));
    }
    return ret;
  }

  @Override
  public Date getRequestValidityNotAfter() {
    Date ret = null;
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    final OptionalValidity val = templ.getValidity();
    if (val != null) {
      final Time time = val.getNotAfter();
      if (time != null) {
        ret = time.getDate();
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Request validity notAfter is: "
              + (ret == null ? "null" : ret.toString()));
    }
    return ret;
  }

  @Override
  public Extensions getRequestExtensions() {
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    final Extensions exts = templ.getExtensions();
    if (LOG.isDebugEnabled()) {
      if (exts != null) {
        LOG.debug("Request contains extensions");
      } else {
        LOG.debug("Request does not contain extensions");
      }
    }
    return exts;
  }

  @Override
  public boolean verify()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException {
    boolean ret = false;
    final ProofOfPossession pop = getReq().getPopo();
    if (LOG.isDebugEnabled()) {
      LOG.debug("allowRaVerifyPopo: " + allowRaVerifyPopo);
      if (pop != null) {
        LOG.debug(
            "pop.getRaVerified(): "
                + (pop.getType() == ProofOfPossession.TYPE_RA_VERIFIED));
      } else {
        LOG.debug("No POP in message");
      }
    }
    if (pop == null) {
      // POP can be null only if we don't have a public key in the message, then
      // we request
      // server generated keys, and don't send any POP
      // This can be either no public key info, or public key info with a algId
      // followed by a zero length bitstring
      // SubjectPublicKeyInfo ::= SEQUENCE {
      //   algorithm AlgorithmIdentifier,
      //   publicKey BIT STRING }
      SubjectPublicKeyInfo pkinfo = getRequestSubjectPublicKeyInfo();
      if (pkinfo == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "POP is not present, but neither is a SubjectPublicKeyInfo, so"
                  + " POP is OK...for server generated keys.");
        }
        ret = true; // public key null, this is OK when there is no POP
      } else if (pkinfo.getAlgorithm() != null
          && pkinfo.getPublicKeyData().intValue() == 0) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "POP is not present, but SubjectPublicKeyInfo is, with an algId"
                  + " followed by zero length data, so POP is OK...for server"
                  + " generated keys.");
        }
        ret = true;
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "POP is not present, but SubjectPublicKey is, but not with an"
                  + " algId followed by zero length data, POP is not OK...not"
                  + " even for server generated keys.");
        }
        ret = false;
      }
    } else if (allowRaVerifyPopo
        && (pop.getType() == ProofOfPossession.TYPE_RA_VERIFIED)) {
      ret = true;
    } else if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY) {
      try {
        final POPOSigningKey sk = (POPOSigningKey) pop.getObject();
        final POPOSigningKeyInput pski = sk.getPoposkInput();
        ASN1Encodable protObject = pski;
        // Use of POPOSigningKeyInput or not, as described in RFC4211, section
        // 4.1.
        if (pski == null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Using CertRequest as POPO input because POPOSigningKeyInput"
                    + " is missing.");
          }
          protObject = getReq().getCertReq();
        } else {
          // Assume POPOSigningKeyInput with the public key and name, MUST be
          // the same as in the request according to RFC4211
          if (LOG.isDebugEnabled()) {
            LOG.debug("Using POPOSigningKeyInput as POPO input.");
          }
          final CertRequest areq = getReq().getCertReq();
          // If subject is present in cert template it must be the same as in
          // POPOSigningKeyInput
          final X500Name subject = areq.getCertTemplate().getSubject();
          if (subject != null
              && !subject
                  .toString()
                  .equals(pski.getSender().getName().toString())) {
            LOG.info(
                "Subject '"
                    + subject.toString()
                    + "', is not equal to '"
                    + pski.getSender().toString()
                    + "'.");
            protObject = null; // pski is not a valid protection object
          }
          // If public key is present in cert template it must be the same as in
          // POPOSigningKeyInput
          final SubjectPublicKeyInfo pk = areq.getCertTemplate().getPublicKey();
          if (pk != null
              && !Arrays.areEqual(
                  pk.getEncoded(), pski.getPublicKey().getEncoded())) {
            LOG.info(
                "Subject key in cert template, is not equal to subject key in"
                    + " POPOSigningKeyInput.");
            protObject = null; // pski is not a valid protection object
          }
        }
        // If a protectObject is present we extract the bytes and verify it
        if (protObject != null) {
          final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ASN1OutputStream.create(bao, ASN1Encoding.DER).writeObject(protObject);
          final byte[] protBytes = bao.toByteArray();
          final AlgorithmIdentifier algId = sk.getAlgorithmIdentifier();
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "POP protection bytes length: "
                    + (protBytes != null ? protBytes.length : "null"));
            LOG.debug(
                "POP algorithm identifier is: " + algId.getAlgorithm().getId());
          }
          final Signature sig =
              Signature.getInstance(algId.getAlgorithm().getId(), "BC");
          sig.initVerify(getRequestPublicKey());
          sig.update(protBytes);
          final DERBitString bs = sk.getSignature();
          ret = sig.verify(bs.getBytes());
          if (LOG.isDebugEnabled()) {
            LOG.debug("POP verify returns: " + ret);
          }
        }
      } catch (IOException e) {
        LOG.error("Error encoding CertReqMsg: ", e);
      } catch (SignatureException e) {
        LOG.error("SignatureException verifying POP: ", e);
      }
    }
    return ret;
  }

  @Override
  public boolean requireKeyInfo() {
    return false;
  }

  @Override
  public void setKeyInfo(
      final Certificate cert, final PrivateKey key, final String provider) { }

  @Override
  public int getErrorNo() {
    return 0;
  }

  @Override
  public String getErrorText() {
    return null;
  }

  @Override
  public void setSenderNonce(final String b64nonce) {
    this.b64SenderNonce = b64nonce;
  }

  @Override
  public String getSenderNonce() {
    return b64SenderNonce;
  }

  @Override
  public void setTransactionId(final String b64transid) {
    this.b64TransId = b64transid;
  }

  @Override
  public String getTransactionId() {
    return b64TransId;
  }

  @Override
  public byte[] getRequestKeyInfo() {
    return null;
  }

  @Override
  public String getPreferredDigestAlg() {
    return preferredDigestAlg;
  }

  /**
   * @param digestAlgo Alg
   */
  public void setPreferredDigestAlg(final String digestAlgo) {
    if (StringUtils.isNotEmpty(digestAlgo)) {
      preferredDigestAlg = digestAlgo;
    }
  }

  @Override
  public boolean includeCACert() {
    return false;
  }

  @Override
  public int getRequestType() {
    return requestType;
  }

  @Override
  public int getRequestId() {
    return requestId;
  }

  /** @return the subject DN from the request, used from CrmfMessageHandler */
  public String getSubjectDN() {
    String ret = null;
    final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    final X500Name name = templ.getSubject();
    if (name != null) {
      ret = CertTools.stringToBCDNString(name.toString());
    }
    return ret;
  }

  private CertReqMessages getCertReqFromTag(final PKIBody body, final int tag) {
    CertReqMessages msgs = null;
    if (tag == 0 || tag == 2 || tag == 7 || tag == 9 || tag == 13) {
      msgs = (CertReqMessages) body.getContent();
    }
    return msgs;
  }

  @Override
  public void setResponseKeyInfo(final PrivateKey key, final String provider) {
    // These values are never used for this type of message
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Key and provider were set for a CrmfRequestMessage. These values"
              + " are not used and will be ignored.");
    }
  }

  @Override
  public boolean isImplicitConfirm() {
    InfoTypeAndValue[] infos = this.getHeader().getGeneralInfo();
    if (infos != null) {
      for (int i = 0; i < infos.length; i++) {
        if (CMPObjectIdentifiers.it_implicitConfirm.equals(
            infos[i].getInfoType())) {
          return true;
        }
      }
    }
    return false;
  }
}
