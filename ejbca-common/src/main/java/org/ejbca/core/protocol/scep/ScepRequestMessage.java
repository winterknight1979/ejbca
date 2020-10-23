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

package org.ejbca.core.protocol.scep;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * Class to handle SCEP request messages sent to the CA.
 *
 * @version $Id: ScepRequestMessage.java 22561 2016-01-12 14:35:29Z mikekushner
 *     $
 */
public class ScepRequestMessage extends PKCS10RequestMessage
    implements RequestMessage {
  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  static final long serialVersionUID = -235623330828902051L;

  /** Log. */
  private static Logger LOG = Logger.getLogger(ScepRequestMessage.class);

  /** Param. */
  public static final String ID_VERISIGN = "2.16.840.1.113733";
  /** Param. */
  public static final String ID_PKI = ID_VERISIGN + ".1";
  /** Param. */
  public static final String ID_ATTRIBUTES = ID_PKI + ".9";
  /** Param. */
  public static final String ID_MESSAGETYPE = ID_ATTRIBUTES + ".2";
  /** Param. */
  public static final String ID_PKISTATUS = ID_ATTRIBUTES + ".3";
  /** Param. */
  public static final String ID_FAILINFO = ID_ATTRIBUTES + ".4";
  /** Param. */
  public static final String ID_SENDERNONCE = ID_ATTRIBUTES + ".5";
  /** Param. */
  public static final String ID_RECIPIENTNONCE = ID_ATTRIBUTES + ".6";
  /** Param. */
  public static final String ID_TRANSID = ID_ATTRIBUTES + ".7";
  /** Param. */
  public static final String ID_EXTENSIONREQ = ID_ATTRIBUTES + ".8";

  /** Raw form of the Scep message, */
  private final byte[] scepmsg;

  /**
   * The messageType attribute specify the type of operation performed by the
   * transaction. This attribute is required in all PKI messages. Currently, the
   * following message types are defined: PKCSReq (19) -- Permits use of PKCS#10
   * certificate request CertRep (3) -- Response to certificate or CRL request
   * GetCertInitial (20) -- Certificate polling in manual enrollment GetCert
   * (21) -- Retrieve a certificate GetCRL (22) -- Retrieve a CRL
   */
  private int messageType = 0;

  /** Param. */
  public static final int SCEP_TYPE_PKCSREQ = 19;
  /** Param. */
  public static final int SCEP_TYPE_GETCERTINITIAL =
      20; // Used when request is in pending state.
  /** Param. */
  public static final int SCEP_TYPE_GETCRL = 22;
  /** Param. */
  public static final int SCEP_TYPE_GETCERT = 21;

  /**
   * SenderNonce in a request is used as recipientNonce when the server sends
   * back a reply to the client. This is base64 encoded bytes
   */
  private String senderNonce = null;

  /** transaction id. */
  private String transactionId = null;

  /**
   * request key info, this is the requester's self-signed certificate used to
   * identify the senders public key.
   */
  private byte[] requestKeyInfo = null;

  /** Type of error. */
  private int error = 0;

  /** Error text. */
  private String errorText = null;

  /**
   * Issuer DN the message is sent to (CAs Issuer DN), contained in the request
   * as recipientInfo.issuerAndSerialNumber in EnvelopeData part.
   */
  private transient String issuerDN = null;

  /**
   * SerialNumber of the CA cert of the CA the message is sent to, contained in
   * the request as recipientInfo.issuerAndSerialNumber in EnvelopeData part.
   */
  private transient BigInteger serialNo = null;

  /** Signed data, the whole enchilada to to speak... */
  private transient SignedData sd = null;

  /** Enveloped data, carrying the 'beef' of the request. */
  private transient EnvelopedData envData = null;

  /** Enveloped data, carrying the 'beef' of the request. */
  private transient ContentInfo envEncData = null;

  /** Private key used for decryption. */
  private transient PrivateKey privateKey = null;
  /**
   * JCE Provider used when decrypting with private key. Default provider is BC.
   */
  private transient String jceProvider = BouncyCastleProvider.PROVIDER_NAME;

  /** IssuerAndSerialNUmber for CRL request. */
  private transient IssuerAndSerialNumber issuerAndSerno = null;

  /**
   * preferred digest algorithm to use in replies, if applicable. Defaults to
   * CMSSignedGenerator.DIGEST_MD5 for SCEP messages. If SCEP request is
   * digested with SHA1 it is set to SHA1 though. This is only for backwards
   * compatibility issues, as specified in a SCEP draft. Modern
   * request/responses will use SHA-1.
   */
  private transient String preferredDigestAlg = CMSSignedGenerator.DIGEST_MD5;

  /** Cert. */
  private transient Certificate signercert;

  /**
   * Constructs a new SCEP/PKCS7 message handler object.
   *
   * @param msg The DER encoded PKCS7 request.
   * @param incCACert if the CA certificate should be included in the response
   *     or not
   * @throws IOException if the request can not be parsed.
   */
  public ScepRequestMessage(final byte[] msg, final boolean incCACert)
      throws IOException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">ScepRequestMessage");
    }
    this.scepmsg = msg;
    this.includeCACert = incCACert;
    init();
    if (LOG.isTraceEnabled()) {
      LOG.trace("<ScepRequestMessage");
    }
  }

  /**
   * This method verifies the signature of the PKCS#7 wrapper of this message.
   *
   * @param publicKey the public key of the keypair that signed this message
   * @return true if signature verifies.
   * @throws CMSException if the underlying byte array of this SCEP message
   *     couldn't be read
   * @throws OperatorCreationException if a signature verifier couldn't be
   *     constructed from the given public key
   */
  public boolean verifySignature(final PublicKey publicKey)
      throws CMSException, OperatorCreationException {
    CMSSignedData cmsSignedData = new CMSSignedData(scepmsg);
    return cmsSignedData.verifySignatures(new ScepVerifierProvider(publicKey));
  }

  private void init() throws IOException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">init");
    }
    try {
      CMSSignedData csd = new CMSSignedData(scepmsg);
      SignerInformationStore infoStore = csd.getSignerInfos();
      Collection<SignerInformation> signers = infoStore.getSigners();
      Iterator<SignerInformation> iter = signers.iterator();
      if (iter.hasNext()) {
        SignerInformation si = (SignerInformation) iter.next();
        preferredDigestAlg = si.getDigestAlgOID();
        LOG.debug(
            "Set "
                + preferredDigestAlg
                + " as preferred digest algorithm for SCEP");
      }
    } catch (CMSException e) {
      // ignore, use default digest algo
      LOG.error("CMSException trying to get preferred digest algorithm: ", e);
    }
    // Parse and verify the integrity of the PKIOperation message PKCS#7
    /* If this would have been done using the newer CMS it would have 
     * made me so much happier... */
    ASN1InputStream seqAsn1InputStream =
        new ASN1InputStream(new ByteArrayInputStream(scepmsg));
    ASN1Sequence seq = null;
    try {
      seq = (ASN1Sequence) seqAsn1InputStream.readObject();
    } finally {
      seqAsn1InputStream.close();
    }
    ContentInfo ci = ContentInfo.getInstance(seq);
    String ctoid = ci.getContentType().getId();

    if (ctoid.equals(CMSObjectIdentifiers.signedData.getId())) {
      // This is SignedData so it is a pkcsCertReqSigned,
      // pkcsGetCertInitialSigned, pkcsGetCertSigned, pkcsGetCRLSigned
      // (could also be pkcsRepSigned or certOnly, but we don't receive them on
      // the server side
      // Try to find out what kind of message this is
      sd = SignedData.getInstance((ASN1Sequence) ci.getContent());
      // Get self signed cert to identify the senders public key
      ASN1Set certs = sd.getCertificates();
      if (certs.size() > 0) {
        // There should be only one...
        ASN1Encodable dercert = certs.getObjectAt(0);
        if (dercert != null) {
          // Requester's self-signed certificate is requestKeyInfo
          ByteArrayOutputStream bOut = new ByteArrayOutputStream();
          DEROutputStream dOut = new DEROutputStream(bOut);
          dOut.writeObject(dercert);
          if (bOut.size() > 0) {
            requestKeyInfo = bOut.toByteArray();
            // Create Certificate used for debugging
            try {
              signercert =
                  CertTools.getCertfromByteArray(
                      requestKeyInfo, Certificate.class);
              if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "requestKeyInfo is SubjectDN: "
                        + CertTools.getSubjectDN(signercert)
                        + ", Serial="
                        + CertTools.getSerialNumberAsString(signercert)
                        + "; IssuerDN: "
                        + CertTools.getIssuerDN(signercert).toString());
              }
            } catch (CertificateException e) {
              LOG.error("Error parsing requestKeyInfo : ", e);
            }
          }
        }
      }

      Enumeration<?> sis = sd.getSignerInfos().getObjects();

      if (sis.hasMoreElements()) {
        SignerInfo si =
            SignerInfo.getInstance((ASN1Sequence) sis.nextElement());
        Enumeration<?> attr = si.getAuthenticatedAttributes().getObjects();

        while (attr.hasMoreElements()) {
          Attribute a =
              Attribute.getInstance((ASN1Sequence) attr.nextElement());
          if (LOG.isDebugEnabled()) {
            LOG.debug("Found attribute: " + a.getAttrType().getId());
          }
          if (a.getAttrType().getId().equals(ID_SENDERNONCE)) {
            Enumeration<?> values = a.getAttrValues().getObjects();
            ASN1OctetString str =
                ASN1OctetString.getInstance(values.nextElement());
            senderNonce = new String(Base64.encode(str.getOctets(), false));
            if (LOG.isDebugEnabled()) {
              LOG.debug("senderNonce = " + senderNonce);
            }
          }
          if (a.getAttrType().getId().equals(ID_TRANSID)) {
            Enumeration<?> values = a.getAttrValues().getObjects();
            DERPrintableString str =
                DERPrintableString.getInstance(values.nextElement());
            transactionId = str.getString();
            if (LOG.isDebugEnabled()) {
              LOG.debug("transactionId = " + transactionId);
            }
          }
          if (a.getAttrType().getId().equals(ID_MESSAGETYPE)) {
            Enumeration<?> values = a.getAttrValues().getObjects();
            DERPrintableString str =
                DERPrintableString.getInstance(values.nextElement());
            messageType = Integer.parseInt(str.getString());
            if (LOG.isDebugEnabled()) {
              LOG.debug("messagetype = " + messageType);
            }
          }
        }
      }

      // If this is a PKCSReq
      if ((messageType == ScepRequestMessage.SCEP_TYPE_PKCSREQ)
          || (messageType == ScepRequestMessage.SCEP_TYPE_GETCRL)
          || (messageType == ScepRequestMessage.SCEP_TYPE_GETCERTINITIAL)) {
        // Extract the contents, which is an encrypted PKCS10 if messageType ==
        // 19
        // , and an encrypted issuer and subject if messageType == 20 (not
        // extracted)
        // and an encrypted IssuerAndSerialNumber if messageType == 22
        ci = sd.getEncapContentInfo();
        ctoid = ci.getContentType().getId();

        if (ctoid.equals(CMSObjectIdentifiers.data.getId())) {
          ASN1OctetString content = (ASN1OctetString) ci.getContent();
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "envelopedData is " + content.getOctets().length + " bytes.");
          }
          ASN1InputStream seq1Asn1InputStream =
              new ASN1InputStream(
                  new ByteArrayInputStream(content.getOctets()));
          ASN1Sequence seq1 = null;
          try {
            seq1 = (ASN1Sequence) seq1Asn1InputStream.readObject();
          } finally {
            seq1Asn1InputStream.close();
          }
          envEncData = ContentInfo.getInstance(seq1);
          ctoid = envEncData.getContentType().getId();

          if (ctoid.equals(CMSObjectIdentifiers.envelopedData.getId())) {
            envData =
                EnvelopedData.getInstance(
                    (ASN1Sequence) envEncData.getContent());
            ASN1Set recipientInfos = envData.getRecipientInfos();
            Enumeration<?> e = recipientInfos.getObjects();
            while (e.hasMoreElements()) {
              RecipientInfo ri = RecipientInfo.getInstance(e.nextElement());
              KeyTransRecipientInfo recipientInfo =
                  KeyTransRecipientInfo.getInstance(ri.getInfo());
              RecipientIdentifier rid = recipientInfo.getRecipientIdentifier();
              IssuerAndSerialNumber iasn =
                  IssuerAndSerialNumber.getInstance(rid.getId());
              issuerDN = iasn.getName().toString();
              serialNo = iasn.getSerialNumber().getValue();
              if (LOG.isDebugEnabled()) {
                LOG.debug("IssuerDN: " + issuerDN);
                LOG.debug(
                    "SerialNumber: "
                        + iasn.getSerialNumber().getValue().toString(16));
              }
            }
          } else {
            errorText =
                "EncapsulatedContentInfo does not contain PKCS7"
                    + " envelopedData: ";
            LOG.error(errorText + ctoid);
            error = 2;
          }
        } else {
          errorText = "EncapsulatedContentInfo is not of type 'data': ";
          LOG.error(errorText + ctoid);
          error = badType;
        }
      } else {
        errorText = "This is not a certification request!";
        LOG.error(errorText);
        error = badReq;
      }
    } else {
      errorText = "PKCSReq does not contain 'signedData': ";
      LOG.error(errorText + ctoid);
      error = 1;
    }

    LOG.trace("<init");
  } // init

  private void decrypt()
      throws CMSException, NoSuchProviderException, GeneralSecurityException,
          IOException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">decrypt");
    }
    // Now we are getting somewhere (pheew),
    // Now we just have to get the damn key...to decrypt the PKCS10
    if (privateKey == null) {
      errorText = "Need private key to decrypt!";
      error = needKey;
      LOG.error(errorText);
      return;
    }

    if (envEncData == null) {
      errorText = "No enveloped data to decrypt!";
      error = noData;
      LOG.error(errorText);
      return;
    }

    CMSEnvelopedData ed = new CMSEnvelopedData(envEncData);
    RecipientInformationStore recipients = ed.getRecipientInfos();
    Collection<RecipientInformation> c = recipients.getRecipients();
    Iterator<RecipientInformation> it = c.iterator();
    byte[] decBytes = null;

    while (it.hasNext()) {
      RecipientInformation recipient = (RecipientInformation) it.next();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Privatekey : " + privateKey.getAlgorithm());
      }
      JceKeyTransEnvelopedRecipient rec =
          new JceKeyTransEnvelopedRecipient(privateKey);
      rec.setProvider(
          jceProvider); // Use the crypto token provides for asymmetric key
                        // operations
      rec.setContentProvider(
          BouncyCastleProvider
              .PROVIDER_NAME); // Use BC for the symmetric key operations
      // Option we must set to prevent Java PKCS#11 provider to try to make the
      // symmetric decryption in the HSM,
      // even though we set content provider to BC. Symm decryption in HSM
      // varies between different HSMs and at least for this case is known
      // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where
      // they introduced imho a buggy behavior)
      rec.setMustProduceEncodableUnwrappedKey(true);
      decBytes = recipient.getContent(rec);
      break;
    }

    if (messageType == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
      pkcs10 = new JcaPKCS10CertificationRequest(decBytes);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Successfully extracted PKCS10:"
                + new String(Base64.encode(pkcs10.getEncoded())));
      }
    }
    if (messageType == ScepRequestMessage.SCEP_TYPE_GETCRL) {
      ASN1InputStream derAsn1InputStream =
          new ASN1InputStream(new ByteArrayInputStream(decBytes));
      ASN1Primitive derobj = null;
      try {
        derobj = derAsn1InputStream.readObject();
      } finally {
        derAsn1InputStream.close();
      }
      issuerAndSerno = IssuerAndSerialNumber.getInstance(derobj);
      LOG.debug("Successfully extracted IssuerAndSerialNumber.");
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<decrypt");
    }
  } // decrypt

  @Override
  public PublicKey getRequestPublicKey() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getRequestPublicKey()");
    }
    PublicKey ret = null;
    try {
      if (envData == null) {
        init();
        decrypt();
      }
      ret = super.getRequestPublicKey();
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getRequestPublicKey()");
    }
    return ret;
  }

  @Override
  public String getRequestAltNames() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getRequestAltNames()");
    }
    String ret = null;
    try {
      if (envData == null) {
        init();
        decrypt();
      }
      ret = super.getRequestAltNames();
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getRequestAltNames()");
    }
    return ret;
  }

  @Override
  public boolean verify() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">verify()");
    }
    boolean ret = false;
    try {
      if (pkcs10 == null) {
        init();
        decrypt();
      }
      ret = super.verify();
    } catch (IOException e) {
      LOG.error("PKCS7 not initialized!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<verify()");
    }
    return ret;
  }

  @Override
  public String getPassword() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getPassword()");
    }
    String ret = null;
    try {
      if (pkcs10 == null) {
        init();
        decrypt();
      }
      ret = super.getPassword();
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getPassword()");
    }
    return ret;
  }

  @Override
  public String getUsername() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getUsername()");
    }
    String ret = null;
    try {
      if (pkcs10 == null) {
        init();
        decrypt();
      }
      ret = super.getUsername();
      if (ret == null) {
        // For Cisco boxes they can sometimes send DN as SN instead of CN
        String name = CertTools.getPartFromDN(getRequestDN(), "SN");
        if (name == null) {
          LOG.error("No SN in DN: " + getRequestDN());
          return null;
        }
        // Special if the DN contains unstructuredAddress where it becomes:
        // SN=1728668 + 1.2.840.113549.1.9.2=pix.primekey.se
        // We only want the SN and not the oid-part.
        int index = name.indexOf(' ');
        ret = name;
        if (index > 0) {
          ret = name.substring(0, index);
        } else {
          // Perhaps there is no space, only +
          index = name.indexOf('+');
          if (index > 0) {
            ret = name.substring(0, index);
          }
        }
      }
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getUsername(): " + ret);
    }
    return ret;
  }

  @Override
  public String getIssuerDN() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getIssuerDN()");
    }
    String ret = null;
    try {
      if (envData == null) {
        init();
      }
      ret = issuerDN;
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getIssuerDN(): " + ret);
    }
    return ret;
  }

  @Override
  public BigInteger getSerialNo() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getSerialNo()");
    }
    // Use another method to do the decryption etc...
    getIssuerDN();
    return serialNo;
  }

  @Override
  public String getCRLIssuerDN() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCRLIssuerDN()");
    }
    String ret = null;
    try {
      if (issuerAndSerno == null) {
        init();
        decrypt();
      }
      ret = CertTools.stringToBCDNString(issuerAndSerno.getName().toString());
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getCRLIssuerDN(): " + ret);
    }
    return ret;
  }

  @Override
  public BigInteger getCRLSerialNo() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCRLSerialNo()");
    }
    BigInteger ret = null;
    try {
      if (issuerAndSerno == null) {
        init();
        decrypt();
      }
      ret = issuerAndSerno.getSerialNumber().getValue();
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getCRLSerialNo(): " + ret);
    }
    return ret;
  }

  @Override
  public String getRequestDN() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getRequestDN()");
    }
    String ret = null;
    try {
      if (pkcs10 == null) {
        init();
        decrypt();
      }
      ret = super.getRequestDN();
    } catch (IOException e) {
      LOG.error("PKCS7 not inited!");
    } catch (GeneralSecurityException e) {
      LOG.error("Error in PKCS7:", e);
    } catch (CMSException e) {
      LOG.error("Error in PKCS7:", e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getRequestDN(): " + ret);
    }
    return ret;
  }

  @Override
  public boolean requireKeyInfo() {
    return true;
  }

  @Override
  public void setKeyInfo(
      final Certificate cert, final PrivateKey key, final String provider) {
    // We don't need the public key
    // this.cert = cert;
    this.privateKey = key;
    if (provider == null) {
      this.jceProvider = BouncyCastleProvider.PROVIDER_NAME;
    } else {
      this.jceProvider = provider;
    }
  }

  @Override
  public int getErrorNo() {
    return error;
  }

  @Override
  public String getErrorText() {
    return errorText;
  }

  @Override
  public String getSenderNonce() {
    return senderNonce;
  }

  @Override
  public String getTransactionId() {
    return transactionId;
  }

  @Override
  public byte[] getRequestKeyInfo() {
    return requestKeyInfo;
  }

  @Override
  public String getPreferredDigestAlg() {
    return preferredDigestAlg;
  }

  /**
   * Returns the type of SCEP message it is.
   *
   * @return value as defined by SCEP_TYPE_PKCSREQ, SCEP_TYPE_GETCRL,
   *     SCEP_TYPE_GETCERT
   */
  public int getMessageType() {
    return messageType;
  }

  /**
   * Method returning the certificate used to sign the SCEP_TYPE_PKCSREQ pkcs7
   * request.
   *
   * @return The certificate used for signing or null if it doesn't exist or not
   *     been initialized.
   */
  public Certificate getSignerCert() {
    return signercert;
  }

  private static class ScepVerifierProvider
      implements SignerInformationVerifierProvider {

	  /** param. */
	  private final SignerInformationVerifier signerInformationVerifier;

    ScepVerifierProvider(final PublicKey publicKey)
        throws OperatorCreationException {
      JcaDigestCalculatorProviderBuilder calculatorProviderBuilder =
          new JcaDigestCalculatorProviderBuilder()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME);
      JcaSignerInfoVerifierBuilder signerInfoVerifierBuilder =
          new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build())
              .setProvider(BouncyCastleProvider.PROVIDER_NAME);
      signerInformationVerifier = signerInfoVerifierBuilder.build(publicKey);
    }

    @Override
    public SignerInformationVerifier get(final SignerId signerId)
        throws OperatorCreationException {
      return signerInformationVerifier;
    }
  }
  
  /** error. */
  private final int badType = 3;
  /** error. */
  private final int badReq = 4;
  /** error. */
  private final int needKey = 5;
  /** error. */
  private final int noData = 6;
}
