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

package org.ejbca.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cesecore.certificates.util.AlgorithmTools;

/**
 * CMS utils.
 *
 * @version $Id: CMS.java 26780 2017-10-10 09:37:56Z mikekushner $
 */
public final class CMS {
    private CMS() { }
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(CMS.class);
  /** Size. */
  private static final int BUFFER_SIZE = 0x20000;

  private static void fromInToOut(final InputStream in, final OutputStream out)
      throws IOException {
    byte[] buf = new byte[BUFFER_SIZE];
    while (true) {
      int len = in.read(buf);
      if (len < 0) {
        break;
      }
      out.write(buf, 0, len);
    }
    out.close();
  }
  /**
   * @param is data to be encrypted
   * @param os encrypted data
   * @param cert certificate with the public key to be used for the encryption
   * @param symmAlgOid the symmetric encryption algorithm to use, for example
   *     CMSEnvelopedGenerator.AES128_CBC
   * @throws Exception Fail
   */
  public static void encrypt(
      final InputStream is,
      final OutputStream os,
      final X509Certificate cert,
      final String symmAlgOid)
      throws Exception {
    final InputStream bis = new BufferedInputStream(is, BUFFER_SIZE);
    final OutputStream bos = new BufferedOutputStream(os, BUFFER_SIZE);
    final CMSEnvelopedDataStreamGenerator edGen =
        new CMSEnvelopedDataStreamGenerator();
    edGen.addRecipientInfoGenerator(
        new JceKeyTransRecipientInfoGenerator(
            "hej".getBytes(), cert.getPublicKey()));
    BcCMSContentEncryptorBuilder bcCMSContentEncryptorBuilder =
        new BcCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(symmAlgOid));
    final OutputStream out =
        edGen.open(bos, bcCMSContentEncryptorBuilder.build());
    fromInToOut(bis, out);
    bos.close();
    os.close();
  }
  /**
   * @param is data to be decrypted
   * @param os decrypted data
   * @param key to be used for the decryption
   * @param providerName the provider that should do the decryption
   * @throws Exception Fail
   */
  public static void decrypt(
      final InputStream is,
      final OutputStream os,
      final PrivateKey key,
      final String providerName)
      throws Exception {
    final InputStream bis = new BufferedInputStream(is, BUFFER_SIZE);
    final OutputStream bos = new BufferedOutputStream(os, BUFFER_SIZE);
    final Iterator<RecipientInformation> it =
        new CMSEnvelopedDataParser(bis)
            .getRecipientInfos()
            .getRecipients()
            .iterator();
    if (it.hasNext()) {
      final RecipientInformation recipientInformation = it.next();
      JceKeyTransEnvelopedRecipient rec =
          new JceKeyTransEnvelopedRecipient(key);
      rec.setProvider(providerName);
      rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
      // Option we must set to prevent Java PKCS#11 provider to try to make the
      // symmetric decryption in the HSM,
      // even though we set content provider to BC. Symm decryption in HSM
      // varies between different HSMs and at least for this case is known
      // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where
      // they introduced imho a buggy behavior)
      rec.setMustProduceEncodableUnwrappedKey(true);
      final CMSTypedStream recData = recipientInformation.getContentStream(rec);
      final InputStream ris = recData.getContentStream();
      fromInToOut(ris, bos);
    }
    os.close();
  }
  /**
   * @param is data to be signed
   * @param os signed data
   * @param key to do be used for signing
   * @param providerName the provider that should do the signing
   * @param cert Cert
   * @throws Exception fail
   */
  public static void sign(
      final InputStream is,
      final OutputStream os,
      final PrivateKey key,
      final String providerName,
      final X509Certificate cert)
      throws Exception {
    final InputStream bis = new BufferedInputStream(is, BUFFER_SIZE);
    final OutputStream bos = new BufferedOutputStream(os, BUFFER_SIZE);
    final CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
    JcaDigestCalculatorProviderBuilder calculatorProviderBuilder =
        new JcaDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);
    JcaSignerInfoGeneratorBuilder builder =
        new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
    final String digest = CMSSignedGenerator.DIGEST_SHA256;
    String signatureAlgorithmName =
        AlgorithmTools.getAlgorithmNameFromDigestAndKey(
            digest, key.getAlgorithm());
    ContentSigner contentSigner =
        new JcaContentSignerBuilder(signatureAlgorithmName)
            .setProvider(providerName)
            .build(key);
    if (cert != null) {
      gen.addSignerInfoGenerator(builder.build(contentSigner, cert));
    } else {
      gen.addSignerInfoGenerator(
          builder.build(contentSigner, "hej".getBytes()));
    }
    final OutputStream out = gen.open(bos, true);
    fromInToOut(bis, out);
    bos.close();
    os.close();
  }

  public static class VerifyResult {
      /** Date. */
    private final Date signDate;
    /** Bool. */
    private final boolean isVerifying;
    /** ID. */
    private final SignerId signerId;

    /**
     * @param asignDate date
     * @param aisVerifying verify
     * @param asignerId id
     */
    public VerifyResult(
        final Date asignDate,
        final boolean aisVerifying,
        final SignerId asignerId) {
      this.signDate = asignDate;
      this.isVerifying = aisVerifying;
      this.signerId = asignerId;
    }

    /**
     * @return the signDate
     */
    public Date getSignDate() {
        return signDate;
    }

    /**
     * @return the isVerifying
     */
    public boolean isVerifying() {
        return isVerifying;
    }

    /**
     * @return the signerId
     */
    public SignerId getSignerId() {
        return signerId;
    }
  }
  /**
   * @param is signed data to be verified
   * @param os signature removed from signed data
   * @param cert the certificate with the public key that should do the
   *     verification
   * @return true if the signing was to with the private key corresponding to
   *     the public key in the certificate.
   * @throws Exception Fail
   */
  public static VerifyResult verify(
      final InputStream is, final OutputStream os, final X509Certificate cert)
      throws Exception {
    final InputStream bis = new BufferedInputStream(is, BUFFER_SIZE);
    final OutputStream bos = new BufferedOutputStream(os, BUFFER_SIZE);
    final CMSSignedDataParser sp =
        new CMSSignedDataParser(new BcDigestCalculatorProvider(), bis);
    final CMSTypedStream sc = sp.getSignedContent();
    final InputStream ris = sc.getContentStream();
    fromInToOut(ris, bos);
    os.close();
    sc.drain();
    @SuppressWarnings("rawtypes")
    final Iterator it = sp.getSignerInfos().getSigners().iterator();
    if (!it.hasNext()) {
      return null;
    }
    final SignerInformation signerInfo = (SignerInformation) it.next();
    final Attribute attribute =
        (Attribute)
            signerInfo
                .getSignedAttributes()
                .getAll(CMSAttributes.signingTime)
                .get(0);
    final Date date =
        Time.getInstance(
                attribute.getAttrValues().getObjectAt(0).toASN1Primitive())
            .getDate();
    final SignerId id = signerInfo.getSID();
    boolean result = false;
    try {
      JcaDigestCalculatorProviderBuilder calculatorProviderBuilder =
          new JcaDigestCalculatorProviderBuilder()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME);
      JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder =
          new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build())
              .setProvider(BouncyCastleProvider.PROVIDER_NAME);
      result =
          signerInfo.verify(
              jcaSignerInfoVerifierBuilder.build(cert.getPublicKey()));
    } catch (Throwable t) { // NOPMD
      LOG.debug("Exception when verifying", t);
    }
    return new VerifyResult(date, result, id);
  }
}
