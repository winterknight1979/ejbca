/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.example.FileHelper;

/**
 * Tests specific for CV Certificates.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class TestCVCertificate extends TestCase implements CVCTest {

    /** Param. */
  private static final byte[] TEST_EXTENSION_VALUE =
      new byte[] {(byte) 0xf0, (byte) 0xe1, (byte) 0xd2};

  @Override
  protected void setUp() throws Exception {
    // Install Bouncy Castle as security provider
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  protected void tearDown() throws Exception {
    // Uninstall BC
    Security.removeProvider("BC");
  }

  /**
   * Check: DER-encoding/decoding of a CVCertificate should not affect its data.
 * @throws Exception fail
   */
  public void testEncoding() throws Exception {

    CVCertificate cert1 = createTestCertificate();

    byte[] pubkey1 = cert1.getCertificateBody().getPublicKey().getDEREncoded();

    byte[] der = cert1.getDEREncoded();

    CVCObject cvcObj = CertificateParser.parseCertificate(der);
    assertTrue(
        "Parsed object is not a CVCertificate: " + cvcObj.getTag(),
        (cvcObj instanceof CVCertificate));

    CVCertificate cert2 = (CVCertificate) cvcObj;
    assertEquals(
        "Certificates as text differ", cert1.getAsText(), cert2.getAsText());

    byte[] pubkey2 = cert2.getCertificateBody().getPublicKey().getDEREncoded();
    assertTrue(
        "DER-coded public keys not equal", Arrays.equals(pubkey1, pubkey2));
  }

  /** Check: The CVCertificate signature should be verifiable.
 * @throws Exception fail */
  public void testVerifyCertificate() throws Exception {
    // Create new key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
    keyGen.initialize(1024, new SecureRandom());
    KeyPair keyPair = keyGen.generateKeyPair();

    CAReferenceField caRef =
        new CAReferenceField(
            CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
    HolderReferenceField holderRef =
        new HolderReferenceField(
            HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

    // This will create a self-signed certificate
    CVCertificate cert =
        CertificateGeneratorHelper.createTestCertificate(
            keyPair.getPublic(),
            keyPair.getPrivate(),
            caRef,
            holderRef,
            "SHA1WithRSA",
            AuthorizationRoleEnum.IS);
    cert.verify(keyPair.getPublic(), "BC");

    CardVerifiableCertificate cvc = new CardVerifiableCertificate(cert);
    cvc.verify(keyPair.getPublic(), "BC");
  }

  /** Check: Verify certificate chain.
 * @throws Exception fail*/
  public void testVerifyCertificateChain() throws Exception {
    // Create key pair for CA
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
    keyGen.initialize(1024, new SecureRandom());
    KeyPair caKeyPair = keyGen.generateKeyPair();

    // Simulate an IS certificate that has been signed by CA
    // Create new key pair
    keyGen.initialize(1024, new SecureRandom());
    KeyPair isKeyPair = keyGen.generateKeyPair();
    CAReferenceField caRef =
        new CAReferenceField(
            CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
    HolderReferenceField holderRef =
        new HolderReferenceField(
            HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);
    Calendar cal = Calendar.getInstance();
    Date dateFrom = cal.getTime();
    cal.add(Calendar.DAY_OF_MONTH, 3);
    Date dateTo = cal.getTime();
    CVCertificate isCert =
        CertificateGeneratorHelper.createCertificate(
            isKeyPair.getPublic(),
            caKeyPair.getPrivate(),
            "SHA256WithRSA",
            caRef,
            holderRef,
            AuthorizationRoleEnum.IS,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
            dateFrom,
            dateTo,
            "BC");

    try {
      isCert.verify(isKeyPair.getPublic(), "BC");
      throw new Exception(
          "Verifying with holder's public key should not work!");
    } catch (SignatureException e) {
      // This is expected

      isCert.verify(caKeyPair.getPublic(), "BC");
    }
  }

  /** Check: Validate CVCProvider.
 * @throws Exception fail  */
  public void testSecurityProvider() throws Exception {
    Security.addProvider(new CVCProvider());

    CVCertificate cvc = createTestCertificate();

    CertificateFactory factory = CertificateFactory.getInstance("CVC");
    ByteArrayInputStream bin = new ByteArrayInputStream(cvc.getDEREncoded());
    Certificate cert = factory.generateCertificate(bin);

    assertTrue(
        "cert not a CardVerifiableCertificate",
        (cert instanceof CardVerifiableCertificate));

    String expectedFormat = "CVC";
    assertEquals(
        "Type is not " + expectedFormat, expectedFormat, cert.getType());
    assertEquals(
        "Key format is not " + expectedFormat,
        expectedFormat,
        cert.getPublicKey().getFormat());

    Security.removeProvider("CVC");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  public void testExternalCert() throws Exception {
    byte[] bytes =
        FileHelper.loadFile(
            new File("./src/test/resources/GO_CVCA_RSA2008.cvcert"));
    CVCertificate cvc = (CVCertificate) CertificateParser.parseCVCObject(bytes);
    CardVerifiableCertificate cvcacert = new CardVerifiableCertificate(cvc);
    System.out.println("CERT\n: " + cvcacert.toString());
    cvcacert.verify(cvc.getCertificateBody().getPublicKey(), "BC");
  }

  /**
   * Test.
   * @throws Exception fail
   */
  public void testEncodeAuthTermCert() throws Exception {
    byte[] bytes =
        FileHelper.loadFile(
            new File("./src/test/resources/at_cert_19a.cvcert"));
    CVCertificate cvc = (CVCertificate) CertificateParser.parseCVCObject(bytes);
    CardVerifiableCertificate atcert = new CardVerifiableCertificate(cvc);

    // Only CVCA certs have the full information needed to verify them,
    // so just check that the bytes are encoded correctly
    assertTrue(
        "re-encoded data was not equal",
        Arrays.equals(cvc.getDEREncoded(), bytes));
    assertTrue(
        "re-encoded data was not equal",
        Arrays.equals(atcert.getEncoded(), bytes));
    // atcert.verify(atcert.getPublicKey(), "BC");
  }

  /**
   * Test.
   * @throws Exception fail
   */
  public void testCertificateExtensions() throws Exception {
    // Create new key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
    keyGen.initialize(1024, new SecureRandom());
    KeyPair keyPair = keyGen.generateKeyPair();

    CAReferenceField caRef =
        new CAReferenceField(
            CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
    HolderReferenceField holderRef =
        new HolderReferenceField(
            HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

    // Generate certificates
    final Calendar cal = Calendar.getInstance();
    cal.add(Calendar.MONTH, 3);
    final Date validTo = cal.getTime();
    CVCertificate cert;
    byte[] encoded;
    CVCertificate decodedCert;

    cert =
        CertificateGeneratorHelper.createCertificate(
            keyPair.getPublic(),
            keyPair.getPrivate(),
            "SHA256WithRSA",
            caRef,
            holderRef,
            AuthorizationRoleEnum.IS,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
            new Date(),
            validTo,
            null,
            "BC");
    encoded = cert.getDEREncoded();
    decodedCert = CertificateParser.parseCertificate(encoded);
    try {
      decodedCert.getCertificateBody().getCertificateExtensions();
      fail("Should throw when trying to get extensions while none are present");
    } catch (NoSuchFieldException e) {
      // NOPMD expected
    }

    final Collection<CVCDiscretionaryDataTemplate> extensions =
        new ArrayList<CVCDiscretionaryDataTemplate>();
    final CVCDiscretionaryDataTemplate ext1 =
        new CVCDiscretionaryDataTemplate("2.999.1.2.3", TEST_EXTENSION_VALUE);
    final CVCDiscretionaryDataTemplate ext2 =
        new CVCDiscretionaryDataTemplate("2.999.4", new byte[] {});
    extensions.add(ext1);
    extensions.add(ext2);
    cert =
        CertificateGeneratorHelper.createCertificate(
            keyPair.getPublic(),
            keyPair.getPrivate(),
            "SHA256WithRSA",
            caRef,
            holderRef,
            AuthorizationRoleEnum.IS,
            AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
            new Date(),
            validTo,
            extensions,
            "BC");

    encoded = cert.getDEREncoded();
    decodedCert = CertificateParser.parseCertificate(encoded);
    System.out.println("DECODED CERT: " + decodedCert.getAsText());
    assertNotNull(
        "Certificate extensions was null when decoding certificate.",
        decodedCert.getCertificateBody().getCertificateExtensions());
    List<CVCDiscretionaryDataTemplate> decodedExts =
        decodedCert
            .getCertificateBody()
            .getCertificateExtensions()
            .getExtensions();
    assertEquals(
        "Wrong number of extensions in decoded certificate.",
        2,
        decodedExts.size());
    assertEquals("2.999.1.2.3", decodedExts.get(0).getObjectIdentifier());
    assertEquals("2.999.4", decodedExts.get(1).getObjectIdentifier());
    assertEquals(3, decodedExts.get(0).getExtensionData().length);
    assertEquals(
        TEST_EXTENSION_VALUE[0], decodedExts.get(0).getExtensionData()[0]);
    assertEquals(
        TEST_EXTENSION_VALUE[1], decodedExts.get(0).getExtensionData()[1]);
    assertEquals(
        TEST_EXTENSION_VALUE[2], decodedExts.get(0).getExtensionData()[2]);
    assertEquals(0, decodedExts.get(1).getExtensionData().length);
  }

  // Helper for creating a test certificate
  private CVCertificate createTestCertificate() throws Exception {
    // Create new key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
    keyGen.initialize(1024, new SecureRandom());
    KeyPair keyPair = keyGen.generateKeyPair();

    CAReferenceField caRef =
        new CAReferenceField(
            CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
    HolderReferenceField holderRef =
        new HolderReferenceField(
            HR_COUNTRY_CODE, HR_HOLDER_MNEMONIC, HR_SEQUENCE_NO);

    // Call CertificateGenerator
    return CertificateGeneratorHelper.createTestCertificate(
        keyPair.getPublic(),
        keyPair.getPrivate(),
        caRef,
        holderRef,
        "SHA1WithRSA",
        AuthorizationRoleEnum.IS);
  }
}
