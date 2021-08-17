package org.ejbca.cvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class TestNonEacCVC extends TestCase implements CVCTest {
  /** Param. */
    static final String CC_ROLE_SC_HSM = "1.3.6.1.4.1.24991.3.1.1";

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
   * @throws Exception Fail
   */
  public void testDontFailOnUnknownChat() throws Exception {
    byte[] rawCvc =
        Hex.decode(
            "7F218201B47F4E82016C5F290100420E44455352434143433130303030317F4982"
            + "011D060A04007F000702020202038120A9FB57DBA1EEA9BC3E660A909D838D72"
            + "6E3BF623D52620282013481D1F6E537782207D5A0975FC2C3057EEF67530417A"
            + "FFE7FB8055C126DC5C6CE94A4B44F330B5D9832026DC5C6CE94A4B44F330B5D9"
            + "BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B68441048BD2AEB9CB7E57CB2C"
            + "4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97"
            + "F8461A14611DC9C27745132DED8E545C1D54C72F0469978520A9FB57DBA1EEA9"
            + "BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A78641046D025A80"
            + "26CDBA245F10DF1B72E9880FFF746DAB40A43A3D5C6BEBF27707C30F6DEA7243"
            + "0EE3287B0665C1EAA6EAA4FA26C46303001983F82BD1AA31E03DA0628701015F"
            + "200E44455352434143433130303030317F4C10060B2B0601040181C31F030101"
            + "5301C05F25060102010100095F24060302010100085F37409DBB382B1711D2BA"
            + "ACB0C623D40C6267D0B52BA455C01F56333DC9554810B9B2878DAF9EC3ADA19C"
            + "7B065D780D6C9C3C2ECEDFD78DEB18AF40778ADF89E861CA");

    CVCertificate cvc = CertificateParser.parseCertificate(rawCvc);

    assertNotNull(cvc);
    assertAuthorization(cvc, CC_ROLE_SC_HSM, (byte) 0xC0, Hex.decode("C0"));
  }

  /**
   * @throws Exception Test
   */
  public void testConstructWithUnknownChat() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    KeyPair keyPair = keyGen.generateKeyPair();

    CAReferenceField car = new CAReferenceField("DE", "TEST", "00001");
    HolderReferenceField chr = new HolderReferenceField("DE", "TEST", "00001");

    AuthorizationRole role = new AuthorizationRoleRawValue((byte) 0xC0);
    AccessRights rights =
        new AccessRightsRawValue(new byte[] {role.getValue()});

    CVCAuthorizationTemplate chat =
        new CVCAuthorizationTemplate(role, rights, CC_ROLE_SC_HSM);

    String algorithm = "SHA256withECDSA";
    CVCPublicKey cvcPublicKey =
        KeyFactory.createInstance(keyPair.getPublic(), algorithm, role);
    CVCertificateBody cvcBody =
        new CVCertificateBody(
            car, cvcPublicKey, chr, chat, new Date(), new Date());

    CVCertificate cvCertificate =
        CertificateGeneratorHelper.createCertificate(
            keyPair.getPrivate(),
            algorithm,
            cvcBody,
            BouncyCastleProvider.PROVIDER_NAME);

    assertNotNull(cvCertificate);
    assertAuthorization(
        cvCertificate, CC_ROLE_SC_HSM, (byte) 0xC0, Hex.decode("C0"));
  }

  private static void assertAuthorization(
      final CVCertificate cvc,
      final String oid,
      final byte role,
      final byte[] rights)
      throws Exception {
    CVCAuthorizationTemplate chat =
        cvc.getCertificateBody().getAuthorizationTemplate();
    assertEquals(oid, chat.getObjectIdentifier());

    AuthorizationField authorizationField = chat.getAuthorizationField();
    assertTrue(
        authorizationField.getAccessRights() instanceof AccessRightsRawValue);
    assertTrue(
        authorizationField.getAuthRole() instanceof AuthorizationRoleRawValue);

    assertEquals(authorizationField.getAuthRole().getValue(), role);
    assertEquals(
        Hex.toHexString(authorizationField.getAccessRights().getEncoded()),
        Hex.toHexString(rights));
  }
}
