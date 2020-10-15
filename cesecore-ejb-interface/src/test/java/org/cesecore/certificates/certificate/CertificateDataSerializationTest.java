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
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Date;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests backwards and forwards compatibility with the CertificateData class,
 * and indirectly CertificateDataWrapper.
 *
 * @version $Id: CertificateDataSerializationTest.java 27422 2017-12-05
 *     14:05:42Z bastianf $
 */
public class CertificateDataSerializationTest {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CertificateDataSerializationTest.class);

  /**
   * CertificateData object that's intentionally missing the endEntityProfileId
   * column.
   */
  private static final String OLD_DATA =
      "rO0ABXNyADVvcmcuY2VzZWNvcmUuY2VydGlma"
      + "WNhdGVzLmNlcnRpZmljYXRlLkNlcnRpZmljYXRl"
      + "RGF0YYoibbY+5VZeAgASSgAKZXhwaXJlRGF0ZUo"
      + "ADnJldm9jYXRpb25EYXRlSQAQcmV2b2NhdGlv"
      + "blJlYXNvbkkACnJvd1ZlcnNpb25JAAZzdGF0d"
      + "XNJAAR0eXBlSgAKdXBkYXRlVGltZUwACmJhc2U2"
      + "NENlcnR0ABJMamF2YS9sYW5nL1N0cmluZztMA"
      + "A1jQUZpbmdlcnByaW50cQB+AAFMABRjZXJ0aWZp"
      + "Y2F0ZVByb2ZpbGVJZHQAE0xqYXZhL2xhbmcvS"
      + "W50ZWdlcjtMAAtmaW5nZXJwcmludHEAfgABTAAI"
      + "aXNzdWVyRE5xAH4AAUwADXJvd1Byb3RlY3Rp"
      + "b25xAH4AAUwADHNlcmlhbE51bWJlcnEAfgABTAAJ"
      + "c3ViamVjdEROcQB+AAFMAAxzdWJqZWN0S2V5"
      + "WRxAH4AAUwAA3RhZ3EAfgABTAAIdXNlcm5hbWVx"
      + "AH4AAXhwAAABnfKkEeD///////////////8AA"
      + "AAAAAAAFAAAAAEAAAFUhbhajXB0ABAxMjM0NTY3"
      + "ODEyMzQ1Njc4c3IAEWphdmEubGFuZy5JbnRlZ"
      + "2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZh"
      + "LmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAA"
      + "AF0ACgxOTRiNDcxMjJmMTcwMjA2NzcxNWVjZmIx"
      + "MTYyMTE1N2M5NmNmMmFidAALQ049Y2VydHVzZ"
      + "XJwdAATODc2NzYzODEyNDM1MTIyMjgzMXQAC0NO"
      + "PWNlcnR1c2VydAAcY1U1UXF2NDR1T0JzVGpnQ"
      + "Xh5WmNVYnZGNnNrPXB0AAhjZXJ0dXNlcg==";

  /**
   * CertificateData object that intentionally has a non-existing column called
   * "testFutureColumn".
   */
  private static final String FUTURE_DATA =
      "rO0ABXNyADVvcmcuY2VzZWNvcmUuY2VydGlma"
      + "WNhdGVzLmNlcnRpZmljYXRlLkNlcnRpZmljYXRl"
      + "RGF0YYoibbY+5VZeAgAUSgAKZXhwaXJlRGF0Z"
      + "UoADnJldm9jYXRpb25EYXRlSQAQcmV2b2NhdGlv"
      + "blJlYXNvbkkACnJvd1ZlcnNpb25JAAZzdGF0d"
      + "XNJAAR0eXBlSgAKdXBkYXRlVGltZUwACmJhc2U2"
      + "NENlcnR0ABJMamF2YS9sYW5nL1N0cmluZztMAA"
      + "1jQUZpbmdlcnByaW50cQB+AAFMABRjZXJ0aWZp"
      + "Y2F0ZVByb2ZpbGVJZHQAE0xqYXZhL2xhbmcvSW5"
      + "0ZWdlcjtMABJlbmRFbnRpdHlQcm9maWxlSWRx"
      + "AH4AAkwAC2ZpbmdlcnByaW50cQB+AAFMAAhpc3"
      + "N1ZXJETnEAfgABTAANcm93UHJvdGVjdGlvbnEA"
      + "fgABTAAMc2VyaWFsTnVtYmVycQB+AAFMAAlzdWJ"
      + "qZWN0RE5xAH4AAUwADHN1YmplY3RLZXlJZHEA"
      + "fgABTAADdGFncQB+AAFMABB0ZXN0RnV0dXJlQ29"
      + "sdW1ucQB+AAJMAAh1c2VybmFtZXEAfgABeHAA"
      + "AAGd8rEtWP///////////////wAAAAAAAAAUAAA"
      + "AAQAAAVSFxXkJcHQAEDEyMzQ1Njc4MTIzNDU2"
      + "NzhzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94G"
      + "HOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5O"
      + "dW1iZXKGrJUdC5TgiwIAAHhwAAAAAXB0ACg0YT"
      + "cyYTk0MGRhY2U3ZjcxYWE4OWYzYTcyNjVmYTRm"
      + "MGUwYzFlMGY3dAALQ049Y2VydHVzZXJwdAATMzU"
      + "wNzY2NTg4NjI3NTcyOTY3NXQAC0NOPWNlcnR1"
      + "c2VydAAcUFg0eUc4cEs0b3JPZFBTU0hLMDMvOW"
      + "tUcjBNPXBwdAAIY2VydHVzZXI=";

  /**
   * CertificateData object that has a non-existent field "testNonExistentClass"
   * with of a non-existent type.
   * "org.cesecore.certificates.certificate.NonExistent"
   */
  private static final String FUTURE_NEW_CLASS_DATA =
      "rO0ABXNyADVvcmcuY2VzZWNvcmUuY2VydGlmaWNhd"
      + "GVzLmNlcnRpZmljYXRlLkNlcnRpZmljYXRl"
      + "RGF0YYoibbY+5VZeAgAUSgAKZXhwaXJlRGF0Z"
      + "UoADnJldm9jYXRpb25EYXRlSQAQcmV2b2NhdGlv"
      + "blJlYXNvbkkACnJvd1ZlcnNpb25JAAZzdGF0dX"
      + "NJAAR0eXBlSgAKdXBkYXRlVGltZUwACmJhc2U2"
      + "NENlcnR0ABJMamF2YS9sYW5nL1N0cmluZztMAA"
      + "1jQUZpbmdlcnByaW50cQB+AAFMABRjZXJ0aWZp"
      + "Y2F0ZVByb2ZpbGVJZHQAE0xqYXZhL2xhbmcvSW5"
      + "0ZWdlcjtMABJlbmRFbnRpdHlQcm9maWxlSWRx"
      + "AH4AAkwAC2ZpbmdlcnByaW50cQB+AAFMAAhpc3"
      + "N1ZXJETnEAfgABTAANcm93UHJvdGVjdGlvbnEA"
      + "fgABTAAMc2VyaWFsTnVtYmVycQB+AAFMAAlzdWJ"
      + "qZWN0RE5xAH4AAUwADHN1YmplY3RLZXlJZHEA"
      + "fgABTAADdGFncQB+AAFMABR0ZXN0Tm9uRXhpc3R"
      + "lbnRDbGFzc3QAI0xvcmcvY2VzZWNvcmUvaW50"
      + "ZXJuYWwvTm9uRXhpc3RlbnQ7TAAIdXNlcm5hbWVx"
      + "AH4AAXhwAAABnk5S8Nj///////////////8A"
      + "AAAAAAAAFAAAAAEAAAFU4Wc5Z3B0ABAxMjM0NTY"
      + "3ODEyMzQ1Njc4c3IAEWphdmEubGFuZy5JbnRl"
      + "Z2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhL"
      + "mxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAA"
      + "AAFwdAAoNjlkOWEzYzI3N2ViYjg4ODZmMzQzYTRi"
      + "NWEzM2ViYTVlNDJlZmEyM3QAC0NOPWNlcnR1"
      + "c2VycHQAEzYyODQxMDQwODE0Mjg3NzQxMTJ0AAtD"
      + "Tj1jZXJ0dXNlcnQAHFdXaUJwdTZidFVTRzZZ"
      + "RE4yT1dnazJsYi95ND1wcHQACGNlcnR1c2Vy";
/** Setup. */
  @BeforeClass
  public static void beforeClass() {
    CryptoProviderTools.installBCProviderIfNotAvailable();
  }

  /**
   * This test prints the serialized form of a CertificateData object, and was
   * used to generated the data above.
   *
   * @throws Exception on fail
   */
  @Test
  public void testSerializeCurrent() throws Exception {
    LOG.trace(">testSerializeCurrent");
    final KeyPair kp = KeyTools.genKeys("1024", "RSA");
    final Certificate cert =
        CertTools.genSelfCert(
            "CN=certuser",
            10 * 365,
            null,
            kp.getPrivate(),
            kp.getPublic(),
            "SHA256withRSA",
            false);
    final CertificateData certData =
        new CertificateData(
            cert,
            kp.getPublic(),
            "certuser",
            "1234567812345678",
            CertificateConstants.CERT_ACTIVE,
            CertificateConstants.CERTTYPE_ENDENTITY,
            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
            EndEntityConstants.NO_END_ENTITY_PROFILE,
            null,
            new Date().getTime(),
            false,
            true);
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    final Base64OutputStream b64os = new Base64OutputStream(baos);
    final ObjectOutputStream oos = new ObjectOutputStream(b64os);
    oos.writeObject(certData);
    oos.close();
    b64os.close();
    LOG.info("Base 64 of serialized CertData is: " + baos.toString("US-ASCII"));
    LOG.trace("<testSerializeCurrent");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testDeserializeOld() throws Exception {
    LOG.trace(">testDeserializeOld");
    final ByteArrayInputStream bais =
        new ByteArrayInputStream(OLD_DATA.getBytes("US-ASCII"));
    final Base64InputStream b64is = new Base64InputStream(bais);
    final ObjectInputStream ois = new ObjectInputStream(b64is);
    final CertificateData certData = (CertificateData) ois.readObject();
    ois.close();
    assertEquals(
        "certuser",
        certData.getUsername()); // unrelated column. should not be affected
    assertNull(
        "End Entity Profile Id in CertificateData with old serialization.",
        certData.getEndEntityProfileId());
    assertEquals(
        EndEntityConstants.NO_END_ENTITY_PROFILE,
        certData.getEndEntityProfileIdOrZero());
    LOG.trace("<testDeserializeOld");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testDeserializeFuture() throws Exception {
    LOG.trace(">testDeserializeFuture");
    final ByteArrayInputStream bais =
        new ByteArrayInputStream(FUTURE_DATA.getBytes("US-ASCII"));
    final Base64InputStream b64is = new Base64InputStream(bais);
    final ObjectInputStream ois = new ObjectInputStream(b64is);
    final CertificateData certData = (CertificateData) ois.readObject();
    ois.close();
    assertEquals(
        "certuser",
        certData.getUsername()); // unrelated column. should not be affected
    LOG.trace("<testDeserializeFuture");
  }

  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testDeserializeFutureFieldNewClass() throws Exception {
    LOG.trace(">testDeserializeFutureFieldNewClass");
    final ByteArrayInputStream bais =
        new ByteArrayInputStream(FUTURE_NEW_CLASS_DATA.getBytes("US-ASCII"));
    final Base64InputStream b64is = new Base64InputStream(bais);
    final ObjectInputStream ois = new ObjectInputStream(b64is);
    final CertificateData certData = (CertificateData) ois.readObject();
    ois.close();
    assertEquals(
        "certuser",
        certData.getUsername()); // unrelated column. should not be affected
    LOG.trace("<testDeserializeFutureFieldNewClass");
  }
}
