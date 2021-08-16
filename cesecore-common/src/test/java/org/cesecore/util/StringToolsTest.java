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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolderUtil;
import org.junit.Test;

/**
 * Tests the StringTools class .
 *
 * @version $Id: StringToolsTest.java 30976 2019-01-03 14:47:14Z samuellb $
 */
public class StringToolsTest {
    /** Logger. */
  private static Logger log = Logger.getLogger(StringToolsTest.class);

  /**
   * tests stripping whitespace.
   *
   * @throws Exception error
   */
  @Test
  public void test01StripWhitespace() throws Exception {
    log.trace(">test01StripWhitespace()");
    String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
    assertEquals("foobarquux", StringTools.stripWhitespace(test));
    log.trace(">test01StripWhitespace()");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void test02IpStringToOctets() throws Exception {
    log.trace(">test02IpStringToOctets()");
    String ip = "23.34.45.167";
    byte[] octs = StringTools.ipStringToOctets(ip);
    for (int i = 0; i < octs.length; i++) {
      log.debug("octs[" + i + "]=" + (int) octs[i]);
    }
    log.trace(">test02IpStringToOctets()");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void test03Strip() throws Exception {
    log.trace(">test03Strip()");
    String strip1 = "foo$bar:far%";
    String stripped = StringTools.strip(strip1);
    assertFalse(
        "String has chars that should be stripped!",
        StringTools.hasSqlStripChars(strip1).isEmpty());
    assertEquals("String not stripped correctly!", stripped, "foo/bar:far/");
    log.trace("<test03Strip()");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void test04Strip() throws Exception {
    log.trace(">test04Strip()");
    String strip1 = "CN=foo, O=Acme\\, Inc, OU=;\\/\\<\\>bar";
    String stripped = StringTools.strip(strip1);
    assertFalse(
        "String has chars that should be stripped!",
        StringTools.hasSqlStripChars(strip1).isEmpty());
    assertEquals(
        "String not stripped correctly! " + stripped,
        "CN=foo, O=Acme\\, Inc, OU=//\\<\\>bar",
        stripped);

    strip1 = "CN=foo, O=Acme\\, Inc, OU=;\\/<>\"bar";
    stripped = StringTools.strip(strip1);
    assertFalse(
        "String has chars that should be stripped!",
        StringTools.hasSqlStripChars(strip1).isEmpty());
    assertEquals(
        "String not stripped correctly! " + stripped,
        "CN=foo, O=Acme\\, Inc, OU=//<>\"bar",
        stripped);
    strip1 = "CN=foo\\+bar, O=Acme\\, Inc";
    stripped = StringTools.strip(strip1);
    assertTrue(
        "String does not have chars to be stripped!",
        StringTools.hasSqlStripChars(strip1).isEmpty());
    assertEquals(
        "String not stripped correctly! " + stripped,
        "CN=foo\\+bar, O=Acme\\, Inc",
        stripped);

    // Multi-valued.. not supported by EJBCA yet.. let it through for backwards
    // compatibility.
    strip1 = "CN=foo+CN=bar, O=Acme\\, Inc";
    stripped = StringTools.strip(strip1);
    assertTrue(
        "String does not have chars to be stripped!",
        StringTools.hasSqlStripChars(strip1).isEmpty());
    assertEquals(
        "String not stripped correctly! " + stripped,
        "CN=foo+CN=bar, O=Acme\\, Inc",
        stripped);

    log.trace("<test04Strip()");
  }

  /** key. */
  static final String FORBIDDEN_CHARS_KEY = "forbidden.characters";

  private static void forbiddenTest(
      final String forbidden, final String input, final String output) {
    ConfigurationHolderUtil.instance().setProperty(FORBIDDEN_CHARS_KEY, forbidden);
    StringTools.CharSet.reset();
    final String stripped = StringTools.strip(input);
    if (input.equals(output)) {
      assertTrue(
          "The string do NOT have chars that should be stripped!",
          StringTools.hasStripChars(input).isEmpty());
    } else {
      assertFalse(
          "The string DO have chars that should be stripped!",
          StringTools.hasStripChars(input).isEmpty());
    }
    assertEquals("String not stripped correctly!", output, stripped);
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void test05Strip() throws Exception {
    log.trace(">test05Strip()");
    final Object originalValue =
        ConfigurationHolderUtil.instance().getProperty(FORBIDDEN_CHARS_KEY);
    try {
      final String input =
          "|\n|\r|;|foo bar|!|\u0000|`|?|$|~|\\<|\\>|\\\"|\\\\";
      final String defaultOutput =
          "|/|/|/|foo bar|/|/|/|/|/|/|\\<|\\>|\\\"|\\\\";
      forbiddenTest(null, input, defaultOutput);
      forbiddenTest("\n\r;!\u0000%`?$~", input, defaultOutput);
      forbiddenTest("", input, input);
      forbiddenTest("ABCDEF", input, input);
      forbiddenTest(
          "rab| oof<>\"\\", input, "/\n/\r/;/////////!/\u0000/`/?/$/~////////");
      forbiddenTest(
          "\"", input, "|\n|\r|;|foo bar|!|\u0000|`|?|$|~|\\<|\\>|/|\\\\");
      forbiddenTest(
          "f", input, "|\n|\r|;|/oo bar|!|\u0000|`|?|$|~|\\<|\\>|\\\"|\\\\");
    } finally {
      ConfigurationHolderUtil.instance()
          .setProperty(FORBIDDEN_CHARS_KEY, originalValue);
    }
    log.trace("<test05Strip()");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testBase64() throws Exception {
    String s1 = "C=SE, O=abc, CN=def";
    String b1 = StringTools.putBase64String(s1);
    String s2 = StringTools.getBase64String(b1);
    assertEquals(s2, s1);

    s1 = "C=SE, O=åäö, CN=ÅÖ";
    b1 = StringTools.putBase64String(s1);
    s2 = StringTools.getBase64String(b1);
    assertEquals(s2, s1);
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testObfuscate() throws Exception {
    String obf = StringTools.obfuscate("foo123");
    String deobf = StringTools.deobfuscate(obf);
    assertEquals("foo123", deobf);
    String obfif = StringTools.obfuscate("foo123qw");
    String deobfif = StringTools.deobfuscate(obfif);
    assertEquals("foo123qw", deobfif);
    assertEquals("foo123qwe", StringTools.deobfuscateIf("foo123qwe"));
    // Empty String should be handled
    assertEquals("", StringTools.obfuscate(""));
    assertEquals("", StringTools.deobfuscateIf("OBF:"));
    assertEquals("", StringTools.deobfuscate("OBF:"));
    assertNull(StringTools.deobfuscate(null));
    assertNull(StringTools.deobfuscateIf(null));
    assertNull(StringTools.obfuscate(null));
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testPbe() throws Exception {
    CryptoProviderTools.installBCProvider();
    String enc = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
    String dec =
        StringTools.pbeDecryptStringWithSha256Aes192(
            enc,
            ConfigurationHolderUtil.getString("password.encryption.key")
                .toCharArray());
    assertEquals("foo123", dec);
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testKeySequence() throws Exception {
    String oldSeq = "00001";
    assertEquals(
        "00002",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    oldSeq = "92002";
    assertEquals(
        "92003",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    oldSeq = "SE201";
    assertEquals(
        "SE202",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    oldSeq = "SEFO1";
    assertEquals(
        "SEFO2",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    oldSeq = "SEBAR";
    assertEquals(
        "SEBAR",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));

    oldSeq = "AAAAA";
    assertEquals(
        "AAAAB",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC, oldSeq));
    oldSeq = "SE201";
    assertEquals(
        "SE202",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC, oldSeq));
    oldSeq = "SEFAA";
    assertEquals(
        "SEFAB",
        StringTools.incrementKeySequence(
            StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC,
            oldSeq));
  }

  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testIpStringToOctets() throws Exception {
    String ipv4 = "192.168.4.45";
    byte[] ipv4oct = StringTools.ipStringToOctets(ipv4);
    assertNotNull(ipv4oct);
    assertEquals(4, ipv4oct.length);
    String ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    byte[] ipv6oct = StringTools.ipStringToOctets(ipv6);
    assertNotNull(ipv6oct);
    assertEquals(16, ipv6oct.length);
    String invalid = "foo";
    byte[] oct = StringTools.ipStringToOctets(invalid);
    assertNotNull(oct);
    assertEquals(0, oct.length);
    String invalidipv4 = "192.177.333.22";
    oct = StringTools.ipStringToOctets(invalidipv4);
    assertNotNull(oct);
    assertEquals(0, oct.length);
    String invalidipv6 = "2001:0db8:85a3:0000:0000:8a2e:11111:7334";
    oct = StringTools.ipStringToOctets(invalidipv6);
    assertNotNull(oct);
    assertEquals(0, oct.length);
  }
  /**
   * Test.
   */
  @Test
  public void testIsValidSanDnsName() {
    assertTrue(StringTools.isValidSanDnsName("a.b.cc"));
    assertTrue(StringTools.isValidSanDnsName("b.cc"));
    assertFalse(StringTools.isValidSanDnsName("b.cc."));
    assertFalse(StringTools.isValidSanDnsName("a.b.cc."));
    assertFalse(StringTools.isValidSanDnsName("*.b.cc."));
    assertFalse(StringTools.isValidSanDnsName("c."));
    assertFalse(StringTools.isValidSanDnsName("b.c."));
    assertFalse(StringTools.isValidSanDnsName("a.b.c."));
    assertFalse(StringTools.isValidSanDnsName("*.b.c."));

    assertFalse(StringTools.isValidSanDnsName(".primekey.com"));
    assertFalse(StringTools.isValidSanDnsName("primekey..com"));
    assertFalse(StringTools.isValidSanDnsName("sub.*.primekey.com"));
    assertFalse(StringTools.isValidSanDnsName("-primekey.com"));
    assertFalse(StringTools.isValidSanDnsName("primekey-.com"));
    assertFalse(
        StringTools.isValidSanDnsName(
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com"));
    assertFalse(
        StringTools.isValidSanDnsName(
            "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.com"));
    assertFalse(StringTools.isValidSanDnsName("pr#mekey.com"));
    assertFalse(StringTools.isValidSanDnsName(" primekey.com"));
    assertFalse(StringTools.isValidSanDnsName("primekey.com "));
    assertFalse(StringTools.isValidSanDnsName("*.*.b.c"));

    assertTrue(StringTools.isValidSanDnsName("a.b.c.d.e.g.h.i.j.k.ll"));
    assertTrue(StringTools.isValidSanDnsName("*.b.cc"));
    assertTrue(StringTools.isValidSanDnsName("r3.com"));
    assertTrue(StringTools.isValidSanDnsName("com.r3"));
    assertTrue(StringTools.isValidSanDnsName("primekey-solutions.com"));
    assertTrue(StringTools.isValidSanDnsName("primekey.tech-solutions"));
    assertTrue(StringTools.isValidSanDnsName("3d.primekey.com"));
    assertTrue(StringTools.isValidSanDnsName("sub-test.primekey.com"));
    assertTrue(StringTools.isValidSanDnsName("UPPERCASE.COM"));
    assertTrue(StringTools.isValidSanDnsName("M1XeD.CaSE.C0M"));
    assertTrue(StringTools.isValidSanDnsName("xn--4pf93sJb.com"));
    assertTrue(StringTools.isValidSanDnsName("lab.primekey"));
    assertTrue(
        StringTools.isValidSanDnsName(
            "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                + "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.com"));
    assertTrue(
        StringTools.isValidSanDnsName(
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com"));
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testHasSqlStripChars() throws Exception {
    String str = "select * from Table";
    assertTrue(StringTools.hasSqlStripChars(str).isEmpty());

    str = "select * from Table; delete from password";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());

    str = "select * from User where username like 'foo\\%'";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());

    // check that we can escape commas
    str = "foo\\,";
    assertTrue(StringTools.hasSqlStripChars(str).isEmpty());

    str = "foo\\;";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());

    // Check that escaping does not work for other characters
    str = "foo\\?";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());

    str = "foo\\?bar";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());

    str = "\\?bar";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());

    // Check special case that a slash at the end also returns bad
    str = "foo\\";
    assertFalse(StringTools.hasSqlStripChars(str).isEmpty());
  }
  /**
   * Test.
   */
  @Test
  public void testParseCertData() {
    String certdata =
        "0000AAAA : DN : \"CN=foo,O=foo,C=SE\" : SubjectDN : \"CN=foo2,C=SE\"";
    String[] res = StringTools.parseCertData(certdata);
    assertNotNull(res);
    assertEquals(
        "Failed to find the administrator certificate serialnumber",
        res[0],
        "0000AAAA");
    assertEquals(
        "Failed to find the administrator certificate issuerDN",
        res[1],
        "CN=foo,O=foo,C=SE");

    certdata = "0000AAAA,CN=foo,O=foo,C=SE";
    res = StringTools.parseCertData(certdata);
    assertNotNull(res);
    assertEquals(
        "Failed to find the client certificate serialnumber",
        res[0],
        "0000AAAA");
    assertEquals(
        "Failed to find the client certificate issuerDN",
        res[1],
        "CN=foo,O=foo,C=SE");

    certdata = "0000AAAA, CN=foo,O=foo,C=SE";
    res = StringTools.parseCertData(certdata);
    assertNotNull(res);
    assertEquals(
        "Failed to find the client certificate serialnumber",
        res[0],
        "0000AAAA");
    assertEquals(
        "Failed to find the client certificate issuerDN",
        res[1],
        "CN=foo,O=foo,C=SE");

    certdata = "0000AAAA, CN=foo,SN=123456,O=foo,C=SE";
    res = StringTools.parseCertData(certdata);
    assertNotNull(res);
    assertEquals(
        "Failed to find the client certificate serialnumber",
        res[0],
        "0000AAAA");
    assertEquals(
        "Failed to find the client certificate issuerDN",
        "CN=foo,SN=123456,O=foo,C=SE",
        res[1]);

    certdata = "0000AAAA, E=ca.intern@primek-y.se,CN=foo,SN=123456,O=foo,C=SE";
    res = StringTools.parseCertData(certdata);
    assertNotNull(res);
    assertEquals(
        "Failed to find the client certificate serialnumber",
        res[0],
        "0000AAAA");
    assertEquals(
        "Failed to find the client certificate issuerDN",
        "E=ca.intern@primek-y.se,CN=foo,SN=123456,O=foo,C=SE",
        res[1]);

    certdata =
        "AAAAFFFF,"
            + " 1.2.3.4.5=Test,CN=foo,1.2.345678=Hello,O=foo,"
            + "ORGANIZATIONIDENTIFIER=OrgIdent,C=SE";
    res = StringTools.parseCertData(certdata);
    assertNotNull(res);
    assertEquals(
        "Failed to find the client certificate serialnumber",
        res[0],
        "AAAAFFFF");
    assertEquals(
        "Failed to find the client certificate issuerDN",
        "1.2.3.4.5=Test,CN=foo,1.2.345678=Hello,O=foo,"
        + "ORGANIZATIONIDENTIFIER=OrgIdent,C=SE",
        res[1]);
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testSplitURIs() throws Exception {
    assertEquals(
        Arrays.asList("aa;a", "bb;;;b", "cc"),
        StringTools.splitURIs("\"aa;a\";\"bb;;;b\";\"cc\""));
    assertEquals(
        Arrays.asList("aa", "bb;;;b", "cc"),
        StringTools.splitURIs("aa;\"bb;;;b\";\"cc\""));
    assertEquals(
        Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;cc"));
    assertEquals(
        Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;cc;"));
    assertEquals(
        Arrays.asList("aa", "bb", "cc"),
        StringTools.splitURIs("aa   ;  bb;cc  ")); // Extra white-spaces
    assertEquals(
        Arrays.asList("aa", "bb", "cc"),
        StringTools.splitURIs("  aa;bb ;cc;  ")); // Extra white-spaces
    assertEquals(
        Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;;;;cc;"));
    assertEquals(
        Arrays.asList("aa", "bb", "cc"),
        StringTools.splitURIs(";;;;;aa;bb;;;;cc;"));
    assertEquals(
        Arrays.asList("aa", "b", "c", "d", "e"),
        StringTools.splitURIs(";;\"aa\";;;b;c;;;;d;\"e\";;;"));
    assertEquals(
        Arrays.asList("http://example.com"),
        StringTools.splitURIs("http://example.com"));
    assertEquals(
        Arrays.asList("http://example.com"),
        StringTools.splitURIs("\"http://example.com\""));
    assertEquals(
        Arrays.asList("http://example.com"),
        StringTools.splitURIs("\"http://example.com\";"));
    assertEquals(Collections.EMPTY_LIST, StringTools.splitURIs(""));
    assertEquals(
        Arrays.asList("http://example.com"),
        StringTools.splitURIs("\"http://example.com")); // No ending quote
    assertEquals(
        Arrays.asList("aa;a", "bb;;;b", "cc"),
        StringTools.splitURIs("\"aa;a\";\"bb;;;b\";\"cc")); // No ending quote
  }
  /**
   * Test.
   */
  @Test
  public void testB64() {
    assertNull(StringTools.getBase64String(null));
    assertEquals("", StringTools.getBase64String(""));
    assertEquals("B64:", StringTools.getBase64String("B64:"));
    assertEquals("b64:", StringTools.getBase64String("b64:"));
    assertEquals(
        "test",
        StringTools.getBase64String(StringTools.putBase64String("test")));
    assertEquals(
        "test~!\"#%&/()", StringTools.putBase64String("test~!\"#%&/()", true));
    assertEquals(
        "test~!\"#%&/()",
        StringTools.getBase64String(
            StringTools.putBase64String("test~!\"#%&/()", true)));
    assertEquals(
        "test~!\"#%&/()",
        StringTools.getBase64String(
            StringTools.putBase64String("test~!\"#%&/()", false)));
    assertEquals("B64:w6XDpMO2w7zDqA==", StringTools.putBase64String("åäöüè"));
    assertEquals(
        "B64:w6XDpMO2w7zDqA==", StringTools.putBase64String("åäöüè", true));
    assertEquals(
        "åäöüè",
        StringTools.getBase64String(
            StringTools.putBase64String("åäöüè", true)));
    assertEquals(
        "åäöüè",
        StringTools.getBase64String(
            StringTools.putBase64String("åäöüè", false)));
    // Check against unicodes as well, just to be sure encodiings are not messed
    // up by eclipse of anything else
    assertEquals(
        "B64:w6XDpMO2w7zDqA==",
        StringTools.putBase64String("\u00E5\u00E4\u00F6\u00FC\u00E8"));
    assertEquals(
        "B64:w6XDpMO2w7zDqA==",
        StringTools.putBase64String("\u00E5\u00E4\u00F6\u00FC\u00E8", true));
    assertEquals(
        "\u00E5\u00E4\u00F6\u00FC\u00E8",
        StringTools.getBase64String(
            StringTools.putBase64String("åäöüè", true)));
    assertEquals(
        "\u00E5\u00E4\u00F6\u00FC\u00E8",
        StringTools.getBase64String(
            StringTools.putBase64String("åäöüè", false)));
  }
  /**
   * Test.
   */
  @Test
  public void testStripXss() {
    final String str = "foo<tag>tag</tag>!";
    String ret = StringTools.strip(str);
    assertEquals(
        "<> should not have been stripped, but ! should have: ",
        "foo<tag>tag</tag>/",
        ret);
    ret = StringTools.stripUsername(str);
    assertEquals(
        "<> should have been stripped and so should !",
        "foo/tag/tag//tag//",
        ret);
  }
  /**
   * Test.
   */
  @Test
  public void testCleanXForwardedFor() {
    assertEquals(
        "192.0.2.43, 2001:db8:cafe::17",
        StringTools.getCleanXForwardedFor("192.0.2.43, 2001:db8:cafe::17"));
    assertEquals("192.0.2.43", StringTools.getCleanXForwardedFor("192.0.2.43"));
    assertEquals(
        "2001:db8:cafe::17",
        StringTools.getCleanXForwardedFor("2001:db8:cafe::17"));
    assertEquals(
        "192.0.2.43, 2001:db8:cafe::17",
        StringTools.getCleanXForwardedFor(" 192.0.2.43, 2001:db8:cafe::17 "));
    assertEquals(
        "192.0.2.43, 2001:db8:cafe::17",
        StringTools.getCleanXForwardedFor("192.0.2.43, 2001:DB8:CAFE::17"));
    assertEquals(null, StringTools.getCleanXForwardedFor(null));
    assertEquals(
        "??c?????a?e????a?e???????????????",
        StringTools.getCleanXForwardedFor(
            "<script>alert(\"alert!\");</stript>"));
  }
  /**
   * Test.
 * @throws InvalidKeyException fail
 * @throws NoSuchAlgorithmException fail
 * @throws NoSuchProviderException  fail
 * @throws NoSuchPaddingException  fail
 * @throws InvalidAlgorithmParameterException fail
 * @throws IllegalBlockSizeException fail
 * @throws BadPaddingException fail
 * @throws UnsupportedEncodingException fail
 * @throws InvalidKeySpecException fail
   */
  @Test
  public void testPasswordEncryptionAndObfuscation()
      throws InvalidKeyException, NoSuchAlgorithmException,
          NoSuchProviderException, NoSuchPaddingException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException,
          BadPaddingException, UnsupportedEncodingException,
          InvalidKeySpecException {
    // First test with legacy encryption, using default pwd
    ConfigurationHolderUtil.backupConfiguration();

      String obf = StringTools.obfuscate("foo123");
      String deobf = StringTools.deobfuscate(obf);
      assertEquals(
          "Obfuscated/De-obfuscated password does not match", "foo123", deobf);

      // Using an encrypted string from older version of EJBCA, using BC 1.52
      String pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              "6bc841b2745e2c95e042a68b4777b34c",
              ConfigurationHolderUtil.getDefaultValue("password.encryption.key")
                  .toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match", "foo123", pwd);

      String pbe = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
      assertEquals(
          "Encryption version should be legacy",
          "legacy",
          StringTools.getEncryptVersionFromString(pbe));
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              pbe,
              ConfigurationHolderUtil.getString("password.encryption.key")
                  .toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match", "foo123", pwd);

      pbe =
          StringTools.pbeEncryptStringWithSha256Aes192(
              "customEncryptionKey", "zeG6qE2zV7BddqHc".toCharArray());
      try {
        pwd =
            StringTools.pbeDecryptStringWithSha256Aes192(
                pbe, "foo123abc".toCharArray());
        fail("Decryption should not work with wrong key");
      } catch (IllegalBlockSizeException
          | BadPaddingException
          | InvalidKeyException
          | InvalidKeySpecException e) {
        // we should end up here typically when encryption fails, but it's not
        // 100% sure
      }
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              pbe, "zeG6qE2zV7BddqHc".toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match",
          "customEncryptionKey",
          pwd);

    // Second test with new encryption
    ConfigurationHolderUtil.updateConfiguration(
        "password.encryption.key", "1POTQK7ofSGTPsOOXwIo2Z0jfXsADtXx");

      obf = StringTools.obfuscate("foo123");
      deobf = StringTools.deobfuscate(obf);
      assertEquals(
          "Obfuscated/De-obfuscated password does not match", "foo123", deobf);

      // Using an encrypted string from older version of EJBCA, using BC 1.52
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              "6bc841b2745e2c95e042a68b4777b34c",
              ConfigurationHolderUtil.getDefaultValue("password.encryption.key")
                  .toCharArray());
      // Legacy decryption with default pwd should always work
      assertEquals(
          "Encrypted/decrypted password does not match", "foo123", pwd);
      try {
        pwd =
            StringTools.pbeDecryptStringWithSha256Aes192(
                "6bc841b2745e2c95e042a68b4777b34c",
                ConfigurationHolderUtil.getString("password.encryption.key")
                    .toCharArray());
        fail(
            "Decryption of legacey encrypted string with non default pwd"
                + " should not work");
      } catch (BadPaddingException e) {
        // NOPMD: we expected failure
      }

      pbe = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              pbe,
              ConfigurationHolderUtil.getString("password.encryption.key")
                  .toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match", "foo123", pwd);

      pbe =
          StringTools.pbeEncryptStringWithSha256Aes192(
              "customEncryptionKey", "zeG6qE2zV7BddqHc".toCharArray());
      assertEquals(
          "Encryption version should be encv1",
          "encv1",
          StringTools.getEncryptVersionFromString(pbe));
      try {
        pwd =
            StringTools.pbeDecryptStringWithSha256Aes192(
                pbe, "foo123abc".toCharArray());
        assertFalse(
            "Decryption should not work with wrong key. Decrypted data: " + pwd,
            "customEncryptionKey".equals(pwd));
      } catch (IllegalBlockSizeException
          | BadPaddingException
          | InvalidKeyException
          | InvalidKeySpecException e) {
        // we should end up here typically when encryption fails, but it's not
        // 100% sure
      }
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              pbe, "zeG6qE2zV7BddqHc".toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match",
          "customEncryptionKey",
          pwd);

      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              "encv1:61ea7d4ce0564370246f219b7ab7533f8066c4d0a58950e45dd1d3449"
              + "7f98e08:100:3a3e10a382d4c504fc4b7900be204bcc",
              "1POTQK7ofSGTPsOOXwIo2Z0jfXsADtXx".toCharArray());
      assertEquals(
          "Encrypted/decrypted password (from 6.8.0) does not match",
          "foo123",
          pwd);


    // Third test with a different count
    ConfigurationHolderUtil.updateConfiguration(
        "password.encryption.count", "100000");

      obf = StringTools.obfuscate("foo123");
      deobf = StringTools.deobfuscate(obf);
      assertEquals(
          "Obfuscated/De-obfuscated password does not match", "foo123", deobf);

      // Using an encrypted string from older version of EJBCA, using BC 1.52
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              "6bc841b2745e2c95e042a68b4777b34c",
              ConfigurationHolderUtil.getDefaultValue("password.encryption.key")
                  .toCharArray());
      // Legacy decryption with default pwd should always work
      assertEquals(
          "Encrypted/decrypted password does not match", "foo123", pwd);

      pbe = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
      log.info(pbe);
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              pbe,
              ConfigurationHolderUtil.getString("password.encryption.key")
                  .toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match", "foo123", pwd);

      pbe =
          StringTools.pbeEncryptStringWithSha256Aes192(
              "customEncryptionKey", "zeG6qE2zV7BddqHc".toCharArray());
      assertEquals(
          "Encryption version should be encv1",
          "encv1",
          StringTools.getEncryptVersionFromString(pbe));
      try {
        pwd =
            StringTools.pbeDecryptStringWithSha256Aes192(
                pbe, "foo123abc".toCharArray());
        fail("Decryption should not work with wrong key");
      } catch (IllegalBlockSizeException
          | BadPaddingException
          | InvalidKeyException
          | InvalidKeySpecException e) {
        // we should end up here typically when encryption fails, but it's not
        // 100% sure
      }
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              pbe, "zeG6qE2zV7BddqHc".toCharArray());
      assertEquals(
          "Encrypted/decrypted password does not match",
          "customEncryptionKey",
          pwd);

      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              "encv1:61ea7d4ce0564370246f219b7ab7533f8066c4d0a58950e45dd1d34497"
              + "f98e08:100:3a3e10a382d4c504fc4b7900be204bcc",
              "1POTQK7ofSGTPsOOXwIo2Z0jfXsADtXx".toCharArray());
      assertEquals(
          "Encrypted/decrypted password (from 6.8.0) with 100 rounds does not"
              + " match",
          "foo123",
          pwd);
      pwd =
          StringTools.pbeDecryptStringWithSha256Aes192(
              "encv1:7c11bd9798e9d74293d967266fad9d04e6a19833fd3674b049580efa31"
              + "53e32d:100000:f9b7f769bb98f7b52eadf6643b598541",
              "1POTQK7ofSGTPsOOXwIo2Z0jfXsADtXx".toCharArray());
      assertEquals(
          "Encrypted/decrypted password (from 6.8.0) with 100000 rounds does"
              + " not match",
          "foo123",
          pwd);


    assertEquals(
        "Encryption version should be none",
        "none",
        StringTools.getEncryptVersionFromString("foo123"));

    ConfigurationHolderUtil.restoreConfiguration();
  }
  /**
   * Test.
   */
  @Test
  public void testIsAlphaOrAsciiPrintable() {
    assertTrue(StringTools.isAlphaOrAsciiPrintable("foobar123"));
    assertTrue(StringTools.isAlphaOrAsciiPrintable("foobar123-_()?<>"));
    assertTrue(
        StringTools.isAlphaOrAsciiPrintable(
            "foobar123\u00e5")); // Swedish a-ring
    assertFalse(StringTools.isAlphaOrAsciiPrintable("foobar123\r"));
    assertFalse(StringTools.isAlphaOrAsciiPrintable("foobar123\0"));
    assertFalse(StringTools.isAlphaOrAsciiPrintable("foobar123\n"));
  }
  /**
   * Test.
   */
  @Test
  public void testIsLesserThan() {
    assertFalse(StringTools.isLesserThan("6.0.1", "6.0.1"));
    assertFalse(StringTools.isLesserThan("6.0.1", "6.0.0"));
    assertFalse(StringTools.isLesserThan("6.0.1", "5.3.4"));
    assertFalse(StringTools.isLesserThan("5.0", "5.0"));
    assertFalse(StringTools.isLesserThan("5.0", "5.0.0"));
    assertFalse(StringTools.isLesserThan("5.0.0", "5.0"));
    assertFalse(StringTools.isLesserThan("5.0.0.0", "5.0"));
    assertFalse(StringTools.isLesserThan("5.0", "5.0.0.0"));
    assertFalse(StringTools.isLesserThan("6.0.1", "6.0"));
    assertFalse(StringTools.isLesserThan("6.14.0", "6.13.0.14"));
    assertFalse(StringTools.isLesserThan("6.14.0", "6.14.0.Alpha1"));
    assertFalse(
        StringTools.isLesserThan(
            "6.14.0.junk.0",
            "6.14.0.junk.0")); // incorrect syntax, but shouldn't crash

    assertTrue(StringTools.isLesserThan("6.0.1", "6.3.0"));
    assertTrue(StringTools.isLesserThan("6.0.1", "6.3.0"));
    assertTrue(StringTools.isLesserThan("6.0", "6.0.1"));
    assertTrue(StringTools.isLesserThan("6.13.0.14", "6.14.0"));
  }
  /**
   * Test.
   */
  @Test
  public void normalizeNewLines() {
    assertEquals(
        "normalizeNewLines with null.",
        null,
        StringTools.normalizeNewlines(null));
    assertEquals(
        "normalizeNewLines with empty string.",
        "",
        StringTools.normalizeNewlines(""));
    assertEquals(
        "normalizeNewLines with Windows line separator.",
        "\n",
        StringTools.normalizeNewlines("\r\n"));
    assertEquals(
        "normalizeNewLines with Mac line separator.",
        "\n",
        StringTools.normalizeNewlines("\r"));
    assertEquals(
        StringEscapeUtils.escapeJava("\n\nA"),
        StringEscapeUtils.escapeJava(StringTools.normalizeNewlines("\r\r\nA")));
    assertEquals(
        StringEscapeUtils.escapeJava("\nA\nB\n\n"),
        StringEscapeUtils.escapeJava(
            StringTools.normalizeNewlines("\rA\nB\n\n")));
    assertEquals(
        StringEscapeUtils.escapeJava(" \n A \n B \n C"),
        StringEscapeUtils.escapeJava(
            StringTools.normalizeNewlines(" \n A \r\n B \r C")));
  }
  /**
   * Test.
   */
  @Test
  public void normalizeSystemLineSeparator() {
    // Separate test to catch system dependent problems
    assertEquals(
        "normalizeNewLines with system line separator.",
        "A\nB",
        StringTools.normalizeNewlines("A" + System.lineSeparator() + "B"));
  }
  /**
   * Test.
   */
  @Test
  public void splitByNewLines() {
    assertNotNull(StringTools.splitByNewlines(""));
    assertNotNull(StringTools.splitByNewlines("\n"));
    assertEquals(1, StringTools.splitByNewlines("Test").length);
    assertEquals(2, StringTools.splitByNewlines("Test\r\nABC").length);
  }
}
