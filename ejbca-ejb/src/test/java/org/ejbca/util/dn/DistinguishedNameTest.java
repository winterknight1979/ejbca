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
package org.ejbca.util.dn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.HashMap;
import java.util.Map;
import javax.naming.ldap.Rdn;
import org.cesecore.certificates.util.DnComponents;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for DistinguishedName class.
 *
 * @version $Id: DistinguishedNameTest.java 23703 2016-06-21 09:26:03Z anatom $
 */
public class DistinguishedNameTest {

      /** Param. */
  private static final String DN =
      "cn=David Galichet,o=Fimasys,email=dgalichet@fimasys.fr,"
          + "g=M,email=david.galichet@fimasys.fr";
  /** Param. */
  private static final String OTHER_DN =
      "o=Linagora,email=dgalichet@linagora.fr,ou=Linagora Secu,"
          + "l=Paris,email=david.galichet@linagora.com,"
          + "email=dgalichet@linagora.com";
  /** Param. */
  private DistinguishedName dn = null;
  /** Param. */
  private DistinguishedName otherDn = null;

  /** Param. */
  private static final String SUBJECT_ALT_NAME =
      "RFC822NAME=vkn@linagora.com,IPADDRESS=208.77.188.166";
  /** Param. */
  private static final String OTHER_SUBJECT_ALT_NAME =
      "RFC822NAME=linagora.mail@linagora.com,"
      + "IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";
  /** Param. */
  private DistinguishedName subjectAltName = null;
  /** Param. */
  private DistinguishedName otherSubjectAltName = null;

  /**
   * Setuop.
   * @throws Exception fail
   */
  @Before
  public void setUp() throws Exception {
    otherDn = new DistinguishedName(OTHER_DN);
    otherSubjectAltName = new DistinguishedName(OTHER_SUBJECT_ALT_NAME);
  }

  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testGetRdn() throws Exception {
    dn = createNewDN();
    assertEquals(dn.getRdn("cn"), new Rdn("cn", "David Galichet"));
    assertEquals(
        dn.getRdn("email", 1), new Rdn("email", "dgalichet@fimasys.fr"));
    assertEquals(
        dn.getRdn("email", 0), new Rdn("email", "david.galichet@fimasys.fr"));
    assertNull(dn.getRdn("email", 2));
  }

  /* from stack xchange, to work around the Java
   * Versioning system change between Java 8 and Java 9 */
  private static int getVersion() {
    String version = System.getProperty("java.version");
    if (version.startsWith("1.")) {
      version = version.substring(2, 3);
    } else {
      int dot = version.indexOf(".");
      if (dot != -1) {
        version = version.substring(0, dot);
      }
    }
    return Integer.parseInt(version);
  }

  /**
   * Test of mergeDN method, of class DistinguishedName. This version tests the
   * merge without override.
   *
   * @throws Exception Fail
   */
  @Test
  public void testMergeDnWithoutOverride() throws Exception {

    final String expectedDn =
        "cn=David"
            + " Galichet,o=Fimasys,email=dgalichet@fimasys.fr,"
            + "g=M,email=david.galichet@fimasys.fr,ou=Linagora"
            + " Secu,email=dgalichet@linagora.com,l=Paris";
    final String expectedDnJDK8 =
        "cn=David"
            + " Galichet,o=Fimasys,email=dgalichet@fimasys.fr,"
            + "g=M,email=david.galichet@fimasys.fr,ou=Linagora"
            + " Secu,l=Paris,email=dgalichet@linagora.com";
    dn = createNewDN();
    DistinguishedName newDn = dn.mergeDN(otherDn, false, null);

    int major = getVersion();
    if (major > 7) {
      assertEquals(expectedDnJDK8, newDn.toString());
    } else {
      assertEquals(expectedDn, newDn.toString());
    }
  }

  /**
   * Test of mergeDN method, of class DistinguishedName. This version tests the
   * merge with override.
   *
   * @throws Exception Fail
   */
  @Test
  public void testMergeDnWithOverride() throws Exception {

    final String expectedDn =
        "cn=David"
            + " Galichet,o=Linagora,email=dgalichet@linagora.fr,"
            + "g=M,email=david.galichet@linagora.com,ou=Linagora"
            + " Secu,email=dgalichet@linagora.com,l=Paris";
    final String expectedDnJDK8 =
        "cn=David"
            + " Galichet,o=Linagora,email=dgalichet@linagora.fr,g=M,"
            + "email=david.galichet@linagora.com,ou=Linagora"
            + " Secu,l=Paris,email=dgalichet@linagora.com";

    dn = createNewDN();
    DistinguishedName newDn = dn.mergeDN(otherDn, true, null);

    int major = getVersion();
    if (major > 7) {
      assertEquals(expectedDnJDK8, newDn.toString());
    } else {
      assertEquals(expectedDn, newDn.toString());
    }
  }

  /**
   * Test of mergeDN method, of class DistinguishedName. This version tests the
   * merge without override.
   *
   * @throws Exception fail
   */
  @Test
  public void testMergeSubjectAltNameWithoutOverrideNotUsingEntityEmail()
      throws Exception {

    final String expected =
        "RFC822NAME=vkn@linagora.com,"
        + "IPADDRESS=208.77.188.166,UNIFORMRESOURCEID=other.uri";
    subjectAltName = createNewSubjectAltName();
    Map<String, String> dnMap = new HashMap<String, String>();
    dnMap.put(DnComponents.RFC822NAME, "entitymail@linagora.com");
    DistinguishedName altName =
        subjectAltName.mergeDN(otherSubjectAltName, false, dnMap);

    assertEquals(3, altName.size());

    assertEquals(expected, altName.toString());
  }

  /**
   * Test of mergeDN method, of class DistinguishedName. This version tests the
   * merge without override.
   *
   * @throws Exception Fail
   */
  @Test
  public void testMergeSubjectAltNameWithoutOverrideUsingEntityEmail()
      throws Exception {

    final String expected =
        "RFC822NAME=vkn@linagora.com,"
        + "IPADDRESS=208.77.188.166,UNIFORMRESOURCEID=other.uri";
    subjectAltName = createNewSubjectAltName();
    Map<String, String> dnMap = new HashMap<String, String>();
    dnMap.put(DnComponents.RFC822NAME, "entitymail@linagora.com");
    DistinguishedName altName =
        subjectAltName.mergeDN(otherSubjectAltName, false, dnMap);

    assertEquals(expected, altName.toString());
  }
  /**
   * Test of mergeDN method, of class DistinguishedName. This version tests the
   * merge with override.
   *
   * @throws Exception Fail
   */
  @Test
  public void testMergeSubjectAltNameWithOverrideNotUsingEntityEmail()
      throws Exception {

    final String expected =
        "RFC822NAME=linagora.mail@linagora.com,"
        + "IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";
    subjectAltName = createNewSubjectAltName();
    Map<String, String> dnMap = new HashMap<String, String>();
    DistinguishedName altName =
        subjectAltName.mergeDN(otherSubjectAltName, true, dnMap);

    assertEquals(expected, altName.toString());
  }
  /**
   * Test of mergeDN method, of class DistinguishedName. This version tests the
   * merge with override.
   *
   * @throws Exception Fail
   */
  @Test
  public void testMergeSubjectAltNameWithOverrideUsingEntityEmail()
      throws Exception {
    final String anotherSubjectAltName =
        "IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";

    final String expected =
        "RFC822NAME=entitymail@linagora.com,"
        + "IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";
    DistinguishedName san = new DistinguishedName(anotherSubjectAltName);
    subjectAltName = createNewSubjectAltName();
    Map<String, String> dnMap = new HashMap<String, String>();
    dnMap.put(DnComponents.RFC822NAME, "entitymail@linagora.com");
    DistinguishedName altName = subjectAltName.mergeDN(san, true, dnMap);

    assertEquals(expected, altName.toString());
  }

  private DistinguishedName createNewDN() throws Exception {
    return new DistinguishedName(DN);
  }

  private DistinguishedName createNewSubjectAltName() throws Exception {
    return new DistinguishedName(SUBJECT_ALT_NAME);
  }
}
