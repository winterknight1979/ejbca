/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.junit.Test;

/** @version $Id: DNFieldsUtilTest.java 25580 2017-03-22 14:30:19Z anatom $ */
public class DNFieldsUtilTest {
      /** Config. */
  private static final String TRICKY_VALUE_1 =
      " 10/2=5; 2 backs and a comma\\\\\\\\\\, 8/2=4 2 backs\\\\\\\\"; // last
  // comma
  // is end
  // of
  // value
  // since
  // it is
  // a even
  // number
  // (4) of
  // \
  // before
  /** Config. */
  private static final String TRICKY_VALUE_2 = "\\,"; // a single comma
  /** Config. */
  private static final String TRICKY_VALUE_3 =
      "\\\\\\\\\\\\\\,"; // 3 backs and a comma
  /** Config. */
  private static final String TRICKY_VALUE_4 = "\\\\\\\\\\\\"; // 3 backs
  /** Config. */
  private static final String TRICKY_VALUE_5 =
      "\\,\\\\\\\\\\\\\\,"; // comma 3 backs comma
  /** Config. */
  private static final String TRICKY_VALUE_6 = "\\,\\\\\\\\\\\\";
  /** Config. */
  // comma 3 backs
  private static final String TRICKY_VALUE_7 = "\\,\\,\\,\\,\\,\\,"; // 6 commas
  /** Config. */
  private static final String TRICKY_VALUE_8 =
      "\\\\\\,\\,\\,\\\\\\,\\,\\,\\\\"; // 1 back, 3 commas, 1 back, 3 commas, 1
  // back
  /** Config. */
  private static final String KEY_1 = "key1=";
  /** Config. */
  private static final String KEY_2 = "key2=";
  /** Config. */
  private static final String C = ",";
  /** Config. */
  private static final String C_KEY_1 = C + KEY_1;
  /** Config. */
  private static final String C_KEY_2 = C + KEY_2;
  /** Config. */
  private static final String EMPTY_1 = KEY_1 + C;
  /** Config. */
  private static final String EMPTY_2 = KEY_2 + C;
  /** Config. */
  private static final String ORIGINAL_DN =
      KEY_2
          + TRICKY_VALUE_4
          + C
          + EMPTY_1
          + EMPTY_2
          + EMPTY_1
          + EMPTY_1
          + KEY_1
          + TRICKY_VALUE_1
          + C
          + EMPTY_1
          + KEY_2
          + TRICKY_VALUE_5
          + C
          + EMPTY_1
          + EMPTY_2
          + KEY_1
          + TRICKY_VALUE_2
          + C_KEY_2
          + TRICKY_VALUE_6
          + C
          + EMPTY_1
          + KEY_2
          + TRICKY_VALUE_7
          + C_KEY_1
          + TRICKY_VALUE_3
          + C
          + EMPTY_1
          + EMPTY_2
          + EMPTY_1
          + KEY_2
          + TRICKY_VALUE_8
          + C
          + EMPTY_1
          + EMPTY_2
          + EMPTY_2
          + EMPTY_1
          + EMPTY_1
          + EMPTY_2
          + EMPTY_1
          + KEY_2;
  // Note that originalDN ends with an escaped comma, so this line should end
  // with a comma as a character
  /** Config. */
  private static final String TRAILING_SPACES_REMOVED_DN =
      KEY_2
          + TRICKY_VALUE_4
          + C
          + EMPTY_1
          + EMPTY_2
          + EMPTY_1
          + EMPTY_1
          + KEY_1
          + TRICKY_VALUE_1
          + C
          + EMPTY_1
          + KEY_2
          + TRICKY_VALUE_5
          + C
          + EMPTY_1
          + EMPTY_2
          + KEY_1
          + TRICKY_VALUE_2
          + C_KEY_2
          + TRICKY_VALUE_6
          + C
          + EMPTY_1
          + KEY_2
          + TRICKY_VALUE_7
          + C_KEY_1
          + TRICKY_VALUE_3
          + C
          + EMPTY_2
          + KEY_2
          + TRICKY_VALUE_8
          + C;
  /** Config. */
  private static final String ALL_SPACES_REMOVED_DN =
      KEY_2
          + TRICKY_VALUE_4
          + C_KEY_1
          + TRICKY_VALUE_1
          + C_KEY_2
          + TRICKY_VALUE_5
          + C_KEY_1
          + TRICKY_VALUE_2
          + C_KEY_2
          + TRICKY_VALUE_6
          + C_KEY_2
          + TRICKY_VALUE_7
          + C_KEY_1
          + TRICKY_VALUE_3
          + C_KEY_2
          + TRICKY_VALUE_8
          + C;
  /** Config. */
  private static final String DEFAULT_EMPTY_BEFORE =
      "UNSTRUCTUREDNAME=, DN=, POSTALADDRESS=, NAME=, UID=, OU=,"
          + " 1.3.6.1.4.1.18838.1.1=, 1.3.6.1.4.1.4710.1.3.2=, ST=,"
          + " UNSTRUCTUREDADDRESS=, BUSINESSCATEGORY=, STREET=, CN=test1,"
          + " POSTALCODE=, O=, PSEUDONYM=, DC=, SURNAME=, C=, INITIALS=, SN=,"
          + " L=, GIVENNAME=, TELEPHONENUMBER=, T=, DC=";
  /** Config. */
  private static final String DEFAULT_EMPTY_AFTER = "CN=test1";
  /** Config. */
  private static final String SIMPLE_BEFORE_AFTER = "CN=userName,O=linagora";
  /** Config. */
  private static final String SIMPLE_2_BEFORE =
          "CN=userName,O=, O=linagora, O=";
  /** Config. */
  private static final String SIMPLE_2A_AFTER_A = "CN=userName,O=linagora";
  /** Config. */
  private static final String SIMPLE_2A_AFTER_T = "CN=userName,O=, O=linagora";
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testDnStringToMap() throws Exception {
    // Test empty string -> empty map.
    String string = StringUtils.EMPTY;
    Map<String, String> map = new HashMap<String, String>();
    Map<String, String> dnMap = DNFieldsUtil.dnStringToMap(string);
    assertEquals("An empty DN string must result in an empty map.", map, dnMap);

    // Test valid string with some attributes -> must be all in the map.
    string = "C=SE,O=,OU=Test,CN=Tester";
    map = new HashMap<String, String>();
    map.put("C", "SE");
    map.put("O", StringUtils.EMPTY);
    map.put("OU", "Test");
    map.put("CN", "Tester");
    dnMap = DNFieldsUtil.dnStringToMap(string);
    assertEquals(
        "The DN map size must match the number of DN attributes.",
        4,
        map.size());
    assertTrue(
        "The DN map must contain all attributes.",
        dnMap.containsKey("C")
            && dnMap.containsKey("O")
            && dnMap.containsKey("OU")
            && dnMap.containsKey("CN"));
    assertEquals(
        "The DN map must contain all attributes and values.", map, dnMap);
  }
  /**
   * Test.
   */
  @Test
  public void testDnEqualsWithOtherSerialNumber() {
    // Test empty DN strings.
    String string1 = StringUtils.EMPTY;
    String string2 = StringUtils.EMPTY;
    assertFalse(
        "Empty DNs do not belong to the same CSCA (no valid CSCA subject-DNs).",
        DNFieldsUtil.dnEqualsWithOtherSerialNumber(
            DNFieldsUtil.dnStringToMap(string1),
            DNFieldsUtil.dnStringToMap(string2)));

    // Test CSCA subject-DNs without serialNumber
    string1 = "C=SE,CN=CSCA";
    assertTrue(
        "DNs with the same values for C and CN can belong to the subject-DN of"
            + " the same CSCA.",
        DNFieldsUtil.dnEqualsWithOtherSerialNumber(
            DNFieldsUtil.dnStringToMap(string1),
            DNFieldsUtil.dnStringToMap(string1)));

    // Test subject-DN string with a missing attribute.
    string1 = "C=SE";
    string2 = "C=SE";
    assertFalse(
        "A subject-DN string with missing CN does not belong to a CSCA"
            + " certificate.",
        DNFieldsUtil.dnEqualsWithOtherSerialNumber(
            DNFieldsUtil.dnStringToMap(string1),
            DNFieldsUtil.dnStringToMap(string1)));
  }
  /**
   * Test.
 * @throws Exception  fail
   */
  @Test
  public void testRemoveAllEmpties() throws Exception {
    assertEquals(ALL_SPACES_REMOVED_DN, removeEmpties(ORIGINAL_DN, false));
    assertEquals(DEFAULT_EMPTY_AFTER,
            removeEmpties(DEFAULT_EMPTY_BEFORE, false));
    assertEquals(SIMPLE_BEFORE_AFTER,
            removeEmpties(SIMPLE_BEFORE_AFTER, false));
    assertEquals(SIMPLE_2A_AFTER_A, removeEmpties(SIMPLE_2_BEFORE, false));
  }
  /**
   * Test.
   */
  @Test
  public void testRemoveTrailingEmpties() {
    assertEquals(TRAILING_SPACES_REMOVED_DN, removeEmpties(ORIGINAL_DN, true));
    assertEquals(DEFAULT_EMPTY_AFTER,
            removeEmpties(DEFAULT_EMPTY_BEFORE, true));
    assertEquals(SIMPLE_BEFORE_AFTER,
            removeEmpties(SIMPLE_BEFORE_AFTER, true));
    assertEquals(SIMPLE_2A_AFTER_T, removeEmpties(SIMPLE_2_BEFORE, true));
  }
  /**
   * Test.
   */
  @Test
  public void testRemoveSingleEmpty() {
    assertEquals("", DNFieldsUtil.removeAllEmpties("CN="));
  }
  /**
   * Test.
   */
  @Test
  public void testRemoveSingleEscapedComma() {
    assertEquals("CN=\\,", DNFieldsUtil.removeAllEmpties("CN=\\,"));
  }
  /**
   * Test.
   */
  @Test
  public void testRemoveTrailingEmptiesError() {
    final String badDnString = "ddddddd=, sdfdf, sdfsdf=44";
    final String failMessage = "Behavioral change in DNFieldsUtil.";
    try {
      removeEmpties(badDnString, true);
      fail(failMessage);
    } catch (Exception e) {
      // What we expect if something goes wrong
    }
    try {
      removeEmpties(badDnString, false);
      fail(failMessage);
    } catch (Exception e) {
      // What we expect if something goes wrong
    }
  }

  private String removeEmpties(final String dn, final boolean onlyTrailing) {
    final StringBuilder sb2 = new StringBuilder();
    final StringBuilder sb1 = DNFieldsUtil.removeEmpties(dn, sb2, true);
    final String removedEmpties1 = DNFieldsUtil.removeAllEmpties(dn);
    final String removedEmpties2 = sb2.toString();
    assertEquals(removedEmpties1, removedEmpties2);
    if (sb1 == null) {
      return removedEmpties2;
    }
    if (onlyTrailing) {
      return sb1.toString();
    }
    return removedEmpties2;
  }
}
