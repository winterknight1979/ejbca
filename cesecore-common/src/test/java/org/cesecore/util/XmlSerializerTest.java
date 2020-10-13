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
import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test that XML serialization works as expected.
 *
 * @version $Id: XmlSerializerTest.java 25722 2017-04-20 13:27:16Z samuellb $
 */
public class XmlSerializerTest {
/** Logger. */
  private static final Logger LOG = Logger.getLogger(XmlSerializerTest.class);
  /**
   * Test.
   */
  @Test
  public void serializeSimpleObject() {
    LOG.trace(">serializeSimpleObject");
    final String value = "testValue";
    assertEquals(value, encDecAsXml(value, true, false));
    LOG.trace("<serializeSimpleObject");
  }
  /**
   * Test.
   */
  @Test
  public void serializeSpecialChars() {
    LOG.trace(">serializeSpecialChars");
    final String value = "ĞİŞğışÅÄÖåäö";
    assertEquals(value, encDecAsXml(value, true, true));
    LOG.trace("<serializeSpecialChars");
  }
  /**
   * Test.
   */
  @Test
  public void serializeSpecialCharsWithoutBase64() {
    LOG.trace(">serializeSpecialChars");
    final String value = "ĞİŞğışÅÄÖåäö";
    final String encodedDecoded = (String) encDecAsXml(value, false, false);
    assertEquals(value, encodedDecoded);
    LOG.trace("<serializeSpecialChars");
  }
  /**
   * Test.
   */
  @Test
  public void serializeSpecialXmlChars() {
    LOG.trace(">serializeSpecialXmlChars");
    final String value = "</string>";
    assertEquals(value, encDecAsXml(value, true, false));
    LOG.trace("<serializeSpecialXmlChars");
  }

  /**
   * Make a round trip using a xml enc and dec.
   *
   * @param value val
   * @param useBase64 bool
   * @param expectBase64 bool
   * @return object
   */
  private Object encDecAsXml(
      final String value, final boolean useBase64, final boolean expectBase64) {
    final String key = "SomeKey";
    final Map<String, Object> inputMap = new LinkedHashMap<>();
    inputMap.put(key, value);
    final String encoded =
        useBase64
            ? XmlSerializer.encode(inputMap)
            : XmlSerializer.encodeWithoutBase64(inputMap);
    LOG.debug(encoded);
    if (expectBase64) {
      assertTrue(
          "Special characters should be B64: encoded",
          encoded.contains("B64:"));
    } else {
      assertTrue(
          "Special characters should not be entity encoded, or otherwise"
              + " modified.",
          encoded.contains(value));
    }
    return XmlSerializer.decode(encoded).get(key);
  }
}
