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

package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import org.junit.Test;

/**
 * Tests Base64 HashMap XML encoding and decoding.
 *
 * @version $Id: HashMapTest.java 34163 2020-01-02 15:00:17Z samuellb $
 */
public class HashMapTest {
    /**
       * Test.
       * @throws Exception fail
       */
  @SuppressWarnings("rawtypes")
  @Test
  public void testHashMapNormal() throws Exception {
    HashMap<String, Comparable> a = new HashMap<String, Comparable>();
    a.put("foo0", Boolean.FALSE);
    a.put("foo1", "fooString");
    a.put("foo2", Integer.valueOf(2));
    a.put("foo3", Boolean.TRUE);

    // Write to XML
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    XMLEncoder encoder = new XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    String data = baos.toString("UTF8");
    // log.error(data);

    SecureXMLDecoder decoder =
        new SecureXMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
    HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
    decoder.close();
    assertEquals(((Boolean) b.get("foo0")).booleanValue(), false);
    assertEquals(((Boolean) b.get("foo3")).booleanValue(), true);
    assertEquals(((String) b.get("foo1")), "fooString");
    assertEquals(((Integer) b.get("foo2")).intValue(), 2);
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @SuppressWarnings("rawtypes")
  @Test
  public void testHashMapStrangeChars() throws Exception {
    HashMap<String, Comparable> a = new HashMap<String, Comparable>();
    a.put("foo0", Boolean.FALSE);
    a.put("foo1", "\0001\0002fooString");
    a.put("foo2", Integer.valueOf(2));
    a.put("foo3", Boolean.TRUE);

    // Write to XML
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    XMLEncoder encoder = new XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    String data = baos.toString("UTF8");
    // log.error(data);

    try {
      SecureXMLDecoder decoder =
          new SecureXMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
      HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
      decoder.close();
      assertEquals(((Boolean) b.get("foo0")).booleanValue(), false);
      // We can get two different errors, I don't know if it is different java
      // versions or what...
      // The important thing is that we do expect an error to occur here
    } catch (ClassCastException e) {
      return;
    } catch (ArrayIndexOutOfBoundsException e) {
      return;
    }
    String javaver = System.getProperty("java.version");
    System.out.println(javaver);
    if (getVersion() >= 6) {
      // In java 1.6 the above does work because it encodes the special
      // characters
      //   <string><char code="#0"/>1<char code="#0"/>2fooString</string>
      assertTrue(true);
    } else {
      // In java 1.5 the above does not work, because it will insert bad
      // xml-characters
      // so the test will fail if we got here.
      assertTrue(false);
    }
  }

  /* from stack xchange, to work around the Java Versioning
   * system change between Java 8 and Java 9 */
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
   * Test.
   * @throws Exception fail
   */
  @SuppressWarnings("rawtypes")
  @Test
  public void testHashMapStrangeCharsSafe() throws Exception {
    HashMap<String, Comparable> h = new HashMap<String, Comparable>();
    h.put("foo0", Boolean.FALSE);
    h.put("foo1", "\0001\0002fooString");
    h.put("foo2", Integer.valueOf(2));
    h.put("foo3", Boolean.TRUE);
    h.put("foo4", "");
    HashMap<Object, Object> a = new Base64PutHashMap();
    a.putAll(h);

    // Write to XML
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    XMLEncoder encoder = new XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    String data = baos.toString("UTF8");
    // log.error(data);

    try {
      SecureXMLDecoder decoder =
          new SecureXMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
      HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
      decoder.close();
      @SuppressWarnings("unchecked")
      HashMap<Object, Object> c = new Base64GetHashMap(b);
      assertEquals(((Boolean) c.get("foo0")).booleanValue(), false);
      assertEquals(((Boolean) c.get("foo3")).booleanValue(), true);
      assertEquals(((String) c.get("foo1")), "\0001\0002fooString");
      assertEquals(((String) c.get("foo4")), "");
      assertEquals(((Integer) c.get("foo2")).intValue(), 2);

    } catch (ClassCastException e) {
      assertTrue(false);
    }
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @SuppressWarnings("rawtypes")
  @Test
  public void testHashMapNormalCharsSafe() throws Exception {
    HashMap<String, Comparable> h = new HashMap<String, Comparable>();
    h.put("foo0", Boolean.FALSE);
    h.put("foo1", "fooString");
    h.put("foo2", Integer.valueOf(2));
    h.put("foo3", Boolean.TRUE);
    h.put("foo4", "");
    HashMap<Object, Object> a = new Base64PutHashMap();
    a.putAll(h);

    // Write to XML
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    XMLEncoder encoder = new XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    String data = baos.toString("UTF8");
    // log.error(data);

    try {
      SecureXMLDecoder decoder =
          new SecureXMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
      HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
      decoder.close();
      @SuppressWarnings("unchecked")
      HashMap<Object, Object> c = new Base64GetHashMap(b);
      assertEquals(((Boolean) c.get("foo0")).booleanValue(), false);
      assertEquals(((Boolean) c.get("foo3")).booleanValue(), true);
      assertEquals(((String) c.get("foo4")), "");
      assertEquals(((String) c.get("foo1")), "fooString");
      assertEquals(((Integer) c.get("foo2")).intValue(), 2);

    } catch (ClassCastException e) {
      assertTrue(false);
    }
  }
}
