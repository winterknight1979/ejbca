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

package org.cesecore.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the ConfigurationHolder class.
 *
 * @version $Id: ConfigurationHolderTest.java 19777 2014-09-18 13:11:18Z
 *     mikekushner $
 */
public class ConfigurationHolderTest {

    /** Setup. */
  @Before
  public void setUp() {
    ConfigurationHolderUtil.instance().clear();
  }

  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testGetString() throws Exception {
    File f = File.createTempFile("cesecore", "test");
    try {
      FileWriter fw = new FileWriter(f);

      // First the value "property1" should not exists in configuration
      // Test null default value and a default value
      String val = ConfigurationHolderUtil.getString("property1");
      assertNull(val);
      // Create a configuration file
      fw.write("property1=foo\n");
      fw.write("property2=${property1}bar\n");
      // Make sure we handle comma in values
      fw.write("property3=EN,DE,FR\n");
      fw.close();
      // We haven't read it so it should still not contain our property
      val = ConfigurationHolderUtil.getString("property1");
      assertEquals(null, val);
      // Add the config file to configuration, now the property should be
      // visible
      ConfigurationHolderUtil.addConfigurationFile(f.getAbsolutePath());
      val = ConfigurationHolderUtil.getString("property1");
      assertEquals("foo", val);
      // An expanded string "${property1}bar" will be expanded with the value
      // from "property1" (foo)
      val = ConfigurationHolderUtil.getString("property2");
      assertEquals("foobar", val);
      // Make sure we handle comma in values
      val = ConfigurationHolderUtil.getString("property3");
      assertEquals("EN,DE,FR", val);
    } finally {
      f.deleteOnExit();
    }
  }
  /** Test.
   *
   * @throws SecurityException fail
   * @throws NoSuchFieldException fail
   * @throws IllegalArgumentException fail
   * @throws IllegalAccessException fail
   * @throws IOException fail
   * @throws ConfigurationException fail
   */
  @Test
  public void testGetDefaultValuesWithCommas()
      throws SecurityException, NoSuchFieldException, IllegalArgumentException,
          IllegalAccessException, IOException, ConfigurationException {
    // Make sure we handle comma in default values
    String val =
        ConfigurationHolderUtil.getString("intresources.preferredlanguage");
    assertEquals("en", val);
    // A little reflection magic just to avoid dumping a test value in
    // defaultvalues.properties file.
    Field field
        = ConfigurationHolderUtil.class.getDeclaredField("defaultValues");
    field.setAccessible(true);
    CompositeConfiguration defaultValues =
        (CompositeConfiguration) field.get(null);
    val = ConfigurationHolderUtil.getString("test.comma.in.defaultvalue");
    assertNull(val);
    File f = File.createTempFile("cesecore", "test");
    try {
      FileWriter fw = new FileWriter(f);
      fw.write("test.comma.in.defaultvalue=EN,DE,FR\n");
      fw.close();
      defaultValues.addConfiguration(new PropertiesConfiguration(f));
      val = ConfigurationHolderUtil.getString("test.comma.in.defaultvalue");
      assertEquals("EN,DE,FR", val);
    } finally {
      f.deleteOnExit();
    }
  }
}
