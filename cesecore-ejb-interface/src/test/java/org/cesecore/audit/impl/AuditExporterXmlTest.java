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
package org.cesecore.audit.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.util.SecureXMLDecoder;
import org.junit.Assert;
import org.junit.Test;

/**
 * Test XML exporter implementation.
 *
 * @version $Id: AuditExporterXmlTest.java 34163 2020-01-02 15:00:17Z samuellb $
 */
public class AuditExporterXmlTest {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AuditExporterXmlTest.class);
  /**
   * Test.
   * @throws IOException fail
   */
  @Test
  public void testExportAndParse() throws IOException {
    final String key1 = "key1";
    final String key2 = "key2";
    final Long value1 = Long.MIN_VALUE;
    final String value2 = "ĞİŞğışÅÄÖåäözxcvbnm;<>&!;&lt;&amp;";
    final AuditExporter auditExporter = new AuditExporterXml();
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    auditExporter.setOutputStream(baos);
    auditExporter.writeStartObject();
    auditExporter.writeField(key1, value1);
    auditExporter.writeField(key2, value2);
    auditExporter.writeEndObject();
    auditExporter.close();
    final String result = baos.toString("UTF8");
    LOG.info(result);
    // Verify that we can parse the "export"
    final LinkedHashMap<?, ?> parsed;
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new ByteArrayInputStream(
                result.getBytes(StandardCharsets.UTF_8)))) {
      parsed = (LinkedHashMap<?, ?>) decoder.readObject();
    }
    LOG.info(key1 + "=" + parsed.get(key1));
    Assert.assertEquals(value1, parsed.get(key1));
    LOG.info(key2 + "=" + parsed.get(key2));
    Assert.assertEquals(value2, parsed.get(key2));
  }
}
