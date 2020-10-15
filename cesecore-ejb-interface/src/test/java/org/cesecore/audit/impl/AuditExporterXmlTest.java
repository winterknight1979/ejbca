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

  private static final Logger log =
      Logger.getLogger(AuditExporterXmlTest.class);

  @Test
  public void testExportAndParse() throws IOException {
    final String KEY1 = "key1";
    final String KEY2 = "key2";
    final Long VALUE1 = Long.MIN_VALUE;
    final String VALUE2 = "ĞİŞğışÅÄÖåäözxcvbnm;<>&!;&lt;&amp;";
    final AuditExporter auditExporter = new AuditExporterXml();
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    auditExporter.setOutputStream(baos);
    auditExporter.writeStartObject();
    auditExporter.writeField(KEY1, VALUE1);
    auditExporter.writeField(KEY2, VALUE2);
    auditExporter.writeEndObject();
    auditExporter.close();
    final String result = baos.toString("UTF8");
    log.info(result);
    // Verify that we can parse the "export"
    final LinkedHashMap<?, ?> parsed;
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new ByteArrayInputStream(
                result.getBytes(StandardCharsets.UTF_8)))) {
      parsed = (LinkedHashMap<?, ?>) decoder.readObject();
    }
    log.info(KEY1 + "=" + parsed.get(KEY1));
    Assert.assertEquals(VALUE1, parsed.get(KEY1));
    log.info(KEY2 + "=" + parsed.get(KEY2));
    Assert.assertEquals(VALUE2, parsed.get(KEY2));
  }
}
