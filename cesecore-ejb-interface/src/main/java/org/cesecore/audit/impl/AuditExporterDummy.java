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

import java.io.IOException;
import java.io.OutputStream;
import org.cesecore.audit.audit.AuditExporter;

/**
 * Dummy implementation of AuditExporter that does nothing.
 *
 * @version $Id: AuditExporterDummy.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public class AuditExporterDummy implements AuditExporter {

  @Override
  public void close() throws IOException { // NOPMD: no-op
  }

  @Override
  public void setOutputStream(final OutputStream outputStream)
      throws IOException { // NOPMD: no-op
  }

  @Override
  public void writeEndObject() throws IOException { // NOPMD: no-op
  }

  @Override
  public void writeField(final String key, final long value)
      throws IOException { // NOPMD: no-op
  }

  @Override
  public void writeStartObject() throws IOException { // NOPMD: no-op
  }
  @Override
  public void writeField(final String key, final String value)
      throws IOException { // NOPMD: no-op
  }

  @Override
  public void startObjectLabel(final String label)
          throws IOException { // NOPMD: no-op
  }

  @Override
  public void endObjectLabel() throws IOException { // NOPMD: no-op
  }
}
