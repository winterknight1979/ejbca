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
package org.cesecore.audit.audit;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Interface for how to export audit log data.
 *
 * Users of this interface is expected to call:
 * 1. setOutputStream after creation
 * 2. For each added object:
 * 2a. writeStartObject()
 * 2b. zero or more writeLongField and/or writeStringField
 * 2c. writeEndObject()
 * 3. close()
 *
 * @version $Id: AuditExporter.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public interface AuditExporter {

    /**
     * Set the OutputStream.
     * @param outputStream OS
     * @throws IOException On IO fail
     */
    void setOutputStream(OutputStream outputStream) throws IOException;
    /**
     * Start labelling.
     * @param label Label
     * @throws IOException On IO error
     */
    void startObjectLabel(String label) throws IOException;
    /**
     * End labelling.
     * @throws IOException On IO error
     */
    void endObjectLabel() throws IOException;
    /**
     * Start writing the object.
     * @throws IOException On IO error
     */
    void writeStartObject() throws IOException;
    /**
     * Write an integer property.
     * @param key Property key
     * @param value Value
     * @throws IOException On IO error
     */
    void writeField(String key, long value) throws IOException;
    /**
     * Write a string property.
     * @param key Property key
     * @param value value
     * @throws IOException On IO error
     */
    void writeField(String key, String value) throws IOException;
    /**
     * Finish writing the object.
     * @throws IOException On IO error
     */
    void writeEndObject() throws IOException;
    /**
     * Close the log.
     * @throws IOException On IO error.
     */
    void close() throws IOException;
}
