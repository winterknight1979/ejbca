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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Can be used as Filter InputStream to prevent StringBuilder heap overflow
 * during deserialization.
 *
 * <p>Simple usage: ObjectInputStream objectInputStream = new
 * ObjectInputStream(new SecurityFilterInputStream(new
 * ByteArrayInputStream(someByteArray), 256)); objectInputStream.readObject();
 * //If serialized object have more than 256 bytes, SecurityException will be
 * thrown
 *
 * <p>see "SecurityFilterInputStreamTest" in the test code for more examples
 *
 * @version $Id: SecurityFilterInputStream.java 26057 2017-06-22 08:08:34Z
 *     anatom $
 */
public class SecurityFilterInputStream extends FilterInputStream {
 /** Length. */
  private long len = 0;
  /** max. */
  private long maxBytes = DEFAULT_MAX_BYTES;
 /** Default. */
  public static final long DEFAULT_MAX_BYTES = 0xFFFFF;

  /**
   * @param inputStream IS
   */
  public SecurityFilterInputStream(final InputStream inputStream) {
    super(inputStream);
  }

  /**
   * @param inputStream IS
   * @param amaxBytes Max
   */
  public SecurityFilterInputStream(
          final InputStream inputStream, final long amaxBytes) {
    super(inputStream);
    this.maxBytes = amaxBytes;
  }

  @Override
  public int read() throws IOException {
    int val = super.read();
    if (val != -1) {
      len++;
      checkLength();
    }
    return val;
  }

  @Override
  public int read(
          final byte[] b, final int off, final int alen) throws IOException {
    int val = super.read(b, off, alen);
    if (val > 0) {
      this.len += val;
      checkLength();
    }
    return val;
  }

  private void checkLength() throws IOException {
    if (len > maxBytes) {
      throw new SecurityException(
          "Security violation: attempt to deserialize too many bytes from"
              + " stream. Limit is "
              + maxBytes);
    }
  }

  /**
   * Set max bytes that can be read from serialized object.
   *
   * @return max bytes that can be read from serialized object.
   */
  public long getMaxBytes() {
    return maxBytes;
  }

  /**
   * Returns max bytes that can be read from serialized object.
   *
   * @param amaxBytes bytes that can be read from serialized object. Default:
   *     0xFFFFF
   */
  public void setMaxBytes(final long amaxBytes) {
    this.maxBytes = amaxBytes;
  }
}
