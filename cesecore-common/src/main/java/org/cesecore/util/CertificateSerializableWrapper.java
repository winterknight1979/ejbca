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

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import org.cesecore.certificates.certificate.CertificateWrapper;

/**
 * Wrapper class for transmitting certificates over remote EJB. This wrapper is
 * needed because Java will always deserialize Certificate objects using the
 * first security provider configured on the system. That does not work with
 * Certificates that use other signature algorithms than the ones that are built
 * into Java.
 *
 * <p>This class encodes and decodes the Certificate objects lazily only when
 * serializing or deserializing. So it should have a minimal performance impact.
 *
 * <p>This implementation shouldn't be used directly, and is package-internal.
 * You can create an instance of this class through {@link
 * org.cesecore.util.EJBUtil}.
 *
 * @version $Id: CertificateSerializableWrapper.java 23173 2016-04-12 14:54:52Z
 *     samuellb $
 */
final class CertificateSerializableWrapper
    implements CertificateWrapper, Serializable {

  private static final long serialVersionUID = 1L;

  /** Butes. */
  private byte[] certificateBytes;
  /** Crt. */
  private transient Certificate certificate = null;

  /**
   * Constructor is internal. Please use {@link
   * org.cesecore.util.EJBUtil#wrap(Certificate)} to create a wrapper.
   *
   * @param aCertificate Certificate, non-null.
   */
  CertificateSerializableWrapper(final Certificate aCertificate) {
    if (aCertificate == null) {
      throw new IllegalStateException("Can't wrap null certificate");
    }
    this.certificate = aCertificate;
    this.certificateBytes = null;
  }

  @Override
  public Certificate getCertificate() {
    if (certificate == null && certificateBytes != null) {
      // Lazy restore in case of deserialization
      try {
        certificate =
            CertTools.getCertfromByteArray(certificateBytes, Certificate.class);
      } catch (CertificateParsingException e) {
        throw new IllegalStateException(e);
      }
    }
    return certificate;
  }

  private void writeObject(final ObjectOutputStream stream) throws IOException {
    // Lazy encode before serialization
    if (certificateBytes == null) {
      try {
        certificateBytes = certificate.getEncoded();
      } catch (CertificateEncodingException e) {
        throw new IllegalStateException(e);
      }
    }
    stream.defaultWriteObject();
  }
}
