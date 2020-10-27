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
package org.ejbca.core.model.ca.publisher;

import java.io.File;
import java.security.cert.Certificate;

/**
 * Mocked version of CertificateSamplerCustomPublisher to be able to easily test
 * if the writeCertificate method was called.
 *
 * @version $Id: MockedCertificateSamplerCustomPublisher.java 22121 2015-10-29
 *     13:49:30Z mikekushner $
 */
public class MockedCertificateSamplerCustomPublisher
    extends CertificateSamplerCustomPublisher {
    /** Param. */
    private boolean writeCertificateCalled;

  /** Constructor. */
  public MockedCertificateSamplerCustomPublisher() {
    super();
  }

  @Override
  protected void writeCertificate(
      final Certificate cert,
      final File outFolder,
      final String prefix,
      final String suffix)
      throws PublisherException {
    writeCertificateCalled = true;
  }

  /**
   * @return bool
   */
  public boolean isWriteCertificateCalled() {
    return writeCertificateCalled;
  }

  /** Reset. */
  public void reset() {
    writeCertificateCalled = false;
  }
}
