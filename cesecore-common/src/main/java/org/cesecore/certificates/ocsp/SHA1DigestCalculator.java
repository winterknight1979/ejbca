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
package org.cesecore.certificates.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.DigestCalculator;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;

/**
 * @version $Id: SHA1DigestCalculator.java 18437 2014-02-03 12:46:08Z
 *     mikekushner $
 */
public class SHA1DigestCalculator implements DigestCalculator {
    /** OS. */
  private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
  /** Digest. */
  private MessageDigest digest;
 /**
  * @param adigest digest
  */
  public SHA1DigestCalculator(final MessageDigest adigest) {
    this.digest = adigest;
  }

  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return RespID.HASH_SHA1;
  }

  @Override
  public OutputStream getOutputStream() {
    return bOut;
  }


  @Override
  public byte[] getDigest() {
    byte[] bytes = digest.digest(bOut.toByteArray());

    bOut.reset();

    return bytes;
  }

  /**
   * @return instance
   */
  public static SHA1DigestCalculator buildSha1Instance() {
    try {
      return new SHA1DigestCalculator(MessageDigest.getInstance("SHA1"));
    } catch (NoSuchAlgorithmException e) {
      throw new OcspFailureException(e);
    }
  }
}
