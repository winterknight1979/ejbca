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

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;

/**
 * Data carrier that wraps the contents of an OCSPResp, since OCSPResp and many
 * of its members aren't serializable.
 *
 * @version $Id: OcspResponseInformation.java 25974 2017-06-09 15:51:49Z anatom
 *     $
 */
public class OcspResponseInformation implements Serializable {

  private static final long serialVersionUID = -4177593916232755218L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(OcspResponseInformation.class);
  /** Response.*/
  private final byte[] ocspResponse;
  /** age. */
  private final long maxAge;
  /** boolean. */
  private boolean addCacheHeaders = true;
  /** boolean. */
  private boolean explicitNoCache = false;
  /** Update. */
  private Long nextUpdate = null;
  /** Update. */
  private Long thisUpdate = null;
  /** Header. */
  private String responseHeader = null;
  /** Cert. */
  private X509Certificate signerCert = null;

  /**
   * @param anOcspResponse Resp
   * @param theMaxAge Age
   * @param aSignerCert Cert
   * @throws OCSPException Fail
   */
  public OcspResponseInformation(
      final OCSPResp anOcspResponse,
      final long theMaxAge,
      final X509Certificate aSignerCert)
      throws OCSPException {
    try {
      this.ocspResponse = anOcspResponse.getEncoded();
    } catch (IOException e) {
      throw new IllegalStateException(
          "Unexpected IOException caught when encoding ocsp response.", e);
    }
    this.maxAge = theMaxAge;
    this.signerCert = aSignerCert;
    /*
     * This may seem like a somewhat odd place to perform the
     * below operations (instead of in the end servlet which demanded
     * this object), but BouncyCastle (up to 1.47) is  a bit shy
     *  about making their classes serializable. This means that
     * OCSPResp can't be transmitted, neither can many of the objects
     * it contains such as SingleResp. Luckily we only need
     * these classes for the diagnostic operations performed below,
     * so we can sum up the result in the boolean member
     * addCacheHeaders.  If BC choose to change their policy, the
     *  below code can med moved to a more logical location.
     *  -mikek
     */
    if (anOcspResponse.getResponseObject() == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Will not add cache headers for response to bad request.");
      }
      addCacheHeaders = false;
    } else {
      final BasicOCSPResp basicOCSPResp =
          (BasicOCSPResp) anOcspResponse.getResponseObject();
      final SingleResp[] singleRespones = basicOCSPResp.getResponses();
      if (singleRespones.length != 1) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Will not add RFC 5019 cache headers: reponse contains multiple"
                  + " embedded responses.");
        }
        addCacheHeaders = false;
      } else if (singleRespones[0].getNextUpdate() == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Will not add RFC 5019 cache headers: nextUpdate isn't set.");
        }
        addCacheHeaders = false;
      } else if (basicOCSPResp.hasExtensions()
          && basicOCSPResp.getExtension(
                  OCSPObjectIdentifiers.id_pkix_ocsp_nonce)
              != null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Will not add RFC 5019 cache headers: response contains a"
                  + " nonce.");
        }
        addCacheHeaders = false;
      } else {
        nextUpdate = singleRespones[0].getNextUpdate().getTime();
        thisUpdate = singleRespones[0].getThisUpdate().getTime();
        try {
          responseHeader =
              new String(
                  Hex.encode(
                      MessageDigest.getInstance(
                              "SHA-1", BouncyCastleProvider.PROVIDER_NAME)
                          .digest(this.ocspResponse)));
        } catch (NoSuchProviderException e) {
          throw new OcspFailureException(
              "Bouncycastle was not available as a provider", e);
        } catch (NoSuchAlgorithmException e) {
          throw new OcspFailureException(
              "SHA-1 was not an available algorithm for MessageDigester", e);
        }
      }
      if (addCacheHeaders
          && singleRespones[0].getCertStatus() instanceof UnknownStatus) {
        explicitNoCache = true;
      }
    }
  }

  /**
   * @return response
   */
  public byte[] getOcspResponse() {
    return ocspResponse;
  }

  /**
   * @return duration in milliseconds how long the reponse should be cacheable
   */
  public long getMaxAge() {
    return maxAge;
  }

  /**
   * @return bool
   */
  public boolean shouldAddCacheHeaders() {
    return addCacheHeaders;
  }

  /** @return Date.getTime() long value for nextUpdate time */
  public long getNextUpdate() {
    return nextUpdate;
  }

  /** @return Date.getTime() long value for thisUpdate time */
  public long getThisUpdate() {
    return thisUpdate;
  }

  /**
   * @return header
   */
  public String getResponseHeader() {
    return responseHeader;
  }

  /**
   * @return true if we explicitly should state that the response should not be
   *     cached.
   */
  public boolean isExplicitNoCache() {
    return explicitNoCache;
  }

  /**
   * @return Cert
   */
  public X509Certificate getSignerCert() {
    return signerCert;
  }
}
