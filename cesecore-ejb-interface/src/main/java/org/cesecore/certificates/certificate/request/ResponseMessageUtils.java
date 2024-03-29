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

package org.cesecore.certificates.certificate.request;

import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Random;
import org.apache.log4j.Logger;
import org.cesecore.util.Base64Util;

/**
 * @version $Id: ResponseMessageUtils.java 26080 2017-06-26 17:32:09Z anatom $
 */
public abstract class ResponseMessageUtils {

    /**Logger.
     */
  private static final Logger LOG =
      Logger.getLogger(ResponseMessageUtils.class);

  /**
   * @param responseClass Class
   * @param req Request
   * @param certs Certificates
   * @param signPriv Private key
   * @param provider Provider
   * @return Message
   */
  public static CertificateResponseMessage createResponseMessage(
      final Class<? extends ResponseMessage> responseClass,
      final RequestMessage req,
      final Collection<Certificate> certs,
      final PrivateKey signPriv,
      final String provider) {
    CertificateResponseMessage ret = null;
    // Create the response message and set all required fields
    try {
      ret =
          (CertificateResponseMessage)
              responseClass.getConstructor().newInstance();
    } catch (InstantiationException
        | NoSuchMethodException
        | InvocationTargetException e) {
      // TODO : do something with these exceptions
      LOG.error("Error creating response message", e);
      return null;
    } catch (IllegalAccessException e) {
      LOG.error("Error creating response message", e);
      return null;
    }
    if (ret.requireSignKeyInfo()) {
      ret.setSignKeyInfo(certs, signPriv, provider);
    }
    if (req.getSenderNonce() != null) {
      ret.setRecipientNonce(req.getSenderNonce());
    }
    if (req.getTransactionId() != null) {
      ret.setTransactionId(req.getTransactionId());
    }
    // Sender nonce is a random number
    byte[] senderNonce = new byte[16];
    Random randomSource = new Random();
    randomSource.nextBytes(senderNonce);
    ret.setSenderNonce(new String(Base64Util.encode(senderNonce)));
    // If we have a specified request key info, use it in the reply
    if (req.getRequestKeyInfo() != null) {
      ret.setRecipientKeyInfo(req.getRequestKeyInfo());
    }
    // Which digest algorithm to use to create the response, if applicable
    ret.setPreferredDigestAlg(req.getPreferredDigestAlg());
    // Include the CA cert or not in the response, if applicable for the
    // response type
    ret.setIncludeCACert(req.includeCACert());
    // Hint to the response which request type it is in response to
    ret.setRequestType(req.getRequestType());
    ret.setRequestId(req.getRequestId());
    // If there is some protection parameters, or other params, we need to lift
    // over from the request message, the request and response knows about it
    ret.setProtectionParamsFromRequest(req);
    return ret;
  }
}
