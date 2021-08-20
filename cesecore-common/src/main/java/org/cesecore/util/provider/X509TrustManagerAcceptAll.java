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
package org.cesecore.util.provider;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;

/**
 * This trust manager may be used used by a client that does not bother to
 * verify the TLS certificate chain of the server. Could be us used when you are
 * fetching things from the server that are signed by the server (like
 * certificates). The class must not be used on the server side.
 *
 * @version $Id: X509TrustManagerAcceptAll.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class X509TrustManagerAcceptAll implements X509TrustManager {
/** Logger. */
  private static final Logger LOG =
      Logger.getLogger(X509TrustManagerAcceptAll.class);

  /* (non-Javadoc)
   * @see
   * javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[],
   * java.lang.String)
   */
  @Override
  public void checkClientTrusted(
          final X509Certificate[] chain, final String authType)
      throws CertificateException {
    // do nothing
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "checkClientTrusted: SubjectDN: " + CertTools.getSubjectDN(chain[0]));
      LOG.debug(
          "checkClientTrusted: IssuerDN:  " + CertTools.getIssuerDN(chain[0]));
    }
  }

  /* (non-Javadoc)
   * @see
   * javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[],
   * java.lang.String)
   */
  @Override
  public void checkServerTrusted(
          final X509Certificate[] chain, final String authType)
      throws CertificateException {
    // do nothing
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "checkServerTrusted: SubjectDN: " + CertTools.getSubjectDN(chain[0]));
      LOG.debug(
          "checkServerTrusted: IssuerDN:  " + CertTools.getIssuerDN(chain[0]));
    }
  }

  /* (non-Javadoc)
   * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
   */
  @Override
  public X509Certificate[] getAcceptedIssuers() {
    // only called from server side
    if (LOG.isDebugEnabled()) {
      LOG.debug(">getAcceptedIssuers");
    }
    return null;
  }
}
