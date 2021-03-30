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

package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.ejb.EJB;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.util.HTMLTools;

/**
 * Servlet implementing server side of the Certificate Store. For a detailed
 * description see RFC 4387.
 *
 * @version $Id: CertStoreServlet.java 24974 2017-01-04 14:48:17Z anatom $
 */
public class CertStoreServlet extends StoreServletBase {

  private static final long serialVersionUID = 1L;

  /** Param. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;

  /** Param. */
  private static final Logger LOG = Logger.getLogger(CertStoreServlet.class);

  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
  }

  @Override
  public void iHash(
      final String iHash,
      final HttpServletResponse resp,
      final HttpServletRequest req)
      throws IOException, ServletException {
    returnCerts(
        this.certCache.findLatestByIssuerDN(HashID.getFromB64(iHash)),
        resp,
        iHash);
    return;
  }

  @Override
  public void sKIDHash(
      final String sKIDHash,
      final HttpServletResponse resp,
      final HttpServletRequest req,
      final String name)
      throws IOException, ServletException {
    returnCert(
        this.certCache.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash)),
        resp,
        name);
  }

  @Override
  public void sKIDHash(
      final String sKIDHash,
      final HttpServletResponse resp,
      final HttpServletRequest req)
      throws IOException, ServletException {
    sKIDHash(sKIDHash, resp, req, sKIDHash);
  }

  @Override
  public void sHash(
      final String sHash,
      final HttpServletResponse resp,
      final HttpServletRequest req)
      throws IOException, ServletException {
    final X509Certificate cert =
        this.certCache.findLatestBySubjectDN(HashID.getFromB64(sHash));
    returnCert(cert, resp, sHash);
  }

  @Override
  public void printInfo(
      final X509Certificate cert,
      final String indent,
      final PrintWriter pw,
      final String url) {
    // Important to escape output that have an even small chance of coming from
    // untrusted source
    pw.println(
        indent
            + HTMLTools.htmlescape(cert.getSubjectX500Principal().toString()));
    pw.println(
        indent
            + " "
            + RFC4387URL.sHash.getRef(url, HashID.getFromSubjectDN(cert)));
    pw.println(
        indent
            + " "
            + RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
    pw.println(
        indent
            + " "
            + RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
  }

  @Override
  public String getTitle() {
    return "CA certificates";
  }

  private void returnCert(
      final X509Certificate cert,
      final HttpServletResponse resp,
      final String name)
      throws IOException, ServletException {
    if (cert == null) {
      resp.sendError(
          HttpServletResponse.SC_NO_CONTENT,
          "No certificate with hash: " + HTMLTools.htmlescape(name));
      return;
    }
    final byte[] encoded;
    try {
      encoded = cert.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new ServletException(e);
    }
    resp.setContentType("application/pkix-cert");
    resp.setHeader(
        "Content-disposition",
        "attachment; filename=\""
            + StringTools.stripFilename(name + ".der")
            + "\"");
    resp.setContentLength(encoded.length);
    resp.getOutputStream().write(encoded);
  }

  private void returnCerts(
      final X509Certificate[] certs,
      final HttpServletResponse resp,
      final String name)
      throws IOException, ServletException {
    if (certs == null) {
      resp.sendError(
          HttpServletResponse.SC_NO_CONTENT,
          "No certificates with issuer hash DN: " + HTMLTools.htmlescape(name));
      return;
    }
    final Multipart mp = new MimeMultipart(); // mixed is default
    try {
      resp.setContentType(mp.getContentType());
      for (int i = 0; i < certs.length; i++) {
        final String filename = "cert" + name + '-' + i + ".der";
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Returning certificate with issuerDN '"
                  + CertTools.getIssuerDN(certs[i])
                  + "' and subjectDN '"
                  + CertTools.getSubjectDN(certs[i])
                  + "'. Filename="
                  + filename);
        }
        final InternetHeaders headers = new InternetHeaders();
        headers.addHeader("Content-type", "application/pkix-cert");
        headers.addHeader(
            "Content-disposition",
            "attachment; filename=\""
                + StringTools.stripFilename(filename)
                + "\"");
        mp.addBodyPart(new MimeBodyPart(headers, certs[i].getEncoded()));
      }
      if (LOG.isTraceEnabled()) {
        LOG.trace("content type: " + mp.getContentType());
      }
      mp.writeTo(resp.getOutputStream());
      resp.flushBuffer();
    } catch (CertificateEncodingException e) {
      throw new ServletException(e);
    } catch (MessagingException e) {
      throw new ServletException(e);
    }
  }
}
