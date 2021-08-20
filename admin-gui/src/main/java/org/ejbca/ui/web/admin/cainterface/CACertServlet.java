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

package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringUtil;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet used to distribute CA certificates <br>
 * cacert - returns ca certificate in PEM-format nscacert - returns ca
 * certificate for Firefox iecacert - returns ca certificate for Internet
 * Explorer
 *
 * <p>cacert, nscacert and iecacert also takes optional parameter level=&lt;int
 * 1,2,...&gt;, where the level is which ca certificate in a hierachy should be
 * returned. 0=root (default), 1=sub to root etc.
 *
 * @version $Id: CACertServlet.java 34154 2019-12-23 13:38:17Z samuellb $
 */
public class CACertServlet extends BaseAdminServlet {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(CACertServlet.class);

/** Param. */
  private static final String COMMAND_PROPERTY_NAME = "cmd";
  /** Param. */
  private static final String COMMAND_NSCACERT = "nscacert";
  /** Param. */
  private static final String COMMAND_IECACERT = "iecacert";
  /** Param. */
  private static final String COMMAND_CACERT = "cacert";
  /** Param. */
  private static final String COMMAND_JKSTRUSTSTORE = "jkscert";

/** Param. */
  private static final String LEVEL_PROPERTY = "level";
  /** Param. */
  private static final String ISSUER_PROPERTY = "issuer";
  /** Param. */
  private static final String JKSPASSWORD_PROPERTY = "password";
/** Param. */
  @EJB private SignSessionLocal signSession;

  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
    if (signSession == null) {
      LOG.error("Local EJB injection failed.");
    }
  }

  @Override
  public void doPost(
      final HttpServletRequest req, final HttpServletResponse res)
      throws IOException, ServletException {
    LOG.trace(">doPost()");
    doGet(req, res);
    LOG.trace("<doPost()");
  }

  @Override
  public void doGet(final HttpServletRequest req, final HttpServletResponse res)
      throws java.io.IOException, ServletException {
    LOG.trace(">doGet()");
    try {
      authenticateAdmin(req, res, AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
    } catch (AdminWebAuthenticationException authExc) {
      // TODO: localize this.
      LOG.info("Authentication failed", authExc);
      res.sendError(HttpServletResponse.SC_FORBIDDEN, "Authentication failed");
      return;
    }
    RequestHelper.setDefaultCharacterEncoding(req);

    // HttpServetRequets.getParameter URLDecodes the value for you
    // No need to do it manually, that will cause problems with + characters
    String issuerdn = req.getParameter(ISSUER_PROPERTY);
    issuerdn = CertTools.stringToBCDNString(issuerdn);

    String command;
    // Keep this for logging.
    LOG.debug("Got request from " + req.getRemoteAddr());
    command = req.getParameter(COMMAND_PROPERTY_NAME);
    if (command == null) {
      command = "";
    }
    if ((command.equalsIgnoreCase(COMMAND_NSCACERT)
            || command.equalsIgnoreCase(COMMAND_IECACERT)
            || command.equalsIgnoreCase(COMMAND_JKSTRUSTSTORE)
            || command.equalsIgnoreCase(COMMAND_CACERT))
        && issuerdn != null) {
      String lev = req.getParameter(LEVEL_PROPERTY);
      int level = 0;
      if (lev != null) {
        level = Integer.parseInt(lev);
      }
      // Root CA is level 0, next below root level 1 etc etc
      try {
        Certificate[] chain =
            signSession
                .getCertificateChain(issuerdn.hashCode())
                .toArray(new Certificate[0]);

        // chain.length-1 is last cert in chain (root CA)
        if ((chain.length - 1 - level) < 0) {
          PrintStream ps = new PrintStream(res.getOutputStream());
          ps.println("No CA certificate of level " + level + "exist.");
          LOG.error("No CA certificate of level " + level + "exist.");
          return;
        }
        Certificate cacert = chain[level];
        byte[] enccert = cacert.getEncoded();
        // Se if we can name the file as the CAs CN, if that does not exist try
        // serialnumber, and if that does not exist, use the full O
        // and if that does not exist, use the fixed string
        // CertificateAuthority.
        String filename =
            RequestHelper.getFileNameFromCertNoEnding(
                cacert, "CertificateAuthority");
        // We must remove cache headers for IE
        ServletUtils.removeCacheHeaders(res);
        if (command.equalsIgnoreCase(COMMAND_NSCACERT)) {
          res.setContentType("application/x-x509-ca-cert");
          res.setContentLength(enccert.length);
          res.getOutputStream().write(enccert);
          LOG.debug("Sent CA cert to NS client, len=" + enccert.length + ".");
        } else if (command.equalsIgnoreCase(COMMAND_IECACERT)) {
          String ending = ".cacert.crt";
          if (cacert instanceof CardVerifiableCertificate) {
            ending = ".cvcert";
          }
          res.setHeader(
              "Content-disposition",
              "attachment; filename=\""
                  + StringUtil.stripFilename(filename + ending)
                  + "\"");
          res.setContentType("application/octet-stream");
          res.setContentLength(enccert.length);
          res.getOutputStream().write(enccert);
          LOG.debug("Sent CA cert to IE client, len=" + enccert.length + ".");
        } else if (command.equalsIgnoreCase(COMMAND_CACERT)) {
          String out = CertTools.getPemFromCertificate(cacert);
          res.setHeader(
              "Content-disposition",
              "attachment; filename=\""
                  + StringUtil.stripFilename(filename + ".cacert.pem")
                  + "\"");
          res.setContentType("application/octet-stream");
          res.setContentLength(out.length());
          res.getOutputStream().write(out.getBytes());
          LOG.debug("Sent CA cert to client, len=" + out.length() + ".");
        } else if (command.equalsIgnoreCase(COMMAND_JKSTRUSTSTORE)) {
          String jksPassword = req.getParameter(JKSPASSWORD_PROPERTY).trim();
          final int passwordRequiredLength = 6;
          if (jksPassword != null
              && jksPassword.length() >= passwordRequiredLength) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, jksPassword.toCharArray());
            ks.setCertificateEntry(filename, cacert);
            res.setHeader(
                "Content-disposition",
                "attachment; filename=\""
                    + StringUtil.stripFilename(filename + ".cacert.jks")
                    + "\"");
            res.setContentType("application/octet-stream");
            ks.store(res.getOutputStream(), jksPassword.toCharArray());
          } else {
            res.setContentType("text/plain");
            res.getOutputStream()
                .println(
                    COMMAND_JKSTRUSTSTORE
                        + " requires "
                        + JKSPASSWORD_PROPERTY
                        + " with a minimum of "
                        + passwordRequiredLength
                        + " chars to be set");
            return;
          }
        } else {
          res.setContentType("text/plain");
          res.getOutputStream()
              .println(
                  "Commands="
                      + COMMAND_NSCACERT
                      + " || "
                      + COMMAND_IECACERT
                      + " || "
                      + COMMAND_CACERT
                      + " || "
                      + COMMAND_JKSTRUSTSTORE);
          return;
        }
      } catch (Exception e) {
        LOG.error("Error getting CA certificates: ", e);
        res.sendError(
            HttpServletResponse.SC_NOT_FOUND, "Error getting CA certificates.");
        return;
      }
    } else {
      res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad Request format");
      return;
    }
  } // doGet
}
