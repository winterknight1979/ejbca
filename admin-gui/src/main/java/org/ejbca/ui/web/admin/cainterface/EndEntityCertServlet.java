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
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet used to distribute End Entity certificates through the "View
 * Certificate" jsp page. Checks that the administrator is authorized to view
 * the user before sending the certificate<br>
 * cert - returns certificate in PEM-format nscert - returns certificate for
 * Firefox iecert - returns certificate for Internet Explorer
 *
 * <p>cert, nscert and iecert also takes parameters issuer and certificate sn
 * were issuer is the DN of issuer and certificate serienumber is in hex format.
 *
 * @version $Id: EndEntityCertServlet.java 34154 2019-12-23 13:38:17Z samuellb $
 */
public class EndEntityCertServlet extends BaseAdminServlet {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG =
      Logger.getLogger(EndEntityCertServlet.class);

  /** Param. */
  private static final String COMMAND_PROPERTY_NAME = "cmd";
  /** Param. */
  private static final String COMMAND_NSCERT = "nscert";
  /** Param. */
  private static final String COMMAND_IECERT = "iecert";
  /** Param. */
  private static final String COMMAND_CERT = "cert";

  /** Param. */
  private static final String ISSUER_PROPERTY = "issuer";
  /** Param. */
  private static final String CERTIFICATEDN_PROPERTY = "certificatesn";

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
      throws IOException, ServletException {
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
    String issuerdn = req.getParameter(ISSUER_PROPERTY);
    String certificatesn = req.getParameter(CERTIFICATEDN_PROPERTY);

    String command;
    // Keep this for logging.
    LOG.debug("Got request from " + req.getRemoteAddr());
    command = req.getParameter(COMMAND_PROPERTY_NAME);
    if (command == null) {
      command = "";
    }
    if ((command.equalsIgnoreCase(COMMAND_NSCERT)
            || command.equalsIgnoreCase(COMMAND_IECERT)
            || command.equalsIgnoreCase(COMMAND_CERT))
        && issuerdn != null
        && certificatesn != null) {

      BigInteger certsn = new BigInteger(certificatesn, 16);

      // Fetch the certificate and at the same time check that the user is
      // authorized to it.

      try {
        final RAInterfaceBean raBean = getRaBean(req);
        raBean.loadCertificates(certsn, issuerdn);
        CertificateView certview = raBean.getCertificate(0);

        Certificate cert = certview.getCertificate();
        byte[] enccert = cert.getEncoded();
        // We must remove cache headers for IE
        ServletUtils.removeCacheHeaders(res);
        if (command.equalsIgnoreCase(COMMAND_NSCERT)) {
          res.setContentType("application/x-x509-ca-cert");
          res.setContentLength(enccert.length);
          res.getOutputStream().write(enccert);
          LOG.debug("Sent CA cert to NS client, len=" + enccert.length + ".");
        } else if (command.equalsIgnoreCase(COMMAND_IECERT)) {
          res.setHeader(
              "Content-disposition",
              "attachment; filename="
                  + URLEncoder.encode(certview.getUsername(), "UTF-8")
                  + ".crt");
          res.setContentType("application/octet-stream");
          res.setContentLength(enccert.length);
          res.getOutputStream().write(enccert);
          LOG.debug("Sent CA cert to IE client, len=" + enccert.length + ".");
        } else if (command.equalsIgnoreCase(COMMAND_CERT)) {
          String out = CertTools.getPemFromCertificate(cert);
          res.setHeader(
              "Content-disposition",
              "attachment; filename="
                  + URLEncoder.encode(certview.getUsername(), "UTF-8")
                  + ".pem");
          res.setContentType("application/octet-stream");
          res.setContentLength(out.length());
          res.getOutputStream().write(out.getBytes());
          LOG.debug("Sent CA cert to client, len=" + out.length() + ".");
        } else {
          res.setContentType("text/plain");
          res.getOutputStream()
              .println(
                  "Commands="
                      + COMMAND_NSCERT
                      + " || "
                      + COMMAND_IECERT
                      + " || "
                      + COMMAND_CERT);
          return;
        }
      } catch (Exception e) {
        LOG.error("Error getting certificates: ", e);
        res.sendError(
            HttpServletResponse.SC_NOT_FOUND, "Error getting certificates.");
        return;
      }
    } else {
      res.setContentType("text/plain");
      res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad Request format");
      return;
    }
  } // doGet
}
