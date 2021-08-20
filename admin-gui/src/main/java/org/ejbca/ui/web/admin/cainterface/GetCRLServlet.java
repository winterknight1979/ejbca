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
import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringUtil;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet used to distribute CRLs.<br>
 * The servlet is called with method GET or POST and syntax <code>
 * command=&lt;command&gt;</code>.
 *
 * <p>The follwing commands are supported:<br>
 *
 * <ul>
 *   <li>crl - gets the latest CRL.
 * </ul>
 *
 * @version $Id: GetCRLServlet.java 34154 2019-12-23 13:38:17Z samuellb $
 */
public class GetCRLServlet extends BaseAdminServlet {

  private static final long serialVersionUID = 1L;
  /** Log. */
  private static final Logger LOG = Logger.getLogger(GetCRLServlet.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Param. */
  private static final String COMMAND_PROPERTY_NAME = "cmd";
  /** Param. */
  private static final String COMMAND_CRL = "crl";
  /** Param. */
  private static final String COMMAND_DELTACRL = "deltacrl";
  /** Param. */
  private static final String ISSUER_PROPERTY = "issuer";

  /** Param. */
  @EJB private CrlStoreSessionLocal crlStoreSession;

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
    String issuerdn = null;
    if (req.getParameter(ISSUER_PROPERTY) != null) {
      // HttpServetRequets.getParameter URLDecodes the value for you
      // No need to do it manually, that will cause problems with + characters
      issuerdn = req.getParameter(ISSUER_PROPERTY);
      issuerdn = CertTools.stringToBCDNString(issuerdn);
    }

    String command;
    // Keep this for logging.
    String remoteAddr = req.getRemoteAddr();
    command = req.getParameter(COMMAND_PROPERTY_NAME);
    if (command == null) {
      command = "";
    }
    if (command.equalsIgnoreCase(COMMAND_CRL) && issuerdn != null) {
      try {
        byte[] crl = crlStoreSession.getLastCRL(issuerdn, false);
        String basename = getBaseFileName(issuerdn);
        String filename = basename + ".crl";
        // We must remove cache headers for IE
        ServletUtils.removeCacheHeaders(res);
        res.setHeader(
            "Content-disposition",
            "attachment; filename=\""
                + StringUtil.stripFilename(filename)
                + "\"");
        res.setContentType("application/pkix-crl");
        res.setContentLength(crl.length);
        res.getOutputStream().write(crl);
        String iMsg =
            INTRES.getLocalizedMessage("certreq.sentlatestcrl", remoteAddr);
        LOG.info(iMsg);
      } catch (Exception e) {
        String errMsg =
            INTRES.getLocalizedMessage(
                "certreq.errorsendcrl", remoteAddr, e.getMessage());
        LOG.error(errMsg, e);
        res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
        return;
      }
    }
    if (command.equalsIgnoreCase(COMMAND_DELTACRL) && issuerdn != null) {
      try {
        byte[] crl = crlStoreSession.getLastCRL(issuerdn, true);
        String basename = getBaseFileName(issuerdn);
        String filename = basename + "_delta.crl";
        // We must remove cache headers for IE
        ServletUtils.removeCacheHeaders(res);
        res.setHeader(
            "Content-disposition",
            "attachment; filename=\""
                + StringUtil.stripFilename(filename)
                + "\"");
        res.setContentType("application/pkix-crl");
        res.setContentLength(crl.length);
        res.getOutputStream().write(crl);
        LOG.info("Sent latest delta CRL to client at " + remoteAddr);
      } catch (Exception e) {
        LOG.error("Error sending latest delta CRL to " + remoteAddr, e);
        res.sendError(
            HttpServletResponse.SC_NOT_FOUND,
            "Error getting latest delta CRL.");
        return;
      }
    }
  } // doGet

  /**
   * @param dn DN
   * @return base filename, without extension, with CN, or SN (of CN is null) or
   *     O, with spaces removed so name is compacted.
   */
  private String getBaseFileName(final String dn) {
    String dnpart = CertTools.getPartFromDN(dn, "CN");
    if (dnpart == null) {
      dnpart = CertTools.getPartFromDN(dn, "SN");
    }
    if (dnpart == null) {
      dnpart = CertTools.getPartFromDN(dn, "O");
    }
    String basename = dnpart.replaceAll("\\W", "");
    return basename;
  }
}
