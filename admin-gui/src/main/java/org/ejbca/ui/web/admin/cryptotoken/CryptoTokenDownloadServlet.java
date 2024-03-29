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
package org.ejbca.ui.web.admin.cryptotoken;

import java.io.IOException;
import java.security.PublicKey;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.StringUtil;
import org.ejbca.ui.web.admin.cainterface.BaseAdminServlet;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;

/**
 * Servlet for download of CryptoToken related files, such as the the public key
 * as PEM for a key pair.
 *
 * @version $Id: CryptoTokenDownloadServlet.java 34154 2019-12-23 13:38:17Z
 *     samuellb $
 */
public class CryptoTokenDownloadServlet extends BaseAdminServlet {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG =
      Logger.getLogger(CryptoTokenDownloadServlet.class);

  /** Param. */
  @EJB private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;

  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }

  /** Handles HTTP POST the same way HTTP GET is handled. */
  @Override
  public void doPost(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    doGet(request, response);
  }

  /** Handles HTTP GET. */
  @Override
  public void doGet(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    LOG.trace(">doGet()");
    final AuthenticationToken admin;
    try {
      admin =
          authenticateAdmin(
              request, response, CryptoTokenRules.VIEW.resource());
    } catch (AdminWebAuthenticationException authExc) {
      // TODO: localize this.
      LOG.info("Authentication failed", authExc);
      response.sendError(
          HttpServletResponse.SC_FORBIDDEN, "Authentication failed");
      return;
    }
    final String cryptoTokenIdParam = request.getParameter("cryptoTokenId");
    final int cryptoTokenId = Integer.parseInt(cryptoTokenIdParam);
    final String aliasParam = request.getParameter("alias");
    try {
      final PublicKey publicKey =
          cryptoTokenManagementSession
              .getPublicKey(admin, cryptoTokenId, aliasParam)
              .getPublicKey();
      response.setContentType("application/octet-stream");
      response.setHeader(
          "Content-disposition",
          " attachment; filename=\""
              + StringUtil.stripFilename(aliasParam + ".pem")
              + "\"");
      response.getOutputStream().write(KeyUtil.getAsPem(publicKey).getBytes());
      response.flushBuffer();
    } catch (CryptoTokenOfflineException e) {
      throw new ServletException(e);
    } catch (AuthorizationDeniedException e) {
      throw new ServletException(e);
    }
    LOG.trace("<doGet()");
  }
}
