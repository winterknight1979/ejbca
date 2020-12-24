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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.ejb.EJB;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet implementing server side of the Certificate Management Protocols
 * (CMP).
 *
 * @version $Id: CmpServlet.java 28713 2018-04-13 14:35:47Z anatom $
 */
public class CmpServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CmpServlet.class);
  /** Resource. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /**
   * Only intended to check if Peer connected instance is authorized to CMP at
   * all.
   */
  private final AuthenticationToken raCmpAuthCheckToken =
      new AlwaysAllowLocalAuthenticationToken(
          new UsernamePrincipal("cmpProtocolAuthCheck"));

  /** Param. */
  private static final String DEFAULT_CMP_ALIAS = "cmp";

  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
  /** Param. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /**
   * Handles HTTP post.
   *
   * @param request java standard arg
   * @param response java standard arg
   * @throws IOException input/output error
   */
  @Override
  public void doPost(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">doPost()");
    }
    boolean isProtocolAuthorized =
        raMasterApiProxyBean.isAuthorizedNoLogging(
            raCmpAuthCheckToken, AccessRulesConstants.REGULAR_PEERPROTOCOL_CMP);
    try {
      if (!isProtocolAuthorized) {
        LOG.info("CMP Protocol not authorized for this Peer");
        response.sendError(
            HttpServletResponse.SC_FORBIDDEN,
            "CMP Protocol not authorized for this Peer");
        return;
      }
      final String alias = getAlias(request.getPathInfo());
      final int siz = 32;
      if (alias.length() > siz) {
        LOG.info("Unaccepted alias more than 32 characters.");
        response.sendError(
            HttpServletResponse.SC_BAD_REQUEST,
            "Unaccepted alias more than 32 characters.");
        return;
      }
      final ServletInputStream sin = request.getInputStream();
      // This small code snippet is inspired/copied by apache IO utils to Tomas
      // Gustavsson...
      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      final int len = 1024;
      final byte[] buf = new byte[len];
      int n = 0;
      int bytesRead = 0;
      while (-1 != (n = sin.read(buf))) {
        bytesRead += n;
        if (bytesRead > LimitLengthASN1Reader.MAX_REQUEST_SIZE) {
          throw new IllegalArgumentException(
              "Request is larger than "
                  + LimitLengthASN1Reader.MAX_REQUEST_SIZE
                  + " bytes.");
        }
        output.write(buf, 0, n);
      }
      service(output.toByteArray(), request.getRemoteAddr(), response, alias);
    } catch (IOException | RuntimeException e) {
      // TODO: localize.
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad request. ");
      LOG.info(INTRES.getLocalizedMessage("cmp.errornoasn1"), e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<doPost()");
    }
  }

  /**
   * Handles HTTP get.
   *
   * @param request java standard arg
   * @param response java standard arg
   * @throws IOException input/output error
   */
  @Override
  public void doGet(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">doGet()");
    }
    LOG.info(
        "Received un-allowed method GET in CMP servlet: query string="
            + request.getQueryString());
    response.sendError(
        HttpServletResponse.SC_METHOD_NOT_ALLOWED, "You can only use POST!");
    if (LOG.isTraceEnabled()) {
      LOG.trace("<doGet()");
    }
  }

  private void service(
      final byte[] pkiMessageBytes,
      final String remoteAddr,
      final HttpServletResponse response,
      final String alias)
      throws IOException {
    try {
      LOG.info(
          INTRES.getLocalizedMessage("cmp.receivedmsg", remoteAddr, alias));
      final long startTime = System.currentTimeMillis();
      byte[] result = null;
      try {
        final AuthenticationToken authenticationToken =
            new AlwaysAllowLocalAuthenticationToken(
                new WebPrincipal("CmpServlet", remoteAddr));
        result =
            raMasterApiProxyBean.cmpDispatch(
                authenticationToken, pkiMessageBytes, alias);
      } catch (NoSuchAliasException e) {
        // The CMP alias does not exist
        response.sendError(
            HttpServletResponse.SC_NOT_FOUND,
            "Error in CmpServlet: No such alias");
        LOG.info(e.getMessage());
        return;
      }
      if (result == null) {
        // If resp is null, it means that the dispatcher failed to process the
        // message.
        response.sendError(
            HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
            INTRES.getLocalizedMessage("cmp.errornullresp"));
        return;
      }
      // Add no-cache headers as defined in
      // http://tools.ietf.org/html/draft-ietf-pkix-cmp-transport-protocols-14
      ServletUtils.addCacheHeaders(response);
      // Send back CMP response
      RequestHelper.sendBinaryBytes(
          result, response, "application/pkixcmp", null);
      final long endTime = System.currentTimeMillis();
      LOG.info(
          INTRES.getLocalizedMessage(
              "cmp.sentresponsemsg",
              remoteAddr,
              Long.valueOf(endTime - startTime)));
    } catch (IOException | RuntimeException e) {
      LOG.error("Error in CmpServlet:", e);
      response.sendError(
          HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in CmpServlet.");
    }
  }

  private String getAlias(final String pathInfo) {
    // PathInfo contains the alias used for CMP configuration.
    // The CMP URL for custom configuration looks like:
    // http://HOST:PORT/ejbca/publicweb/cmp/*
    // pathInfo contains what * is and should have the form "/<SOME IDENTIFYING
    // TEXT>". We extract the "SOME IDENTIFYING
    // TEXT" and that will be the CMP configuration alias.
    final String alias;
    if (pathInfo != null && pathInfo.length() > 1) {
      alias = pathInfo.substring(1);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Using CMP configuration alias: " + alias);
      }
    } else {
      alias = DEFAULT_CMP_ALIAS;
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "No CMP alias specified in the URL. Using the default alias: "
                + DEFAULT_CMP_ALIAS);
      }
    }
    return alias;
  }
}
