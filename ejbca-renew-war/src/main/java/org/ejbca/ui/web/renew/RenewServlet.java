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

package org.ejbca.ui.web.renew;

import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.ejb.EJB;
import javax.ejb.ObjectNotFoundException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderUtil;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Servlet used for requesting browser certificate renewals.
 *
 * @version $Id: RenewServlet.java 22811 2016-02-15 16:48:23Z samuellb $
 */
public class RenewServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private static final Logger LOG = Logger.getLogger(RenewServlet.class);

  /** Submit button on the web page. */
  public static final String BUTTONRENEW = "buttonrenew";

  /** Param. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** Param. */
  @EJB private EndEntityAccessSessionLocal endEntityAccessSession;
  /** Param. */
  @EJB private EndEntityProfileSessionLocal endEntityProfileSession;
  /** Param. */
  @EJB private EndEntityManagementSessionLocal endEntityManagementSession;

  /**
   * Servlet init.
   *
   * @param config servlet configuration
   * @throws ServletException on error
   */
  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
    // Install BouncyCastle provider
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }

  /**
   * @param request Req
   * @param response Resp
   * @throws IOException Fail
   * @throws ServletException Fail
   */
  public void doRequest(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {

    AuthenticationToken admin =
        new AlwaysAllowLocalAuthenticationToken(
            new WebPrincipal("RenewServlet", request.getRemoteAddr()));

    // SSL client authentication
    Object o = request.getAttribute("javax.servlet.request.X509Certificate");
    if (o == null || !(o instanceof X509Certificate[])) {
      response.sendError(
          HttpServletResponse.SC_UNAUTHORIZED,
          "This servlet requires certificate authentication!");
      return;
    }
    X509Certificate certificate = ((X509Certificate[]) o)[0];
    request.setAttribute("certificate", certificate);
    boolean isrevoked =
        certificateStoreSession.isRevoked(
            certificate.getIssuerDN().getName(), certificate.getSerialNumber());
    if (isrevoked) {
      request.setAttribute(
          "errorMessage",
          "User certificate with serial number "
              + certificate.getSerialNumber()
              + " from issuer \'"
              + certificate.getIssuerDN()
              + "\' is revoked.");
    } else {
      String username =
          certificateStoreSession.findUsernameByCertSerno(
              certificate.getSerialNumber(),
              CertTools.getIssuerDN(certificate));
      if (username == null || username.length() == 0) {
        throw new ServletException(
            new ObjectNotFoundException("Not possible to retrieve user name"));
      }
      request.setAttribute("username", username);
      if (LOG.isDebugEnabled()) {
        LOG.debug("User authenticated as '" + username + "'.");
      }

      // Request certificate renewal
      if (request.getParameter(BUTTONRENEW) != null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Got renewal request for '" + username + "'.");
        }
        String statusMessage;
        try {
          EndEntityInformation userdata =
              endEntityAccessSession.findUser(admin, username);
          if (userdata.getType().contains(EndEntityTypes.SENDNOTIFICATION)) {
            EndEntityProfile profile =
                endEntityProfileSession.getEndEntityProfile(
                    userdata.getEndEntityProfileId());
            userdata.setPassword(profile.getAutoGeneratedPasswd());
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.changeUser(admin, userdata, false);
            statusMessage =
                "Your request for certificate renewal has been submitted. You"
                    + " will be notified by mail of the status change and new"
                    + " password.";
          } else {
            LOG.warn(
                "End entity with username "
                    + username
                    + " attempted to renew browser certificate, but password"
                    + " cannot be retrieved since notifications are not"
                    + " configured.");
            statusMessage =
                "No notifications have been set for this end entity, so the"
                    + " new password can't be retrieved.";
          }
        } catch (WaitingForApprovalException ex) {
          statusMessage =
              "Your request for certificate renewal has been submitted and is"
                  + " now waiting for approval.";
        } catch (ApprovalException ex) {
          statusMessage =
              "Your request for certificate renewal has been submitted before"
                  + " and is already waiting for approval.";
        } catch (Exception ex) {
          throw new ServletException(ex);
        }
        request.setAttribute("statusMessage", statusMessage);
      }
    }
    request.setAttribute("buttonRenew", BUTTONRENEW);
    request.getRequestDispatcher("/renewpage.jsp").forward(request, response);
  }

  /**
   * Handles HTTP POST.
   *
   * @param request servlet request
   * @param response servlet response
   * @throws IOException input/output error
   * @throws ServletException on error
   */
  @Override
  public void doPost(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    doRequest(request, response);
  }

  /**
   * Handles HTTP GET.
   *
   * @param request servlet request
   * @param response servlet response
   * @throws IOException input/output error
   * @throws ServletException on error
   */
  @Override
  public void doGet(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    doRequest(request, response);
  }
}
