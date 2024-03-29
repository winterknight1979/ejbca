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

import java.beans.Beans;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;
import org.cesecore.util.StringUtil;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.UserView;

/**
 * This is a servlet that is used for creating a user into EJBCA and retrieving
 * her certificate. This servlet requires authentication of the administrator,
 * specifically it requires that the client certificate has the privilege
 * "/ra_functionality/create_end_entity", as defined in the admin-GUI.
 *
 * <p>This implementation handles only the POST method.
 *
 * <p>The CGI parameters for requests are the following.
 *
 * <dl>
 *   <dt>pkcs10req
 *   <dd>A PKCS#10 request, mandatory.
 *   <dt>username
 *   <dd>The username (for EJBCA use only). Optional, defaults to the DN in the
 *       PKCS#10 request.
 *   <dt>password
 *   <dd>Password for the user (for EJBCA internal use only). Optional, defaults
 *       to an empty string. Used for authorization af certificate request.
 *   <dt>entityprofile
 *   <dd>The name of the EJBCA end entity profile for the user. Optional,
 *       defaults to the built-in EMPTY end entity profile.
 *   <dt>certificateprofile
 *   <dd>The name of the EJBCA certificate profile to use. Optional, defaults to
 *       the built-in ENDUSER certificate profile.
 *   <dt>ca
 *   <dd>The name of the ca to use. Required,
 * </dl>
 *
 * @version $Id: AdminCertReqServlet.java 34154 2019-12-23 13:38:17Z samuellb $
 */
public class AdminCertReqServlet extends BaseAdminServlet {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(AdminCertReqServlet.class);
  /** Param. */

  private static final byte[] BEGIN_CERT =
      "-----BEGIN CERTIFICATE-----".getBytes();
  /** Param. */
  private static final int BEGIN_CERT_LENGTH = BEGIN_CERT.length;

  /** Param. */
  private static final byte[] END_CERT = "-----END CERTIFICATE-----".getBytes();
  /** Param. */
  private static final int END_CERT_LENGTH = END_CERT.length;

  /** Param. */
  private static final byte[] NL = "\n".getBytes();
  /** Param. */
  private static final int NL_LENGTH = NL.length;

  /** Param. */
  @EJB private SignSessionLocal signSession;

  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
    if (signSession == null) {
      LOG.error("Local EJB injection failed.");
    }
  }

  /**
   * Handles PKCS10 certificate request, these are constructed as:
   *
   * <pre><code>
   * CertificationRequest ::= SEQUENCE {
   * certificationRequestInfo  CertificationRequestInfo,
   * signatureAlgorithm          AlgorithmIdentifier{{ SignatureAlgorithms }},
   * signature                       BIT STRING
   * }
   * CertificationRequestInfo ::= SEQUENCE {
   * version             INTEGER { v1(0) } (v1,...),
   * subject             Name,
   * subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
   * attributes          [0] Attributes{{ CRIAttributes }}
   * }
   * SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
   * algorithm           AlgorithmIdentifier {{IOSet}},
   * subjectPublicKey    BIT STRING
   * }
   * </code></pre>
   *
   * PublicKey's encoded-format has to be RSA X.509.
   */
  @Override
  public void doPost(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    final AuthenticationToken admin;
    try {
      admin =
          authenticateAdmin(
              request, response, AccessRulesConstants.REGULAR_CREATEENDENTITY);
    } catch (AdminWebAuthenticationException authExc) {
      // TODO: localize this.
      LOG.info("Authentication failed", authExc);
      response.sendError(
          HttpServletResponse.SC_FORBIDDEN, "Authentication failed");
      return;
    }

    RequestHelper.setDefaultCharacterEncoding(request);

    byte[] buffer = pkcs10Bytes(request.getParameter("pkcs10req"));
    if (buffer == null) {
      response.sendError(
          HttpServletResponse.SC_BAD_REQUEST,
          "Invalid request, missing 'pkcs10req'!");
      return;
    }

    RAInterfaceBean rabean = getRaBean(request);

    // Decompose the PKCS#10 request, and create the user.
    PKCS10RequestMessage p10 = new PKCS10RequestMessage(buffer);
    String dn = p10.getCertificationRequest().getSubject().toString();

    String username = request.getParameter("username");
    if (username == null || username.trim().length() == 0) {
      username = dn;
    }
    // Strip dangerous chars
    username = StringUtil.stripUsername(username);
    // need null check here?
    // Before doing anything else, check if the user name is unique and ok.
    username = checkUsername(rabean, username);

    UserView newuser = new UserView();
    newuser.setUsername(username);

    newuser.setSubjectDN(dn);
    newuser.setTokenType(SecConst.TOKEN_SOFT_BROWSERGEN);
    newuser.setKeyRecoverable(false);

    String email = CertTools.getPartFromDN(dn, "E"); // BC says VeriSign
    if (email == null) {
      email = CertTools.getPartFromDN(dn, "EMAILADDRESS");
    } else {
      newuser.setEmail(email);
    }

    String tmp = null;
    int eProfileId = EndEntityConstants.EMPTY_END_ENTITY_PROFILE;
    tmp = request.getParameter("entityprofile");
    if (tmp != null) {
      int reqId;
      try {
        reqId = rabean.getEndEntityProfileId(tmp);
      } catch (EndEntityProfileNotFoundException e) {
        throw new ServletException("No such end entity profile: " + tmp, e);
      }
      eProfileId = reqId;
    }
    newuser.setEndEntityProfileId(eProfileId);

    int cProfileId = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
    tmp = request.getParameter("certificateprofile");
    if (tmp != null) {
      CAInterfaceBean cabean = getCaBean(request);
      int reqId = cabean.getCertificateProfileId(tmp);
      if (reqId == 0) {
        throw new ServletException("No such certificate profile: " + tmp);
      }
      cProfileId = reqId;
    }
    newuser.setCertificateProfileId(cProfileId);

    int caid = 0;
    tmp = request.getParameter("ca");
    if (tmp != null) {
      // TODO: get requested CA to sign with
    }
    newuser.setCAId(caid);

    String password = request.getParameter("password");
    if (password == null) {
      password = "";
    }
    newuser.setPassword(password);
    newuser.setClearTextPassword(false);

    try {
      rabean.addUser(newuser);
    } catch (Exception e) {
      throw new ServletException("Error adding user: " + e.toString(), e);
    }

    byte[] pkcs7;
    try {
      p10.setUsername(username);
      p10.setPassword(password);
      ResponseMessage resp =
          signSession.createCertificate(
              admin, p10, X509ResponseMessage.class, null);
      X509Certificate cert =
          CertTools.getCertfromByteArray(
              resp.getResponseMessage(), X509Certificate.class);
      pkcs7 = signSession.createPKCS7(admin, cert, true);
    } catch (EjbcaException e) {
      // EJBCA did not accept any of all parameters in the request.
      throw new ServletException(e);
    } catch (CertificateEncodingException e) {
      // Error in cert
      throw new ServletException(e);
    } catch (CertificateException e) {
      // Error in cert
      throw new ServletException(e);
    } catch (CesecoreException e) {
      // EJBCA did not accept any of all parameters in the request.
      throw new ServletException(e);
    } catch (AuthorizationDeniedException e) {
      // Weird authorization error.
      throw new ServletException(e);
    } catch (CertificateExtensionException e) {
      throw new ServletException(e);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created certificate (PKCS7) for " + username);
    }
    sendNewB64Cert(Base64Util.encode(pkcs7), response);
  }

  @Override
  public void doGet(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    LOG.trace(">doGet()");
    response.setHeader("Allow", "POST");
    response.sendError(
        HttpServletResponse.SC_METHOD_NOT_ALLOWED,
        "The certificate request servlet only handles the POST method.");
    LOG.trace("<doGet()");
  } // doGet

  private void sendNewB64Cert(
      final byte[] b64cert, final HttpServletResponse out) throws IOException {
    final int mul = 3;
    out.setContentType("application/octet-stream");
    out.setHeader("Content-Disposition", "filename=cert.pem");
    out.setContentLength(
        b64cert.length + BEGIN_CERT_LENGTH
            + END_CERT_LENGTH + (mul * NL_LENGTH));

    ServletOutputStream os = out.getOutputStream();
    os.write(BEGIN_CERT);
    os.write(NL);
    os.write(b64cert);
    os.write(NL);
    os.write(END_CERT);
    os.write(NL);
    out.flushBuffer();
  }

  /**
   * @param pkcs10 PKCS 10 string
   * @return bytes
   */
  private static byte[] pkcs10Bytes(final String pkcs10) {
    byte[] bytes = null;
    if (pkcs10 != null) {
      byte[] reqBytes = pkcs10.getBytes();
      try {
        // A real PKCS10 PEM request
        String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
        String endKey = "-----END CERTIFICATE REQUEST-----";
        bytes = FileTools.getBytesFromPEM(reqBytes, beginKey, endKey);
      } catch (IOException e) {
        try {
          // Keytool PKCS10 PEM request
          String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
          String endKey = "-----END NEW CERTIFICATE REQUEST-----";
          bytes = FileTools.getBytesFromPEM(reqBytes, beginKey, endKey);
        } catch (IOException e2) {
          // IE PKCS10 Base64 coded request
          bytes = Base64Util.decode(reqBytes);
        }
      }
    }
    return bytes;
  }

  /**
   * @param req Request
   * @return Bean
   * @throws ServletException Fail
   */
  private CAInterfaceBean getCaBean(final HttpServletRequest req)
      throws ServletException {
    HttpSession session = req.getSession();
    CAInterfaceBean cabean = (CAInterfaceBean) session.getAttribute("cabean");
    if (cabean == null) {
      try {
        cabean =
            (CAInterfaceBean)
                Beans.instantiate(
                    Thread.currentThread().getContextClassLoader(),
                    org.ejbca.ui.web.admin.cainterface.CAInterfaceBean.class
                        .getName());
      } catch (ClassNotFoundException e) {
        throw new ServletException(e);
      } catch (Exception e) {
        throw new ServletException("Unable to instantiate CAInterfaceBean", e);
      }
      try {
        cabean.initialize(getEjbcaWebBean(req));
      } catch (Exception e) {
        throw new ServletException("Cannot initialize CAInterfaceBean", e);
      }
      session.setAttribute("cabean", cabean);
    }
    return cabean;
  }

  /**
   * @param rabean Bean
   * @param ousername User
   * @return String
   * @throws ServletException Fail
   */
  private String checkUsername(
      final RAInterfaceBean rabean,
      final String ousername) throws ServletException {
    String username = ousername;
    if (username != null) {
      username = username.trim();
    }
    if (username == null || username.length() == 0) {
      throw new ServletException("Username must not be empty.");
    }

    String msg = null;
    try {
      if (rabean.userExist(username)) {
        msg = "User '" + username + "' already exists.";
      }
    } catch (Exception e) {
      throw new ServletException(
          "Error checking username '" + username + ": " + e.toString(), e);
    }
    if (msg != null) {
      throw new ServletException(msg);
    }

    return username;
  }
}
