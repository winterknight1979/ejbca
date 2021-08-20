package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.util.StringUtil;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;
import org.ejbca.ui.web.pub.ServletUtils;

/** This Servlet exports a CA as an octet/stream. */
public class CAExportServlet extends BaseAdminServlet {
      /** Param. */
  private static final Logger LOG = Logger.getLogger(CAExportServlet.class);
  private static final long serialVersionUID = 378499368926058906L;
  /** Param. */
  public static final String HIDDEN_CANAME = "hiddencaname";
  /** Param. */
  public static final String TEXTFIELD_EXPORTCA_PASSWORD =
      "textfieldexportcapassword";

  /** Param. */
  @EJB private CAAdminSessionLocal caAdminSession;
  /** Param. */
  @EJB private CaSessionLocal caSession;

  /** Initialize. */
  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
    if (caAdminSession == null) {
      LOG.error("Local EJB injection failed.");
    }
  }

  /**
   * Handle HTTP Post. Redirect the request to doGet(..). This method should not
   * be called explicitly.
   *
   * @param req The request.
   * @param res The response.
   */
  @Override
  public void doPost(
      final HttpServletRequest req, final HttpServletResponse res)
      throws IOException, ServletException {
    LOG.trace(">doPost()");
    doGet(req, res);
    LOG.trace("<doPost()");
  }

  /**
   * Validates the request parameters and outputs the CA as an PKCS#12
   * output/octet-stream. This method should not be called explicitly.
   *
   * @param req The request.
   * @param res The response.
   */
  @Override
  public void doGet(final HttpServletRequest req, final HttpServletResponse res)
      throws IOException, ServletException {
    LOG.trace(">doGet()");
    final AuthenticationToken admin;
    try {
      admin = authenticateAdmin(req, res, StandardRules.ROLE_ROOT.resource());
    } catch (AdminWebAuthenticationException authExc) {
      // TODO: localize this.
      LOG.info("Authentication failed", authExc);
      res.sendError(HttpServletResponse.SC_FORBIDDEN, "Authentication failed");
      return;
    }
    RequestHelper.setDefaultCharacterEncoding(req);
    String caname = req.getParameter(HIDDEN_CANAME);
    String capassword = req.getParameter(TEXTFIELD_EXPORTCA_PASSWORD);
    LOG.info(
        "Got request from " + req.getRemoteAddr() + " to export " + caname);
    try {
      byte[] keystorebytes = null;
      CAInfo cainfo = caSession.getCAInfo(admin, caname);
      String ext = "p12"; // Default for X.509 CAs
      if (cainfo.getCAType() == CAInfo.CATYPE_CVC) {
        ext = "pkcs8";
      }
      keystorebytes =
          caAdminSession.exportCAKeyStore(
              admin,
              caname,
              capassword,
              capassword,
              "SignatureKeyAlias",
              "EncryptionKeyAlias");
      ServletUtils.removeCacheHeaders(
          res); // We must remove cache headers for IE
      res.setContentType("application/octet-stream");
      res.setContentLength(keystorebytes.length);
      res.setHeader(
          "Content-Disposition",
          "attachment;filename=\""
              + StringUtil.stripFilename(caname + "." + ext)
              + "\"");
      res.getOutputStream().write(keystorebytes);
    } catch (Exception e) {
      // TODO: localize
      LOG.info("Bad request", e);
      res.setContentType("text/plain");
      res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad request.");
    }
  }
}
