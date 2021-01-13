package org.ejbca.ui.web.admin.configuration;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * Class used to integrate the old jsp framework with the new JSF one. Contains
 * methods for such things as language, themes ext
 *
 * <p>$Id: EjbcaJSFHelper.java 30330 2018-11-01 10:38:35Z anatom $
 */
public class EjbcaJSFHelper {
      /** Param. */
  private static final Logger LOG = Logger.getLogger(EjbcaJSFHelper.class);

  /** Param. */
  private EjbcaJSFLanguageResource text = null;
  /** Param. */
  private EjbcaJSFImageResource image = null;
  /** Param. */
  private EjbcaWebBean ejbcawebbean;
  /** Param. */
  private Boolean legacyInternetExplorer = null;

  /** Param. */
  private boolean initialized = false;

  /** Param. */
  public EjbcaJSFHelper() { }

  /**
   * @param anejbcawebbean bean
   */
  public void setEjbcaWebBean(final EjbcaWebBean anejbcawebbean) {
    if (!initialized) {
      this.ejbcawebbean = anejbcawebbean;
      text = new EjbcaJSFLanguageResource(anejbcawebbean);
      image = new EjbcaJSFImageResource(anejbcawebbean);
      initialized = true;
    }
  }

  /**
   * Returns the EJBCA title.
   *
   * @return Title
   */
  public String getEjbcaTitle() {
    GlobalConfiguration gc = getEjbcaWebBean().getGlobalConfiguration();
    if (gc == null) {
      LOG.warn(
          "GlobalConfiguration is null trying to get from EjbcaWebBean,"
              + " returning default Title.");
      return GlobalConfiguration.getEjbcaDefaultTitle();
    }
    return gc.getEjbcaTitle();
  }

  /**
   * Returns the EJBCA theme.
   *
   * @return Theme
   */
  public String getTheme() {
    return getEjbcaWebBean().getCssFile();
  }

  /**
   * Returns the EJBCA base url.
   *
   * @return String
   */
  public String getEjbcaBaseURL() {
    return getEjbcaWebBean().getBaseUrl();
  }

  /**
   * Returns the EJBCA content string.
   *
   * @return String
   */
  public String getContent() {
    return "text/html; charset=" + WebConfiguration.getWebContentEncoding();
  }

  /**
   * Used for language resources.
   *
   * @return Resource
   */
  public EjbcaJSFLanguageResource getText() {
    setEjbcaWebBean(getEjbcaWebBean());
    return text;
  }

  /**
   * Used for image resources.
   *
   * @return Resource
   */
  public EjbcaJSFImageResource getImage() {
    setEjbcaWebBean(getEjbcaWebBean());
    return image;
  }

  /**
   * Special function for approval pages since it has two different accessrules.
   *
   * @throws AuthorizationDeniedException fail
   */
  public void authorizedToApprovalPages() throws AuthorizationDeniedException {
    // Check Authorization
    boolean approveendentity =
        getEjbcaWebBean()
            .isAuthorizedNoLogSilent(
                AccessRulesConstants.REGULAR_APPROVEENDENTITY);
    boolean approvecaaction =
        getEjbcaWebBean()
            .isAuthorizedNoLogSilent(
                AccessRulesConstants.REGULAR_APPROVECAACTION);
    if (!approveendentity && !approvecaaction) {
      throw new AuthorizationDeniedException(
          "Not authorized to view approval pages");
    }
  }

  /**
   * @return entries
   */
  public int getEntriesPerPage() {
    return getEjbcaWebBean().getEntriesPerPage();
  }

  /**
   * @return Bean
   */
  public EjbcaWebBean getEjbcaWebBean() {
    FacesContext ctx = FacesContext.getCurrentInstance();
    HttpSession session =
        (HttpSession) ctx.getExternalContext().getSession(true);
    synchronized (session) {
      ejbcawebbean =
          (org.ejbca.ui.web.admin.configuration.EjbcaWebBean)
              session.getAttribute("ejbcawebbean");
      if (ejbcawebbean == null) {
        ejbcawebbean = new org.ejbca.ui.web.admin.configuration.EjbcaWebBean();
        try {
          ejbcawebbean.initialize(
              (HttpServletRequest) ctx.getExternalContext().getRequest(),
              AccessRulesConstants.ROLE_ADMINISTRATOR);
          session.setAttribute("ejbcawebbean", ejbcawebbean);
        } catch (Exception e) {
          LOG.error(e);
        }
      }
    }
    return ejbcawebbean;
  }

  /**
   * @return token
   */
  public AuthenticationToken getAdmin() {
    return getEjbcaWebBean().getAdminObject();
  }

  /**
   * @return Bean
   */
  public static EjbcaJSFHelper getBean() {
    FacesContext context = FacesContext.getCurrentInstance();
    Application app = context.getApplication();
    EjbcaJSFHelper value =
        (EjbcaJSFHelper)
            app.evaluateExpressionGet(context, "#{web}", EjbcaJSFHelper.class);
    return value;
  }

  /**
   * @return true if the client browser has identified itself as a legacy
   *     Internet Explorer 10 (or earlier)
   */
  public boolean isLegacyInternetExplorer() {
    if (legacyInternetExplorer == null) {
      final HttpServletRequest httpServletRequest =
          (HttpServletRequest)
              FacesContext.getCurrentInstance()
                  .getExternalContext()
                  .getRequest();
      final String userAgent = httpServletRequest.getHeader("User-Agent");
      if (LOG.isDebugEnabled()) {
        LOG.debug("User-Agent: " + userAgent);
      }
      // Check stolen from
      // org.ejbca.ui.web.pub.ApplyBean.detectBrowser(HttpServletRequest)
      // "Gecko"==Firefox, "MSIE"==Internet Exploder 10-, "Trident"==IE11
      legacyInternetExplorer =
          Boolean.valueOf(
              userAgent != null
                  && userAgent.contains("MSIE")
                  && !userAgent.contains("Gecko"));
    }
    return legacyInternetExplorer.booleanValue();
  }
}
