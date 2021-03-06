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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import javax.ejb.EJB;
import javax.faces.application.Application;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;

/**
 * JSF Managed Bean for handling localization of clients.
 *
 * @version $Id: RaLocaleBean.java 26904 2017-10-26 10:37:28Z aminkh $ TODO: Use
 *     CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@SessionScoped
public class RaLocaleBean implements Serializable {

      /** Param.   */
  private static final String LEFT_TO_RIGHT = "ltr";
  /** Param.   */
  private static final String RIGHT_TO_LEFT = "rtl";

  private static final long serialVersionUID = 1L;
  /** Param.   */
  private static final Logger LOG = Logger.getLogger(RaLocaleBean.class);

  /** Param.   */
  private Locale locale = null;
  /** Param.   */
  private boolean directionLeftToRight = true;

  /** Param.   */
  @EJB private AdminPreferenceSessionLocal adminPreferenceSession;

  /** Param.   */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;

  /**
   * @param araAuthenticationBean Bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }

  /** @return this sessions Locale */
  public Locale getLocale() {

    Locale localeFromDB =
        adminPreferenceSession.getCurrentRaLocale(
            raAuthenticationBean.getAuthenticationToken());

    if (localeFromDB != null) {
      locale = localeFromDB;
      directionLeftToRight = isDirectionLeftToRight(locale);
    } else {
      if (locale == null) {
        final FacesContext facesContext = FacesContext.getCurrentInstance();
        final Locale requestLocale =
            facesContext.getExternalContext().getRequestLocale();
        if (getSupportedLocales().contains(requestLocale)) {
          locale = requestLocale;
        } else {
          locale = facesContext.getApplication().getDefaultLocale();
        }
        directionLeftToRight = isDirectionLeftToRight(locale);
      }
    }
    return locale;
  }
  /**
   * Set this sessions Locale.
   *
   * @param alocale Locale
   */
  public void setLocale(final Locale alocale) {

    this.locale = alocale;
    directionLeftToRight = isDirectionLeftToRight(alocale);
  }

  /** @return a list of all locales as defined in faces-config.xml */
  public List<Locale> getSupportedLocales() {
    final Application application =
        FacesContext.getCurrentInstance().getApplication();
    final Iterator<Locale> iterator = application.getSupportedLocales();
    final List<Locale> ret = new ArrayList<Locale>();
    while (iterator.hasNext()) {
      ret.add(iterator.next());
    }
    final Locale defaultLocale = application.getDefaultLocale();
    if (!ret.contains(defaultLocale)) {
      ret.add(defaultLocale);
    }
    Collections.sort(
        ret,
        new Comparator<Locale>() {
          @Override
          public int compare(final Locale o1, final Locale o2) {
            return o1.getLanguage().compareTo(o2.getLanguage());
          }
        });
    return ret;
  }

  /**
   * @param alocale Locale
   * @return true if the language direction is left to right
   */
  private boolean isDirectionLeftToRight(final Locale alocale) {
    final int directionality =
        Character.getDirectionality(alocale.getDisplayName(alocale).charAt(0));
    LOG.debug(
        "directionality is "
            + directionality
            + " for "
            + alocale.getLanguage()
            + " ("
            + alocale.getDisplayName(alocale)
            + ").");
    return directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT
        && directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC
        && directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT_EMBEDDING
        && directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT_OVERRIDE;
  }

  /** @return true if the language direction is left to right */
  public String getDirection() {
    return directionLeftToRight ? LEFT_TO_RIGHT : RIGHT_TO_LEFT;
  }

  /** @return true if the language direction is left to right */
  public String getIndentionDirection() {
    return directionLeftToRight ? "left" : "right";
  }

  /**
   * @return the reverse of the standard value, for cases when text needs to be
   *     aligned to the other side.
   */
  public String getReverseIndentationDirection() {
    return !directionLeftToRight ? "left" : "right";
  }

  /**
   * Add a faces message with the localized message summary with level
   * FacesMessage.SEVERITY_ERROR.
   *
   * @param messageKey Hey
   * @param params Par ams
   */
  public void addMessageError(final String messageKey, final Object... params) {
    FacesContext.getCurrentInstance()
        .addMessage(
            null,
            new FacesMessage(
                FacesMessage.SEVERITY_ERROR,
                getMessage(messageKey, params),
                null));
  }

  /**
   * Add a faces message with the localized error code message with level
   * FacesMessage.SEVERITY_ERROR.
   *
   * @param errorCode Code
   */
  public void addMessageError(final ErrorCode errorCode) {
    FacesContext.getCurrentInstance()
        .addMessage(
            null,
            new FacesMessage(
                FacesMessage.SEVERITY_ERROR,
                getErrorCodeMessage(errorCode),
                null));
  }

  /**
   * Add a faces message with the localized message summary with level
   * FacesMessage.SEVERITY_WARN.
   *
   * @param messageKey Key
   * @param params Params
   */
  public void addMessageWarn(final String messageKey, final Object... params) {
    FacesContext.getCurrentInstance()
        .addMessage(
            null,
            new FacesMessage(
                FacesMessage.SEVERITY_WARN,
                getMessage(messageKey, params),
                null));
  }

  /**
   * Add a faces message with the localized message summary with level
   * FacesMessage.SEVERITY_INFO.
   *
   * @param messageKey Key
   * @param params Params
   */
  public void addMessageInfo(final String messageKey, final Object... params) {
    FacesContext.getCurrentInstance()
        .addMessage(
            null,
            new FacesMessage(
                FacesMessage.SEVERITY_INFO,
                getMessage(messageKey, params),
                null));
  }

  /**
   * Find localized message template and replace the {number} place holders with
   * the provided parameters. In the case where the localized language template
   * is not available, the template from the default language will be tried.
   *
   * @param messageKey the message key
   * @param params to replace place holders with. Evaluated with
   *     String.valueOf() (null-safe).
   * @return the localized message or "???messageKey???" if no key way found.
   */
  public String getMessage(final String messageKey, final Object... params) {
    if (messageKey == null) {
      return "???null???";
    }
    final FacesContext facesContext = FacesContext.getCurrentInstance();
    String messageTemplate = null;
    try {
      final ResourceBundle resourceBundle =
          facesContext.getApplication().getResourceBundle(facesContext, "msg");
      messageTemplate = resourceBundle.getString(messageKey);
    } catch (MissingResourceException e) {
      // Fall-back to trying the default locale
      facesContext
          .getViewRoot()
          .setLocale(facesContext.getApplication().getDefaultLocale());
      try {
        final ResourceBundle resourceBundle =
            facesContext
                .getApplication()
                .getResourceBundle(facesContext, "msg");
        messageTemplate = resourceBundle.getString(messageKey);
      } catch (MissingResourceException e2) {
        return "???" + messageKey + "???";
      } finally {
        FacesContext.getCurrentInstance().getViewRoot().setLocale(getLocale());
      }
    }
    final StringBuilder sb = new StringBuilder(messageTemplate);
    // Go backwards so if the value was the same a placeholder tag, we wont be
    // affected
    if (params.length > 0) {
      for (int i = params.length - 1; i >= 0; i--) {
        final String placeHolder = "{" + i + "}";
        final int currentIndex = sb.indexOf(placeHolder);
        if (currentIndex == -1) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "messageKey '"
                    + messageKey
                    + "' was referenced using parameter '"
                    + params[i]
                    + "', but no "
                    + placeHolder
                    + " exists.");
          }
          continue;
        }
        sb.replace(
            currentIndex,
            currentIndex + placeHolder.length(),
            String.valueOf(params[i]));
      }
    }
    return sb.toString();
  }

  /**
   * Get localized error code.
   *
   * @param errorCode code
   * @return localized error code
   */
  public String getErrorCodeMessage(final ErrorCode errorCode) {
    if (errorCode == null) {
      return "???errorCodeNull???";
    }
    return getMessage("errorcode_" + errorCode.getInternalErrorCode());
  }

  /**
   * Wraps the RaLocaleBean.getMessage().
   *
   * @param messageKey the message key
   * @param params to replace place holders with. Evaluated with
   *     String.valueOf() (null-safe).
   * @return the localized message or "???messageKey???" if no key way found.
   * @see RaLocaleBean#getMessage
   */
  public FacesMessage getFacesMessage(
      final String messageKey, final Object... params) {
    return new FacesMessage(getMessage(messageKey, params));
  }
}
