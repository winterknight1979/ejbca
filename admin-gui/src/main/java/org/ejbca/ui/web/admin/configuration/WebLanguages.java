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

package org.ejbca.ui.web.admin.configuration;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.servlet.ServletContext;
import org.apache.log4j.Logger;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * An class interpreting the language properties files. I contains one method
 * getText that returns the presented text in the users preferred language.
 *
 * @version $Id: WebLanguages.java 23625 2016-06-07 19:32:11Z anatom $
 */
public class WebLanguages implements java.io.Serializable {
  private static final long serialVersionUID = -2381623760140383128L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(WebLanguages.class);

  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /**
   * Constructor used to load static content. An instance must be declared with
   * this constructor before any WebLanguage object can be used.
   * Special constructor used by Ejbca web bean.
   *
   * @param servletContext Context
   * @param globalconfiguration Config
   */
  private void init(
      final ServletContext servletContext,
      final GlobalConfiguration globalconfiguration) {
    if (languages == null) {
      // Get available languages.
      availablelanguages = null;
      String availablelanguagesstring =
          globalconfiguration.getAvailableLanguagesAsString();
      availablelanguages = availablelanguagesstring.split(",");
      for (int i = 0; i < availablelanguages.length; i++) {
        availablelanguages[i] = availablelanguages[i].trim().toLowerCase();
        if (availablelanguages[i].equalsIgnoreCase("se")) {
            /* For compatibility with EJBCA 6.2.x and before */
          availablelanguages[i] = "sv";
        }
        if (availablelanguages[i].equalsIgnoreCase("ua")) {
            /* For compatibility with EJBCA 6.2.x and before */
          availablelanguages[i] = "uk";
        }
      }
      // Load available languages
      languages = new LanguageProperties[availablelanguages.length];
      for (int i = 0; i < availablelanguages.length; i++) {
        languages[i] = new LanguageProperties();
        String propsfile =
            "/"
                + globalconfiguration.getLanguagePath()
                + "/"
                + globalconfiguration.getLanguageFilename()
                + "."
                + availablelanguages[i]
                + ".properties";

        InputStream is = null;
        try {
          try {
            if (servletContext != null) {
              is = servletContext.getResourceAsStream(propsfile);
            } else {
              is = this.getClass().getResourceAsStream(propsfile);
            }
            if (is == null) {
              // if not available as stream, try it as a file
              is = new FileInputStream("/tmp" + propsfile);
            }
            if (LOG.isDebugEnabled()) {
              LOG.debug("Loading language from file: " + propsfile);
            }
            languages[i].load(is);
          } finally {
            if (is != null) {
              is.close();
            }
          }
        } catch (IOException e) {
          throw new IllegalStateException(
              "Properties file " + propsfile + " could not be read.", e);
        }
      }
      // Get languages English and native names
      languagesenglishnames = new String[availablelanguages.length];
      languagesnativenames = new String[availablelanguages.length];
      for (int i = 0; i < availablelanguages.length; i++) {
        languagesenglishnames[i] =
            languages[i].getProperty("LANGUAGE_ENGLISHNAME");
        languagesnativenames[i] =
            languages[i].getProperty("LANGUAGE_NATIVENAME");
      }
    }
  }

  /**
   * @param servletContext Ctx
   * @param globalconfiguration Config
   * @param preferedlang Lang
   * @param secondarylang Lang
   */
  public WebLanguages(
      final ServletContext servletContext,
      final GlobalConfiguration globalconfiguration,
      final int preferedlang,
      final int secondarylang) {
    init(servletContext, globalconfiguration);
    this.userspreferedlanguage = preferedlang;
    this.userssecondarylanguage = secondarylang;
  }

  /**
   * The main method that looks up the template text in the users preferred
   * language.
   *
   * @param template Template
   * @param params Params
   * @return text
   */
  public String getText(final String template, final Object... params) {
    String returnvalue = null;
    try {
      returnvalue =
          languages[userspreferedlanguage].getMessage(template, params);
      if (returnvalue == null) {
        returnvalue =
            languages[userssecondarylanguage].getMessage(template, params);
      }
      if (returnvalue == null) {
        returnvalue = INTRES.getLocalizedMessage(template, params);
      }
    } catch (java.lang.NullPointerException e) {
    }
    if (returnvalue == null) {
      returnvalue = template;
    }
    return returnvalue;
  }

  /** Returns a text string array containing the available languages.
 * @return Names */
  public String[] getAvailableLanguages() {
    return availablelanguages;
  }

  /** Returns a text string array containing the languages English names.
 * @return names */
  public String[] getLanguagesEnglishNames() {
    return languagesenglishnames;
  }

  /** Returns a text string array containing the languages native names.
 * @return names*/
  public String[] getLanguagesNativeNames() {
    return languagesnativenames;
  }

  // Protected fields
  /** Param. */
  private final int userspreferedlanguage;
  /** Param. */
  private final int userssecondarylanguage;

  /** Param. */
  private String[] availablelanguages;
  /** Param. */
  private String[] languagesenglishnames;
  /** Param. */
  private String[] languagesnativenames;
  /** Param. */
  private LanguageProperties[] languages = null;
}
