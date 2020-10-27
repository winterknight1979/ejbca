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

package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.config.GlobalConfiguration;

/**
 * A class representing a admins personal preferences.
 *
 * @version $Id: AdminPreference.java 27974 2018-01-16 12:56:16Z aminkh $
 */
public class AdminPreference extends UpgradeableDataHashMap
    implements Serializable, Cloneable {

  private static final long serialVersionUID = -3408759285870979620L;

  /** Config. */
  public static final float LATEST_VERSION = 1;

  // Public constants
  /** Config. */
  public static final int FILTERMODE_BASIC = 0;
  /** Config. */
  public static final int FILTERMODE_ADVANCED = 1;

  /** Creates a new instance of AdminPreference. */
  public AdminPreference() {
    super();
    final int defaultEntries = 25;
    // Set default values.
    data.put(PREFEREDLANGUAGE, Integer.valueOf(GlobalConfiguration.EN));
    data.put(SECONDARYLANGUAGE, Integer.valueOf(GlobalConfiguration.EN));
    data.put(ENTRIESPERPAGE, Integer.valueOf(defaultEntries));
    data.put(LOGENTRIESPERPAGE, Integer.valueOf(defaultEntries));
    data.put(THEME, "default_theme");
    data.put(LASTPROFILE, Integer.valueOf(0));
    data.put(LASTFILTERMODE, Integer.valueOf(FILTERMODE_BASIC));
    data.put(LASTLOGFILTERMODE, Integer.valueOf(FILTERMODE_BASIC));
    data.put(FRONTPAGECASTATUS, DEFAULT_FRONTPAGECASTATUS);
    data.put(FRONTPAGEPUBQSTATUS, DEFAULT_FRONTPAGEPUBQSTATUS);
  }

  /**
   * @return lang
   */
  public int getPreferedLanguage() {
    return ((Integer) data.get(PREFEREDLANGUAGE)).intValue();
  }

  /**
   * @param language lang
   */
  public void setPreferedLanguage(final int language) {
    data.put(PREFEREDLANGUAGE, Integer.valueOf(language));
  }

  /**
   * @return lang
   */
  public Locale getPreferedRaLanguage() {
    Locale locale = ((Locale) data.get(PREFEREDRALANGUAGE));

    if (locale == null) {
        return null;
    }
    return locale;
  }

  /**
   * @param language lang
   */
  public void setPreferedRaLanguage(final Locale language) {
    data.put(PREFEREDRALANGUAGE, language);
  }

  /**
   * @return style
   */
  public Integer getPreferedRaStyleId() {

    Integer raStyleId = ((Integer) data.get(PREFEREDRASTYLEID));

    if (raStyleId == null) {
        return null;
    }
    return raStyleId;
  }

  /**
   * @param preferedRaStyleId style
   */
  public void setPreferedRaStyleId(final int preferedRaStyleId) {
    data.put(PREFEREDRASTYLEID, preferedRaStyleId);
  }

  /**
   * Method taking a string, needs as input the available languages.
   *
   * @param languages available languages as retrieved from
   *     EjbcaWebBean.getAvailableLanguages
   * @param languagecode two letter language code (ISO 639-1), e.g. en, sv
   *     org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getAvailableLanguages()
   */
  public void setPreferedLanguage(
      final String[] languages, final String languagecode) {
    if (languages != null) {
      for (int i = 0; i < languages.length; i++) {
        if (languages[i].equalsIgnoreCase(languagecode)) {
          data.put(PREFEREDLANGUAGE, Integer.valueOf(i));
        }
      }
    }
  }

  /**
   * @return lang
   */
  public int getSecondaryLanguage() {
    return ((Integer) data.get(SECONDARYLANGUAGE)).intValue();
  }

  /**
   * @param language lang
   */
  public void setSecondaryLanguage(final int language) {
    data.put(SECONDARYLANGUAGE, Integer.valueOf(language));
  }

  /**
   * Method taking a string, needs as input the available languages.
   *
   * @param languages available languages as retrieved from
   *     EjbcaWebBean.getAvailableLanguages
   * @param languagecode two letter language code (ISO 639-1), e.g. en, sv see
   *     org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getAvailableLanguages()
   */
  public void setSecondaryLanguage(
      final String[] languages, final String languagecode) {
    if (languages != null) {
      for (int i = 0; i < languages.length; i++) {
        if (languages[i].equalsIgnoreCase(languagecode)) {
          data.put(SECONDARYLANGUAGE, Integer.valueOf(i));
        }
      }
    }
  }

  /**
   * @return num
   */
  public int getEntriesPerPage() {
    return ((Integer) data.get(ENTRIESPERPAGE)).intValue();
  }

  /**
   * @param entriesperpage num
   */
  public void setEntriesPerPage(final int entriesperpage) {
    data.put(ENTRIESPERPAGE, Integer.valueOf(entriesperpage));
  }

  /**
   * @return num
   */
  public int getLogEntriesPerPage() {
    return ((Integer) data.get(LOGENTRIESPERPAGE)).intValue();
  }

  /**
   * @param logentriesperpage num
   */
  public void setLogEntriesPerPage(final int logentriesperpage) {
    data.put(LOGENTRIESPERPAGE, Integer.valueOf(logentriesperpage));
  }

  /**
   * @return theme
   */
  public String getTheme() {
    return (String) data.get(THEME);
  }

  /**
   * @param theme theme
   */
  public void setTheme(final String theme) {
    data.put(THEME, theme);
  }

  /**
   * @return profile
   */
  public int getLastProfile() {
    return ((Integer) data.get(LASTPROFILE)).intValue();
  }

  /**
   * @param lastprofile profile
   */
  public void setLastProfile(final int lastprofile) {
    data.put(LASTPROFILE, Integer.valueOf(lastprofile));
  }

  /**
   * Last filter mode is the admins last mode in the list end entities jsp page.
   *
   * @return int
   */
  public int getLastFilterMode() {
    return ((Integer) data.get(LASTFILTERMODE)).intValue();
  }

  /**
   * @param lastfiltermode mode
   */
  public void setLastFilterMode(final int lastfiltermode) {
    data.put(LASTFILTERMODE, Integer.valueOf(lastfiltermode));
  }

  /**
   * @return mode
   */
  public int getLastLogFilterMode() {
    return ((Integer) data.get(LASTLOGFILTERMODE)).intValue();
  }

  /**
   * @param lastlogfiltermode mode
   */
  public void setLastLogFilterMode(final int lastlogfiltermode) {
    data.put(LASTLOGFILTERMODE, Integer.valueOf(lastlogfiltermode));
  }

  /**
   * @return status
   */
  public boolean getFrontpageCaStatus() {
    return Boolean.TRUE.equals(data.get(FRONTPAGECASTATUS));
  }

  /**
   * @param frontpagecastatus status
   */
  public void setFrontpageCaStatus(final boolean frontpagecastatus) {
    data.put(FRONTPAGECASTATUS, Boolean.valueOf(frontpagecastatus));
  }

  /**
   * @return status
   */
  public boolean getFrontpagePublisherQueueStatus() {
    return Boolean.TRUE.equals(data.get(FRONTPAGEPUBQSTATUS));
  }

  /**
   * @param frontpagepubqstatus status
   */
  public void setFrontpagePublisherQueueStatus(
      final boolean frontpagepubqstatus) {
    data.put(FRONTPAGEPUBQSTATUS, Boolean.valueOf(frontpagepubqstatus));
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    AdminPreference clone = new AdminPreference();
    @SuppressWarnings("unchecked")
    HashMap<Object, Object> clonedata =
        (HashMap<Object, Object>) clone.saveData();

    Iterator<Object> i = (data.keySet()).iterator();
    while (i.hasNext()) {
      Object key = i.next();
      clonedata.put(key, data.get(key));
    }

    clone.loadData(clonedata);
    return clone;
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion.
   * @return version*/
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade

      if (data.get(FRONTPAGECASTATUS) == null) {
        data.put(FRONTPAGECASTATUS, DEFAULT_FRONTPAGECASTATUS);
      }
      if (data.get(FRONTPAGEPUBQSTATUS) == null) {
        data.put(FRONTPAGEPUBQSTATUS, DEFAULT_FRONTPAGEPUBQSTATUS);
      }

      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  // Private fields
  /** Config. */
  private static final String PREFEREDLANGUAGE = "preferedlanguage";
  /** Config. */
  private static final String SECONDARYLANGUAGE = "secondarylanguage";
  /** Config. */
  private static final String ENTRIESPERPAGE = "entriesperpage";
  /** Config. */
  private static final String LOGENTRIESPERPAGE = "logentriesperpage";
  /** Config. */
  private static final String THEME = "theme";
  /** Config. */
  private static final String LASTPROFILE = "lastprofile";
  /** Config. */
  private static final String LASTFILTERMODE = "lastfiltermode";
  /** Config. */
  private static final String LASTLOGFILTERMODE = "lastlogfiltermode";
  /** Config. */
  private static final String FRONTPAGECASTATUS = "frontpagecastatus";
  /** Config. */
  private static final String FRONTPAGEPUBQSTATUS = "frontpagepubqstatus";
  /** Config. */
  private static final String PREFEREDRALANGUAGE = "preferedRaLanguage";
  /** Config. */
  private static final String PREFEREDRASTYLEID = "preferedRaStyleId";

  /** Config. */
  public static final boolean DEFAULT_FRONTPAGECASTATUS = true;
  /** Config. */
  public static final boolean DEFAULT_FRONTPAGEPUBQSTATUS = true;
}
