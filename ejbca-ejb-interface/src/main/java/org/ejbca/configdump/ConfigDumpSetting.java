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
package org.ejbca.configdump;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Data class containing settings for configuration dump. Probably better to use
 * a builder pattern here.
 *
 * @version $Id: ConfigDumpSetting.java 29688 2018-08-20 15:27:29Z henriks $
 */
public class ConfigDumpSetting implements Serializable {

  private static final long serialVersionUID = 1L;

  public enum ItemType {
        /** Type. */
    ACMECONFIG,
    /** Type. */
    CA,
    /** Type. */
    CRYPTOTOKEN,
    /** Type. */
    PUBLISHER,
    /** Type. */
    APPROVALPROFILE,
    /** Type. */
    CERTPROFILE,
    /** Type. */
    EEPROFILE,
    /** Type. */
    SERVICE,
    /** Type. */
    ROLE,
    /** Type. */
    KEYBINDING,
    /** Type. */
    ENDENTITY,
    /** Type. */
    SYSCONFIG,
    /** Type. */
    ADMINPREFS,
    /** Type. */
    CMPCONFIG,
    /** Type. */
    OCSPCONFIG,
    /** Type. */
    PEERCONNECTOR,
    /** Type. */
    PEERCONFIG,
    /** Type. */
    SCEPCONFIG,
    /** Type. */
    ESTCONFIG,
    /** Type. */
    VALIDATOR,
    /** Type. */
    CTLOG,
    /** Type. */
    EXTENDEDKEYUSAGE,
    /** Type. */
    CERTEXTENSION
  };

  /** PAram. */
  private File location;
  /** PAram. */
  private Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
  /** PAram. */
  private Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();
  /** PAram. */
  private List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
  /** PAram. */
  private List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
  /** PAram. */
  private final boolean ignoreErrors;
  /** PAram. */
  private final boolean ignoreWarnings;

  /**
   * @return list
   */
  public List<ConfigdumpPattern> getIncludedAnyType() {
    return includedAnyType;
  }

  /**
   * @param theincludedAnyType list
   */
  public void setIncludedAnyType(
      final List<ConfigdumpPattern> theincludedAnyType) {
    this.includedAnyType = theincludedAnyType;
  }

  /**
   * @return list
   */
  public List<ConfigdumpPattern> getExcludedAnyType() {
    return excludedAnyType;
  }

  /**
   * @param theexcludedAnyType list
   */
  public void setExcludedAnyType(
      final List<ConfigdumpPattern> theexcludedAnyType) {
    this.excludedAnyType = theexcludedAnyType;
  }

  /**
   * @return loc
   */
  public File getLocation() {
    return location;
  }


  /**
   * @param alocation loc
   */
  public void setLocation(final File alocation) {
    this.location = alocation;
  }

  /**
   * @param theincluded map
   */
  public void setIncluded(
      final Map<ItemType, List<ConfigdumpPattern>> theincluded) {
    this.included = theincluded;
  }

  /**
   * @param theexcluded map
   */
  public void setExcluded(
      final Map<ItemType, List<ConfigdumpPattern>> theexcluded) {
    this.excluded = theexcluded;
  }

  /**
   * @return map
   */
  public Map<ItemType, List<ConfigdumpPattern>> getIncluded() {
    return included;
  }

  /**
   * @return Map
   */
  public Map<ItemType, List<ConfigdumpPattern>> getExcluded() {
    return excluded;
  }

  /**
   * @return bool
   */
  public boolean getIgnoreErrors() {
    return ignoreErrors;
  }

  /**
   * @return bool
   */
  public boolean getIgnoreWarnings() {
    return ignoreWarnings;
  }

  /**
   * @param alocation loc
   * @param theincluded included
   * @param theexcluded excluded
   * @param theincludedAnyType included
   * @param theexcludedAnyType excluded
   * @param doignoreErrors bool
   * @param doignoreWarnings bool
   */
  public ConfigDumpSetting(
      final File alocation,
      final Map<ItemType, List<ConfigdumpPattern>> theincluded,
      final Map<ItemType, List<ConfigdumpPattern>> theexcluded,
      final List<ConfigdumpPattern> theincludedAnyType,
      final List<ConfigdumpPattern> theexcludedAnyType,
      final boolean doignoreErrors,
      final boolean doignoreWarnings) {
    this.location = alocation;
    this.included = theincluded;
    this.excluded = theexcluded;
    this.includedAnyType = theincludedAnyType;
    this.excludedAnyType = theexcludedAnyType;
    this.ignoreErrors = doignoreErrors;
    this.ignoreWarnings = doignoreWarnings;
  }

  /**
   * @param type type
   * @param nameStr name
   * @return bool
   */
  public boolean isIncluded(final ItemType type, final String nameStr) {

    final List<ConfigdumpPattern> includeList = included.get(type);
    final List<ConfigdumpPattern> excludeList = excluded.get(type);
    final String name = (nameStr != null ? nameStr.toLowerCase() : "");

    if (includeList != null) {
      for (ConfigdumpPattern p : includeList) {
        if (p.matches(name)) {
          return true;
        }
      }
      return false;
    }

    if (!includedAnyType.isEmpty()) {
      for (ConfigdumpPattern p : includedAnyType) {
        if (p.matches(name)) {
          return true;
        }
      }
      return false;
    }

    if (excludeList != null) {
      for (ConfigdumpPattern p : excludeList) {
        if (p.matches(name)) {
          return false;
        }
      }
    }

    for (ConfigdumpPattern p : excludedAnyType) {
      if (p.matches(name)) {
        return false;
      }
    }

    // Didn't match anything. Default is to include.
    return true;
  }
}
