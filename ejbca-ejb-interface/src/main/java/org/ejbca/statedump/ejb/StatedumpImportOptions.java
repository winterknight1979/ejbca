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
package org.ejbca.statedump.ejb;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

/**
 * Options for statedump import. What to overwrite or not overwrite is also set
 * in the options.
 *
 * <p>The location option is mandatory.
 *
 * @version $Id: StatedumpImportOptions.java 22896 2016-02-29 21:08:52Z samuellb
 *     $
 */
public final class StatedumpImportOptions implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private File location;
  /** Param. */
  private File overridesFile;
  /** Param. */
  private boolean merge;
  /** Param. */
  private final Map<StatedumpObjectKey, StatedumpResolution> resolutions =
      new HashMap<>();
  /** Param. */
  private final Map<StatedumpObjectKey, String> passwords = new HashMap<>();
  /** Param. */
  private final List<StatedumpCAIdChange> caIdChanges = new ArrayList<>();
  /** Param. */
  private final Map<Integer, Integer> cryptoTokenIdChanges = new HashMap<>();
  /** Param. */
  private final Map<String, List<StatedumpOverride>> overrides =
      new HashMap<>();

  /** Default. */
  public StatedumpImportOptions() {
    // Does nothing
  }

  /**
   * Sets the directory to import from. Should be an absolute path.
   *
   * @param alocation location
   */
  public void setLocation(final File alocation) {
    this.location = alocation;
  }

  /**
   * @return location
   */
  public File getLocation() {
    return location;
  }

  /**
   * Sets the file to read overrides from. By default, no overrides are read.
   *
   * @param anoverridesFile file
   */
  public void setOverridesFile(final File anoverridesFile) {
    this.overridesFile = anoverridesFile;
  }

  /**
   * @return file
   */
  public File getOverridesFile() {
    return overridesFile;
  }

  /**
   * @param ismerge bool
   */
  public void setMergeCryptoTokens(final boolean ismerge) {
    this.merge = ismerge;
  }

  /**
   * @return bool
   */
  public boolean getMergeCryptoTokens() {
    return merge;
  }

  /**
   * @param key key
   * @param resolution res
   */
  public void addConflictResolution(
      final StatedumpObjectKey key, final StatedumpResolution resolution) {
    resolutions.put(key, resolution);
  }

  /**
   * Internal method, but EJBs can't call package internal methods, so it must
   * be public.
   *
   * @param key key
   * @return resolution
   */
  public StatedumpResolution ulookupConflictResolution(
      final StatedumpObjectKey key) {
    return resolutions.get(key);
  }

  /**
   * @param key Key
   * @param password PWD
   */
  public void addPassword(final StatedumpObjectKey key, final String password) {
    passwords.put(key, password);
  }

  /**
   * Internal method, but EJBs can't call package internal methods, so it must
   * be public.
   *
   * @param key key
   * @return pwd
   */
  public String ulookupPassword(final StatedumpObjectKey key) {
    return passwords.get(key);
  }

  /**
   * Adds a translation of a CA Subject DN (and CA Id, since it's calculated
   * from the Subject DN).
   *
   * @param fromId CA Id from CA while it still has the old name.
   * @param toId New CA Id
   * @param toSubjectDN CA Subject DN of new CA
   */
  public void addCASubjectDNChange(
      final int fromId, final int toId, final String toSubjectDN) {
    caIdChanges.add(new StatedumpCAIdChange(fromId, toId, toSubjectDN));
  }

  /**
   * Internal method, but EJBs can't call package internal methods, so it must
   * be public.
   *
   * @return list
   */
  public List<StatedumpCAIdChange> ugetCASubjectDNChanges() {
    return caIdChanges;
  }

  /**
   * Adds a translation of a CryptoToken Id.
   *
   * @param fromId ID
   * @param toId ID
   */
  public void addCryptoTokenIdChange(final int fromId, final int toId) {
    cryptoTokenIdChanges.put(fromId, toId);
  }

  /**
   * Internal method, but EJBs can't call package internal methods, so it must
   * be public.
   *
   * @return map
   */
  public Map<Integer, Integer> ugetCryptoTokenIdChanges() {
    return cryptoTokenIdChanges;
  }

  /**
   * Adds an override of a field. See StatedumpFieldOverrider.
   *
   * @param key key
   * @param type type
   * @param value value
   */
  public void addOverride(
      final String[] key,
      final StatedumpOverride.Type type,
      final Object value) {
    final String keyStr = StringUtils.join(key, '.');
    List<StatedumpOverride> list = overrides.get(keyStr);
    if (list == null) {
      list = new ArrayList<>();
      overrides.put(keyStr, list);
    }
    list.add(new StatedumpOverride(type, value));
  }

  /**
   * Internal method, but EJBs can't call package internal methods, so it must
   * be public.
   *
   * @param key key
   * @return list
   */
  public List<StatedumpOverride> ugetOverrides(final String[] key) {
    final String keyStr = StringUtils.join(key, '.');
    return overrides.get(keyStr);
  }
}
