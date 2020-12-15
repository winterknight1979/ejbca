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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Results of a dry-run of a statedump import.
 *
 * @version $Id: StatedumpImportResult.java 22489 2015-12-18 18:18:42Z samuellb
 *     $
 */
public final class StatedumpImportResult implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final List<StatedumpObjectKey> conflicts = new ArrayList<>();
  /** Param. */
  private final List<StatedumpObjectKey> passwordsNeeded = new ArrayList<>();
  /** Param. */
  private final Set<StatedumpObjectKey> existingNames = new HashSet<>();
  /** Param. */
  private final Set<StatedumpObjectKey> existingIds = new HashSet<>();
  /** Param. */
  private final List<String> notices = new ArrayList<>();
  /** Param. */
  private long objectCount = 0;

  /**
   * Returns a list of items that conflict with an existing item, because it has
   * the same name or id.
   *
   * @return list
   */
  public List<StatedumpObjectKey> getConflicts() {
    return Collections.unmodifiableList(conflicts);
  }

  /**
   * Internal method, used during statedump imports. Can't be package internal
   * since it's called from the bean
   *
   * @param key key
   */
  public void uaddConflict(final StatedumpObjectKey key) {
    conflicts.add(key);
  }

  /**
   * Returns a list of items that might need a password when imported (e.g.
   * crypto tokens and end entities)
   *
   * @return list
   */
  public List<StatedumpObjectKey> getPasswordsNeeded() {
    return Collections.unmodifiableList(passwordsNeeded);
  }

  /**
   * Internal method, used during statedump imports. Can't be package internal
   * since it's called from the bean
   *
   * @param key key
   */
  public void uaddPasswordNeeded(final StatedumpObjectKey key) {
    passwordsNeeded.add(key);
  }

  /**
   * Check whether the id of an object is already in use.
   *
   * @param key key
   * @return bool
   */
  public boolean hasExistingId(final StatedumpObjectKey key) {
    return existingIds.contains(key);
  }

  /**
   * Internal method, used during statedump imports. Can't be package internal
   * since it's called from the bean
   *
   * @param key key
   */
  public void uaddExistingId(final StatedumpObjectKey key) {
    existingIds.add(key);
  }

  /**
   * Check whether the name of an object is already in use.
   *
   * @param key key
   * @return bool
   */
  public boolean hasExistingName(final StatedumpObjectKey key) {
    return existingNames.contains(key);
  }

  /**
   * Internal method, used during statedump imports. Can't be package internal
   * since it's called from the bean
   *
   * @param key key
   */
  public void uaddExistingName(final StatedumpObjectKey key) {
    existingNames.add(key);
  }

  /**
   * @return count
   */
  public long getObjectCount() {
    return objectCount;
  }

  /**
   * Internal method, used during statedump imports. Can't be package internal
   * since it's called from the bean.
   */
  public void uaddToObjectCount() {
    objectCount += 1;
  }

  /**
   * Internal method, used during statedump imports. Can't be package internal
   * since it's called from the bean
   * @param msg message
   */
  public void uaddNotice(final String msg) {
    notices.add(msg);
  }

  /**
   * Returns a list of info log messages that where generated during the import.
   *
   * @return list
   */
  public List<String> getNotices() {
    return notices;
  }
}
