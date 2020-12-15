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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.Map;

/**
 * Contains information from {@link
 * org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry}.
 *
 * @version $Id: RaRoleMemberTokenTypeInfo.java 25397 2017-03-06 20:19:36Z
 *     samuellb $
 */
public final class RaRoleMemberTokenTypeInfo implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final Map<String, Integer> matchKeys;
  /** Param. */
  private final String defaultMatchKey;
  /** Param. */
  private final boolean issuedByCA;
  /** Param. */
  private final boolean hasMatchValue;
  /** Param. */
  private final int matchOperator;

  /**
   * @param thematchKeys Keys
   * @param adefaultMatchKey Default key
   * @param isissuedByCA Bool
   * @param ahasMatchValue VBool
   * @param amatchOperator Operator
   */
  public RaRoleMemberTokenTypeInfo(
      final Map<String, Integer> thematchKeys,
      final String adefaultMatchKey,
      final boolean isissuedByCA,
      final boolean ahasMatchValue,
      final int amatchOperator) {
    this.matchKeys = thematchKeys;
    this.defaultMatchKey = adefaultMatchKey;
    this.issuedByCA = isissuedByCA;
    this.hasMatchValue = ahasMatchValue;
    this.matchOperator = amatchOperator;
  }

  /**
   * @return map
   */
  public Map<String, Integer> getMatchKeysMap() {
    return matchKeys;
  }

  /**
   * @return keys
   */
  public String getDefaultMatchKey() {
    return defaultMatchKey;
  }

  /**
   * @return bool
   */
  public boolean isIssuedByCA() {
    return issuedByCA;
  }

  /**
   * @return bool
   */
  public boolean getHasMatchValue() {
    return hasMatchValue;
  }

  /**
   * @return Operator
   */
  public int getMatchOperator() {
    return matchOperator;
  }

  /**
   * @param other type to merge
   */
  public void merge(final RaRoleMemberTokenTypeInfo other) {
    matchKeys.putAll(other.matchKeys);
    // the default match key shouldn't differ
  }
}
