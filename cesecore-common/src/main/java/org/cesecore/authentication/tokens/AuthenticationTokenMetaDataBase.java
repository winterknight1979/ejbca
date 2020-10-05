/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authentication.tokens;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * Common functions for meta data definitions for AuthenticationTokens that
 * should be auto-detected via ServiceLoader of AuthenticationTokenMetaData.
 *
 * @version $Id: AuthenticationTokenMetaDataBase.java 25431 2017-03-09 16:52:15Z
 *     mikekushner $
 */
public abstract class AuthenticationTokenMetaDataBase
    implements AuthenticationTokenMetaData {

  /** Type of token. */
  private final String tokenType;
  /** List of matching values. */
  private final List<? extends AccessMatchValue> accessMatchValues;
  /** Allow configuration. */
  private final boolean userConfigurable;
  /** Map of match IDs. */
  private final Map<Integer, AccessMatchValue> accessMatchValueIdMap =
      new HashMap<>();
  /** Map of matching values. */
  private final Map<String, AccessMatchValue> accessMatchValueNameMap =
      new HashMap<>();
  /** Default match value. */
  private final AccessMatchValue defaultAccessMatchValue;

  /**
   * Constructor.
   *
   * @param theTokenType Type of token
   * @param theAccessMatchValues Values to match
   * @param isUserConfigurable Allow config
   */
  protected AuthenticationTokenMetaDataBase(
      final String theTokenType,
      final List<? extends AccessMatchValue> theAccessMatchValues,
      final boolean isUserConfigurable) {
    this.tokenType = theTokenType;
    this.accessMatchValues = theAccessMatchValues;
    this.userConfigurable = isUserConfigurable;
    AccessMatchValue theDefaultAccessMatchValue = null;
    for (final AccessMatchValue accessMatchValue : getAccessMatchValues()) {
      accessMatchValueIdMap.put(
          accessMatchValue.getNumericValue(), accessMatchValue);
      accessMatchValueNameMap.put(accessMatchValue.name(), accessMatchValue);
      if (theDefaultAccessMatchValue == null
          || accessMatchValue.isDefaultValue()) {
        theDefaultAccessMatchValue = accessMatchValue;
      }
    }
    this.defaultAccessMatchValue = theDefaultAccessMatchValue;
  }

  @Override
  public String getTokenType() {
    return tokenType;
  }

  @Override
  public boolean isUserConfigurable() {
    return userConfigurable;
  }

  @Override
  public List<? extends AccessMatchValue> getAccessMatchValues() {
    return accessMatchValues;
  }

  @Override
  public Map<Integer, AccessMatchValue> getAccessMatchValueIdMap() {
    return accessMatchValueIdMap;
  }

  @Override
  public Map<String, AccessMatchValue> getAccessMatchValueNameMap() {
    return accessMatchValueNameMap;
  }

  @Override
  public AccessMatchValue getAccessMatchValueDefault() {
    return defaultAccessMatchValue;
  }

  @Override
  public boolean isSuperToken() {
    // Legacy pattern: When default value is assigned number
    // Integer.MAX_VALUE, the AuthenticationToken will grant
    // any access rule...
    return getAccessMatchValueDefault().getNumericValue() == Integer.MAX_VALUE;
  }
}
