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

package org.cesecore.authorization.user;

import java.io.Serializable;

/**
 * Interface for AccessUserAspectData.
 *
 * @version $Id: AccessUserAspect.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public interface AccessUserAspect extends Serializable {

  /** @return match */
  int getMatchWith();

  /**
   * Set match.
   *
   * @param matchWith Match
   */
  void setMatchWith(Integer matchWith);

  /** @return Type. */
  int getMatchType();

  /**
   * Set type.
   *
   * @param matchType Type
   */
  void setMatchType(Integer matchType);

  /**
   * Set match as type.
   *
   * @param matchType type
   */
  void setMatchTypeAsValue(AccessMatchType matchType);

  /**
   * Get match as type.
   *
   * @return type
   */
  AccessMatchType getMatchTypeAsType();

  /** @return match value */
  String getMatchValue();

  /**
   * Set match value.
   *
   * @param matchValue Value
   */
  void setMatchValue(String matchValue);

  /** @return CA ID */
  Integer getCaId();

  /**
   * Set CA ID.
   *
   * @param caId ID
   */
  void setCaId(Integer caId);

  /** @return token type */
  String getTokenType();

  /**
   * Set token type.
   *
   * @param tokenType Type
   */
  void setTokenType(String tokenType);
}
