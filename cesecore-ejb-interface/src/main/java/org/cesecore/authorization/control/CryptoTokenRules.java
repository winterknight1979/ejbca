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
package org.cesecore.authorization.control;

/**
 * CryptoToken related access rules.
 *
 * @version $Id: CryptoTokenRules.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public enum CryptoTokenRules {
    /** Base. */
  BASE("/cryptotoken"),
  /** Modify. */
  MODIFY_CRYPTOTOKEN(BASE.resource() + "/modify"),
  /** Delete. */
  DELETE_CRYPTOTOKEN(BASE.resource() + "/delete"),
  /** View. */
  VIEW(BASE.resource() + "/view"),
  /** Use. */
  USE(BASE.resource() + "/use"),
  /** Activate. */
  ACTIVATE(BASE.resource() + "/activate"),
  /** Deactivate. */
  DEACTIVATE(BASE.resource() + "/deactivate"),
  /** Keys. */
  GENERATE_KEYS(BASE.resource() + "/keys/generate"),
  /** Keys. */
  REMOVE_KEYS(BASE.resource() + "/keys/remove"),
  /** Keys. */
  TEST_KEYS(BASE.resource() + "/keys/test");

  /** Tesource. */
  private final String resource;

  /**
   * @param aResource resource
   */
  CryptoTokenRules(final String aResource) {
    this.resource = aResource;
  }

  /**
   * @return resource
   */
  public String resource() {
    return this.resource;
  }

  @Override
  public String toString() {
    return this.resource;
  }
}
