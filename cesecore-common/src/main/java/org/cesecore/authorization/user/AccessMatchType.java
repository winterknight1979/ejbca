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

import java.util.HashMap;
import java.util.Map;

/** @version $Id: AccessMatchType.java 26811 2017-10-15 03:29:26Z anatom $ */
public enum AccessMatchType {

  /** Unused. */
  TYPE_UNUSED(0),
  /** Case sensitive. */
  TYPE_EQUALCASE(1000),
  /**
   * Case insensitive. Can be used for textual match values, e.g. a Common Name.
   * Do <b>NOT</b> use with serial numbers (a change since 6.8.0)
   */
  TYPE_EQUALCASEINS(1001),
  /** install. */
  @Deprecated
  TYPE_NOT_EQUALCASE(1002),
  /** Install. */
  @Deprecated
  TYPE_NOT_EQUALCASEINS(1003),
  /** None. */
  @Deprecated
  TYPE_NONE(1999),
  /**
   * Type 2000-2005 are old types used from before EJBCA 4, we must expect to
   * find these in the database in old installations, even though we don't want
   * to use them. These have no meaning whatsoever in newer installations of
   * EJBCA, and can safely be removed from the database if found (unless we ne
   * ed to run an old installation in parallel).
   *
   * <p>Public Web User
   *
   * @deprecated since v4
   */
  @Deprecated
  SPECIALADMIN_PUBLICWEBUSER(2000),
  /**
   * CA command admin.
   *
   * @deprecated since v4
   */
  @Deprecated
  SPECIALADMIN_CACOMMANDLINEADMIN(2001),
  /**
   * RA admin.
   *
   * @deprecated since v4
   */
  @Deprecated
  SPECIALADMIN_RAADMIN(2002),
  /**
   * BAtch Admin.
   *
   * @deprecated since v4
   */
  @Deprecated
  SPECIALADMIN_BATCHCOMMANDLINEADMIN(2003),
  /**
   * Internal user.
   *
   * @deprecated since v4
   */
  @Deprecated
  SPECIALADMIN_INTERNALUSER(2004),
  /**
   * No user.
   *
   * @deprecated since v4
   */
  @Deprecated
  SPECIALADMIN_NOUSER(2005);

  /** ID. */
  private int numericValue;
  /** Map of IDs to match types. */
  private static Map<Integer, AccessMatchType> databaseLookup;
  /** Map of names to match types. */
  private static Map<String, AccessMatchType> nameLookup;

  /**
   * Constructor.
   *
   * @param aNumericValue ID
   */
  AccessMatchType(final int aNumericValue) {
    this.numericValue = aNumericValue;
  }

  /** @return ID */
  public int getNumericValue() {
    return numericValue;
  }

  /**
   * Get match type by ID.
   *
   * @param aNumericValue Value
   * @return Type
   */
  public static AccessMatchType matchFromDatabase(final int aNumericValue) {
    return databaseLookup.get(aNumericValue);
  }

  /**
   * Get match type by name.
   *
   * @param name Name
   * @return Type
   */
  public static AccessMatchType matchFromName(final String name) {
    return nameLookup.get(name);
  }

  static {
    databaseLookup = new HashMap<Integer, AccessMatchType>();
    nameLookup = new HashMap<String, AccessMatchType>();
    for (AccessMatchType accessMatchType : AccessMatchType.values()) {
      databaseLookup.put(accessMatchType.numericValue, accessMatchType);
      nameLookup.put(accessMatchType.name(), accessMatchType);
    }
  }
}
