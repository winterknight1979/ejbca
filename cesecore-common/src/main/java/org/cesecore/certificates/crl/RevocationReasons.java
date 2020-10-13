/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.crl;

import java.util.HashMap;
import java.util.Map;

/**
 * An enum for revocation reasons, with a numerical database value and a String
 * value for CLI applications.
 *
 * <p>Based on RFC 5280 Section 5.3.1
 *
 * @version $Id: RevocationReasons.java 28485 2018-03-14 12:59:48Z anatom $
 */
public enum RevocationReasons {
    /** Not revoked. */
  NOT_REVOKED(-1, "NOT_REVOKED", "The Certificate Is Not Revoked"),
  /** Unspecified. */
  UNSPECIFIED(0, "UNSPECIFIED", "Unspecified"),
  /** Key compromise. */
  KEYCOMPROMISE(1, "KEY_COMPROMISE", "Key Compromise"),
  /** CA compromise. */
  CACOMPROMISE(2, "CA_COMPROMISE", "CA Compromise"),
  /** Changed. */
  AFFILIATIONCHANGED(3, "AFFILIATION_CHANGED", "Affiliation Changed"),
  /** Superseded. */
  SUPERSEDED(4, "SUPERSEDED", "Superseded"),
  /** Ceased operating. */
  CESSATIONOFOPERATION(5, "CESSATION_OF_OPERATION", "Cessation of Operation"),
  /** Hold. */
  CERTIFICATEHOLD(6, "CERTIFICATE_HOLD", "Certificate Hold"),
  /** Remove. */
  REMOVEFROMCRL(8, "REMOVE_FROM_CRL", "Remove from CRL"),
  /** Withdrawn. */
  PRIVILEGESWITHDRAWN(9, "PRIVILEGES_WITHDRAWN", "Privileges Withdrawn"),
  /** Authority compromise. */
  AACOMPROMISE(10, "AA_COMPROMISE", "AA Compromise");

    /** ID. */
  private final int databaseValue;
  /** String. */
  private final String stringValue;
  /** Readable. */
  private final String humanReadable;

  /** DV values. */
  private static final Map<Integer, RevocationReasons> DB_LOOKUP_MAP =
      new HashMap<Integer, RevocationReasons>();
  /** CLI values. */
  private static final Map<String, RevocationReasons> CLI_LOOKUP_MAP =
      new HashMap<String, RevocationReasons>();

  static {
    for (RevocationReasons reason : RevocationReasons.values()) {
      DB_LOOKUP_MAP.put(reason.getDatabaseValue(), reason);
      CLI_LOOKUP_MAP.put(reason.getStringValue(), reason);
    }
  }

  RevocationReasons(
      final int aDatabaseValue,
      final String aStringValue, final String aHumanReadable) {
    this.databaseValue = aDatabaseValue;
    this.stringValue = aStringValue;
    this.humanReadable = aHumanReadable;
  }

  /**
   * @return value from DB
   */
  public int getDatabaseValue() {
    return databaseValue;
  }

  /**
   * @return Human-readable value
   */
  public String getHumanReadable() {
    return humanReadable;
  }

  /**
   * @return Value as string
   */
  public String getStringValue() {
    return stringValue;
  }

  /**
   * @param databaseValue the database value
   * @return the relevant RevocationReasons object, null if none found.
   */
  public static RevocationReasons getFromDatabaseValue(
          final int databaseValue) {
    return DB_LOOKUP_MAP.get(databaseValue);
  }

  /**
   * @param cliValue the database value
   * @return the relevant RevocationReasons object, null if none found.
   */
  public static RevocationReasons getFromCliValue(final  String cliValue) {
    if (cliValue == null) {
      return null;
    }
    return CLI_LOOKUP_MAP.get(cliValue);
  }
}
