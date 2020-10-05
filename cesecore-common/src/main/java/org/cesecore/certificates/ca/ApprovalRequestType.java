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
package org.cesecore.certificates.ca;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a type of approval request.
 *
 * @version $Id: ApprovalRequestType.java 29813 2018-09-05 15:01:59Z bastianf $
 */
public enum ApprovalRequestType {
  /** Add. */
  ADDEDITENDENTITY(1, "APPROVEADDEDITENDENTITY"),
  /** Recover. */
  KEYRECOVER(2, "APPROVEKEYRECOVER"),
  /** Revoke. */
  REVOCATION(3, "APPROVEREVOCATION"),
  /** Activate. */
  ACTIVATECA(4, "APPROVEACTIVATECA");

  /** Value. */
  private final int integerValue;
  /** Language. */
  private final String languageString;
  /** Map of request types. */
  private static final Map<Integer, ApprovalRequestType> REVERSE_LOOKUP_MAP =
      new HashMap<>();

  static {
    for (ApprovalRequestType approvalRequestType
        : ApprovalRequestType.values()) {
      REVERSE_LOOKUP_MAP.put(
          approvalRequestType.getIntegerValue(), approvalRequestType);
    }
  }

  /**
   * Constructor.
   *
   * @param anIntegerValue Value
   * @param aLanguageString Language
   */
  ApprovalRequestType(final int anIntegerValue, final String aLanguageString) {
    this.integerValue = anIntegerValue;
    this.languageString = aLanguageString;
  }

  /** @return value */
  public int getIntegerValue() {
    return integerValue;
  }

  /** @return language */
  public String getLanguageString() {
    return languageString;
  }

  /**
   * Get request type.
   *
   * @param integerValue Value.
   * @return Type
   */
  public static ApprovalRequestType getFromIntegerValue(
      final int integerValue) {
    return REVERSE_LOOKUP_MAP.get(integerValue);
  }
}
