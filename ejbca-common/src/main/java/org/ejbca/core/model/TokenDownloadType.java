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

package org.ejbca.core.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Representation of token download types.
 *
 * @version $Id: TokenDownloadType.java 29210 2018-06-13 10:14:03Z henriks $
 */
public enum TokenDownloadType {
    /** PEM. */
  PEM(1),
  /** Full PEM. */
  PEM_FULL_CHAIN(2),
  /** PKCS 7. */
  PKCS7(3),
  /** PKCS 12. */
  P12(4),
  /** JKS. */
  JKS(5),
  /** DER. */
  DER(6);

    /** Value. */
  private int value;
  /** Map. */
  private static final Map<String, Integer> NAME_ID_LOOKUP_MAP =
      new HashMap<String, Integer>();
  /** Map. */
  private static final Map<Integer, String> ID_NAME_LOOKUP_MAP =
      new HashMap<Integer, String>();

  static {
    for (TokenDownloadType tokenDownloadType : TokenDownloadType.values()) {
      NAME_ID_LOOKUP_MAP.put(tokenDownloadType.name(), tokenDownloadType.value);
      ID_NAME_LOOKUP_MAP.put(tokenDownloadType.value, tokenDownloadType.name());
    }
  }

  /**
   * @param avalue value
   */
  TokenDownloadType(final int avalue) {
    this.value = avalue;
  }

  /**
   * @return value
   */
  public int getValue() {
    return value;
  }

  /**
   * @param tokenTypeName TokenDownloadType Enum name
   * @return Id represented by input Enum name or null if non-existent
   */
  public static Integer getIdFromName(final String tokenTypeName) {
    return NAME_ID_LOOKUP_MAP.get(tokenTypeName);
  }

  /**
   * @param id TokenDownloadType Enum Id
   * @return String representation of the Enum Id input or null of non-existent
   */
  public static String getNameFromId(final int id) {
    return ID_NAME_LOOKUP_MAP.get(id);
  }
}
