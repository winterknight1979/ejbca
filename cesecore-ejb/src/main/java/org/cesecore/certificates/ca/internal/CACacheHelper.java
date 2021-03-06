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
package org.cesecore.certificates.ca.internal;

import java.util.HashMap;
import java.util.Map;

/**
 * Caching of CA SubjectDN hashes that maps to real CAId.
 *
 * <p>In some border cases the content of the CA certificate's subjectDN is not
 * what was used to generate the CA Id and therefore we often want to lookup
 * this "real" value.
 *
 * @version $Id: CACacheHelper.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public final class CACacheHelper {

  /** Caching of CA IDs with CA cert DN hash as ID. */
  protected static volatile Map<Integer, Integer> caIdToCaCertHash =
      new HashMap<Integer, Integer>();

  /** null constructor. */
  private CACacheHelper() {
    // Do nothing
  }

  /**
   * @param caid ID
   * @return Hash
   */
  public static Integer getCaCertHash(final Integer caid) {
    return caIdToCaCertHash.get(Integer.valueOf(caid));
  }

  /**
   * @param caid ID
   * @param caCertHash Hash
   */
  public static void putCaCertHash(
      final Integer caid, final Integer caCertHash) {
    caIdToCaCertHash.put(caid, caCertHash);
  }
}
