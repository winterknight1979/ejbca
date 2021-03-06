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
package org.cesecore.keys.token;

import java.util.List;
import java.util.Map;
import javax.ejb.Local;

/**
 * @version $Id: CryptoTokenSessionLocal.java 25377 2017-03-02 16:46:52Z jeklund
 *     $
 */
@Local
public interface CryptoTokenSessionLocal extends CryptoTokenSession {

  /**
   * @param cryptoTokenId ID
   * @return the specified CryptoToken or null if it does not exis. Throws
   *     RuntimeException if allow.nonexisting.slot=false (default) and a
   *     PKCS#11 slot does not exist.
   */
  CryptoToken getCryptoToken(int cryptoTokenId);

  /**
   * Add the specified CryptoToken to the database and return the id used to
   * store it.
   *
   * @param cryptoToken Token
   * @return Merged token
   * @throws CryptoTokenNameInUseException if nme in use
   */
  int mergeCryptoToken(CryptoToken cryptoToken)
      throws CryptoTokenNameInUseException;

  /**
   * Remove the specified CryptoToken from the database.
   *
   * @param cryptoTokenId the id of the crypto token that should be removed
   * @return true if crypto token exists and is deleted, false if crypto token
   *     with given id does not exist
   */
  boolean removeCryptoToken(int cryptoTokenId);

  /** @return a list of all CryptoToken identifiers in the database. */
  List<Integer> getCryptoTokenIds();

  /**
   * @return a list of all CryptoToken identifiers and corresponding human
   *     readable name in the database.
   */
  Map<Integer, String> getCryptoTokenIdToNameMap();

  /** @return a (copy of a) name to id lookup table */
  Map<String, Integer> getCachedNameToIdMap();

  /** Clears the CryptoToken cache. */
  void flushCache();

  /**
   * Clears the CryptoToken cache except for the cache entries specified in
   * excludeIDs.
   *
   * @param excludeIDs IDs to exclude
   */
  void flushExcludingIDs(List<Integer> excludeIDs);

  /**
   * @param cryptoTokenName Name
   * @param cryptoTokenId ID
   * @return true if the specified name is used by exactly one CryptoToken and
   *     that cryptoToken has the same id (checks the database, not the cache)
   */
  boolean isCryptoTokenNameUsedByIdOnly(
      String cryptoTokenName, int cryptoTokenId);
}
