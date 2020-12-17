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

package org.ejbca.config;

import org.cesecore.config.ConfigurationHolder;

/**
 * Parses configuration bundled in conf/va.properties both for the internal and
 * external VA.
 *
 * @version $Id: VAConfiguration.java 22139 2015-11-03 10:41:56Z mikekushner $
 */
public final class VAConfiguration {
    /** Param. */
  private static final String S_HASH_ALIAS_PREFIX = "va.sKIDHash.alias.";

  private VAConfiguration() { }

  /**
   * @param name Name
   * @return Hash
   */
  public static String sKIDHashFromName(final String name) {
    return ConfigurationHolder.getString(S_HASH_ALIAS_PREFIX + name);
  }

  /**
   * @param name Name
   * @param hash Hash
   * @return Bool
   */
  public static boolean sKIDHashSetAlias(final String name, final String hash) {
    return ConfigurationHolder.updateConfiguration(
        S_HASH_ALIAS_PREFIX + name, hash);
  }
}
