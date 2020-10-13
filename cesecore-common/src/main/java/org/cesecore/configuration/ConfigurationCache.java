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
package org.cesecore.configuration;

import java.util.HashMap;
import java.util.Properties;

/**
 * Marker interface for classes that want to be treated as contents of the
 * Global Configuration Cache.
 *
 * @version $Id: ConfigurationCache.java 19988 2014-10-16 13:37:56Z mikekushner
 *     $
 */
public interface ConfigurationCache {

    /**
     * @return ID
     */
  String getConfigId();

  /** Clear. */
  void clearCache();

  /** Save. */
  void saveData();

  /**
   * @return bool */
  boolean needsUpdate();

  /**
   * @return config
   */
  ConfigurationBase getConfiguration();

  /**
   * @param data data
   * @return config
   */
  @SuppressWarnings("rawtypes")
  ConfigurationBase getConfiguration(HashMap data);

  /**
   * @return config
   */
  ConfigurationBase getNewConfiguration();

  /**
   * @param configuration config
   */
  void updateConfiguration(ConfigurationBase configuration);

  /**
   * @return properties
   */
  Properties getAllProperties();
}
