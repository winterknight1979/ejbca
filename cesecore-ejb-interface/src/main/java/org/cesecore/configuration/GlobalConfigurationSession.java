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
package org.cesecore.configuration;

import java.util.Properties;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Session bean to handle global configuration and such.
 *
 * @version $Id: GlobalConfigurationSession.java 23544 2016-05-25 11:24:19Z
 *     anatom $
 */
public interface GlobalConfigurationSession {

  /**
   * Retrieves the cached GlobalConfiguration. This cache is updated from
   * persistence either by the time specified by
   * MIN_TIME_BETWEEN_GLOBCONF_UPDATES or when {@link
   * #flushConfigurationCache(String)} is executed. This method should be used
   * in all cases where a quick response isn't necessary, otherwise use {@link
   * #flushConfigurationCache(String)}.
   *
   * @param configID ID
   * @return the cached GlobalConfiguration value.
   */
  ConfigurationBase getCachedConfiguration(String configID);

  /**
   * Clear and load global configuration cache.
   *
   * @param configID ID
   */
  void flushConfigurationCache(String configID);

  /**
   * @param admin Admin
   * @param configID ID
   * @return all currently used properties (configured in conf/*.properties.
   *     Required admin access to '/' to dump these properties.
   * @throws AuthorizationDeniedException if privileges are insufficient
   */
  Properties getAllProperties(AuthenticationToken admin, String configID)
      throws AuthorizationDeniedException;

  /**
   * Saves the GlobalConfiguration.
   *
   * @param admin an authentication token
   * @param conf the new Configuration
   * @throws AuthorizationDeniedException if admin was not authorized to edit
   *     the specific configuration
   */
  void saveConfiguration(AuthenticationToken admin, ConfigurationBase conf)
      throws AuthorizationDeniedException;
}
