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

package org.ejbca.core.ejb.config;

import java.util.HashMap;
import java.util.Properties;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;
import org.ejbca.config.AvailableProtocolsConfiguration;



/**
 * Class Holding cache variable for available protocol configuration.
 * Needed because EJB spec does not allow volatile, non-final fields in session beans.
 * 
 * @version $Id: AvailableProtocolsConfigurationCache.java 26987 2017-11-03 08:01:00Z henriks $
 *
 */
public class AvailableProtocolsConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the protocol configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile ConfigurationBase cache = null;
    /** help variable used to control that updates are not performed to often. */
    private volatile long lastUpdateTime = -1;  

    @Override
    public boolean needsUpdate() {
        return cache==null || lastUpdateTime + CesecoreConfiguration.getCacheGlobalConfigurationTime() < System.currentTimeMillis();
    }

    @Override
    public void clearCache() {
        cache = null;
    }

    @Override
    public String getConfigId() {
        if (cache==null) {
            return getNewConfiguration().getConfigurationId();
        }
        return cache.getConfigurationId();
    }

    @Override
    public void saveData() {
       cache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return cache;
    }
    
    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(final HashMap data) {
        final ConfigurationBase returnval = getNewConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        cache = configuration;
        lastUpdateTime = System.currentTimeMillis();
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new AvailableProtocolsConfiguration();      
    }

    @Override
    public Properties getAllProperties() {
        return null;
    }

}
