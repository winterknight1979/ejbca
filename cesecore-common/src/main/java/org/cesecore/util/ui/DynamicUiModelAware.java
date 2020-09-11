/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.ui;

/**
 * Interface type for domain objects (or other objects) with dynamic UI model.
 * 
 * @version $Id: DynamicUiModelAware.java 28531 2018-03-21 06:57:37Z mikekushner $
 *
 */
public interface DynamicUiModelAware {

    /**
     * Initializes the dynamic UI model for this domain object.
     */
    void initDynamicUiModel();
    
    /**
     * Gets the dynamic UI model.
     * @return the object.
     */
    DynamicUiModel getDynamicUiModel();
}
