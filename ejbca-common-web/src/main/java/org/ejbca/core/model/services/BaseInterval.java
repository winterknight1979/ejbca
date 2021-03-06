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
package org.ejbca.core.model.services;

import java.util.Properties;

/**
 * Help base class that manages that implements the init method of the interface
 * and manages the properties.
 *
 * @author Philip Vendil 2006 sep 27
 * @version $Id: BaseInterval.java 22139 2015-11-03 10:41:56Z mikekushner $
 */
public abstract class BaseInterval implements IInterval {

      /** Param. */
  protected Properties properties = null;
  /** Param. */
  protected String serviceName = null;
  /** @see org.ejbca.core.model.services.IAction#init(Properties, String) */
  @Override
  public void init(final Properties theproperties, final String aserviceName) {
    this.properties = theproperties;
    this.serviceName = aserviceName;
  }
}
