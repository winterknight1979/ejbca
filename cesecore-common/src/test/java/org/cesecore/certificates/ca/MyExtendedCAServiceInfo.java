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
package org.cesecore.certificates.ca;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;

/**
 * @version $Id: MyExtendedCAServiceInfo.java 22147 2015-11-03 16:24:00Z
 *     mikekushner $
 */
public class MyExtendedCAServiceInfo extends ExtendedCAServiceInfo {

  private static final long serialVersionUID = 1L;

  /**
   * Type.
   */
  public static final int TYPE = 4711;

  /**
   * @param status status
   */
  public MyExtendedCAServiceInfo(final int status) {
    super(status);
  }

  @Override
  public String getImplClass() {
    return "org.cesecore.certificates.ca.MyExtendedCAService";
  }

  @Override
  public int getType() {
    return MyExtendedCAServiceInfo.TYPE;
  }
}
