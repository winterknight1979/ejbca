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
package org.ejbca.ui.web.admin.services.servicetypes;

/**
 * Class representing an Action Type, should be registered in the
 * ServiceTypesManager. Should be inherited by all action managed beans.
 *
 * @version $Id: ActionType.java 19902 2014-09-30 14:32:24Z anatom $
 */
public abstract class ActionType extends ServiceType {

  private static final long serialVersionUID = -7411725269781465619L;

  /**
   * @param subViewPage Page
   * @param name NAme
   * @param translatable bool
   */
  public ActionType(
      final String subViewPage, final String name, final boolean translatable) {
    super(subViewPage, name, translatable);
  }
}
