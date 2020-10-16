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

package org.ejbca.ui.cli;

/**
 * Exception throws when illegal parameters are issued for an Admin Command
 * (IadminCommand)
 *
 * @version $Id: IllegalAdminCommandException.java 19901 2014-09-30 14:29:38Z
 *     anatom $
 */
public class IllegalAdminCommandException
    extends org.ejbca.core.EjbcaException {
  private static final long serialVersionUID = -5604111464417974618L;

  /**
   * Creates a new instance of IllegalAdminCommandException
   *
   * @param message error message
   */
  public IllegalAdminCommandException(final String message) {
    super(message);
  }
}
