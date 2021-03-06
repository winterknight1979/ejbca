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
package org.cesecore.roles;

/**
 * Thrown when trying to access a role which doesn't exist.
 *
 * @version $Id: RoleNotFoundException.java 17625 2013-09-20 07:12:06Z netmackan
 *     $
 */
public class RoleNotFoundException extends Exception {

  private static final long serialVersionUID = 3905530918766837916L;

  /** Null.
   */
  public RoleNotFoundException() {
    super();
  }

  /**
   * @param arg0 message
   * @param arg1 cause
   */
  public RoleNotFoundException(final String arg0, final Throwable arg1) {
    super(arg0, arg1);
  }

  /**
   * @param arg0 Message.
   */
  public RoleNotFoundException(final String arg0) {
    super(arg0);
  }

  /**
   * @param arg0 cause
   */
  public RoleNotFoundException(final Throwable arg0) {
    super(arg0);
  }
}
