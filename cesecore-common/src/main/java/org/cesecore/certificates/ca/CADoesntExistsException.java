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

import javax.xml.ws.WebFault;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * An exception thrown when someone tries to get/edit/save a CA that does not
 * exist.
 *
 * <p>Should really be called CADoesntExistsException, but changing this name
 * have ripple effects down to the WS-API, and it's not worth breaking any
 * backwards compatibility to change this name.
 *
 * @version $Id: CADoesntExistsException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
@WebFault
public class CADoesntExistsException extends CesecoreException {

  private static final long serialVersionUID = 1542504214401684378L;

  /**
   * Creates a new instance of <code>CADoesntExistsException</code> without
   * detail message.
   */
  public CADoesntExistsException() {
    super(ErrorCode.CA_NOT_EXISTS);
  }

  /**
   * Constructs an instance of <code>CAProfileDoesntExistsException</code> with
   * the specified detail message.
   *
   * @param msg the detail message.
   */
  public CADoesntExistsException(final String msg) {
    super(ErrorCode.CA_NOT_EXISTS, msg);
  }

  /**
   * Constructs an instance of <code>CAProfileDoesntExistsException</code> with
   * the specified cause.
   *
   * @param e the detail message.
   */
  public CADoesntExistsException(final Exception e) {
    super(e);
  }
}
