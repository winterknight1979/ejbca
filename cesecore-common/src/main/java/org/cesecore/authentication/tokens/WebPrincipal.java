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
package org.cesecore.authentication.tokens;

import java.io.Serializable;
import java.security.Principal;

/**
 * Represents any type of web user, can be public web or a servlet.
 *
 * @version $Id: WebPrincipal.java 22811 2016-02-15 16:48:23Z samuellb $
 */
public class WebPrincipal implements Principal, Serializable {

  private static final long serialVersionUID = 1L;
  /** Module. */
  private final String moduleName;
  /** Client IP. */
  private final String clientIPAddress;

  /**
   * @param aModuleName Arbitrary identifier of the page or module, e.g.
   *     "AutoEnrollServlet"
   * @param theClientIPAddress Remote IP address
   */
  public WebPrincipal(
      final String aModuleName, final String theClientIPAddress) {
    this.clientIPAddress = theClientIPAddress;
    this.moduleName = aModuleName;
  }

  @Override
  public String getName() {
    return clientIPAddress;
  }

  @Override
  public String toString() {
    return moduleName + ": " + clientIPAddress;
  }

  /** @return module */
  public String getModuleName() {
    return moduleName;
  }

  /** @return IP address */
  public String getClientIPAddress() {
    return clientIPAddress;
  }
}
