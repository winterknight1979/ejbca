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

package org.ejbca.ui.web.admin.rainterface;

import java.util.HashMap;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;

/**
 * A class used to improve performance by proxying end entity profileid to
 * profilename mappings by minimizing the number of needed lockups over rmi.
 *
 * @author TomSelleck
 * @version $Id: EndEntityProfileNameProxy.java 28844 2018-05-04 08:31:02Z
 *     samuellb $
 */
public class EndEntityProfileNameProxy implements java.io.Serializable {

  private static final long serialVersionUID = 7866894775948690845L;
  /** Param. */
  private final HashMap<Integer, String> profilenamestore;
  /** Param. */
  private final EndEntityProfileSession endEntityProfileSession;

  /**
   * Creates a new instance of ProfileNameProxy.
   *
   * @param anendEntityProfileSession Session
   */
  public EndEntityProfileNameProxy(
      final EndEntityProfileSession anendEntityProfileSession) {
    // Get the RaAdminSession instance.
    this.endEntityProfileSession = anendEntityProfileSession;

    profilenamestore = new HashMap<>();
  }

  /**
   * Method that first tries to find profilename in local hashmap and if it does
   * not exist looks it up over RMI.
   *
   * @param profileid the profile id number to look up.
   * @return the profilename or null if no profilename is relatied to the given
   *     id
   */
  public String getEndEntityProfileName(final int profileid) {
    String returnval = null;
    // Check if name is in hashmap
    returnval = profilenamestore.get(Integer.valueOf(profileid));

    if (returnval == null) {
      // Retreive profilename
      returnval = endEntityProfileSession.getEndEntityProfileName(profileid);
      if (returnval != null) {
        profilenamestore.put(Integer.valueOf(profileid), returnval);
      }
    }
    return returnval;
  }
}
