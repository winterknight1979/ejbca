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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.cesecore.roles.member.RoleMember;

/**
 * Response of role member search from RA UI.
 *
 * @version $Id: RaRoleMemberSearchResponse.java 25585 2017-03-22 17:13:47Z
 *     samuellb $
 */
public class RaRoleMemberSearchResponse implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private List<RoleMember> roleMembers = new ArrayList<>();
  /** Param. */
  private boolean mightHaveMoreResults = false;

  /**
   * @return MEMBERS
   */
  public List<RoleMember> getRoleMembers() {
    return roleMembers;
  }

  /**
   * @param theroleMembers members
   */
  public void setRoleMembers(final List<RoleMember> theroleMembers) {
    this.roleMembers = theroleMembers;
  }

  /**
   * @return bool
   */
  public boolean isMightHaveMoreResults() {
    return mightHaveMoreResults;
  }

  /**
   * @param ismightHaveMoreResults bool
   */
  public void setMightHaveMoreResults(final boolean ismightHaveMoreResults) {
    this.mightHaveMoreResults = ismightHaveMoreResults;
  }

  /**
   * @param other response to merge.
   */
  public void merge(final RaRoleMemberSearchResponse other) {
    final Map<Integer, RoleMember> roleMemberMap = new HashMap<>();
    for (final RoleMember roleMember : roleMembers) {
      roleMemberMap.put(roleMember.getId(), roleMember);
    }
    for (final RoleMember roleMember : other.roleMembers) {
      roleMemberMap.put(roleMember.getId(), roleMember);
    }
    this.roleMembers.clear();
    this.roleMembers.addAll(roleMemberMap.values());
    if (other.isMightHaveMoreResults()) {
      setMightHaveMoreResults(true);
    }
  }
}
