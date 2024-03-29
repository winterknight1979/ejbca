/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.member.RoleMember;

/**
 * Container POJO used due to the fact RoleData in certain contexts doesn't
 * survive encoding to JSF.
 *
 * @version $Id: RoleInformation.java 25516 2017-03-16 16:08:31Z jeklund $
 */
@SuppressWarnings("deprecation")
public class RoleInformation implements Serializable {
  private static final long serialVersionUID = 1L;
  /** Param. */
  private final int identifier;
  /** Param. */
  private final String name;
  /** Param. */
  private final List<AccessUserAspectData> accessUserAspects;
  // Fields added in EJBCA 6.8.0 that we cannot be sure is ever set (defaults to
  // null)
  /** Param. */
  private final String nameSpace;

  /**
   * @param anIdentifier ID
   * @param roleName Name
   * @param theAccessUserAspects Aspects
   * @deprecated use fromRoleMembers
   */
  @Deprecated
  public RoleInformation(
      final int anIdentifier,
      final String roleName,
      final List<AccessUserAspectData> theAccessUserAspects) {
    this(anIdentifier, null, roleName, theAccessUserAspects);
  }

  private RoleInformation(
      final int anIdentifier,
      final String aNameSpace,
      final String roleName,
      final List<AccessUserAspectData> theAccessUserAspects) {
    this.identifier = anIdentifier;
    this.name = roleName;
    this.accessUserAspects = theAccessUserAspects;
    this.nameSpace = aNameSpace;
  }

  /**
   * Static helper to create new instance and still allowing deserialization of
   * this class on EJBCA instances that don't have access to the RoleMember
   * class.
   *
   * <p>Note that this it is in general a bad idea to keep a list of RoleMembers
   * that were part of the Role at a point in time in this class.
   *
   * @param identifier ID
   * @param nameSpace NS
   * @param roleName Name
   * @param roleMembers Members
   * @return Info
   */
  public static RoleInformation fromRoleMembers(
      final int identifier,
      final String nameSpace,
      final String roleName,
      final List<RoleMember> roleMembers) {
    final String nameSpaceToUse =
        StringUtils.isEmpty(nameSpace) ? null : nameSpace;
    final List<AccessUserAspectData> accessUserAspects = new ArrayList<>();
    if (roleMembers != null) {
      for (final RoleMember roleMember : roleMembers) {
        final String roleNameForAspect =
            StringUtils.isEmpty(nameSpace)
                ? roleName
                : nameSpace + ";" + roleName;
        accessUserAspects.add(
            new AccessUserAspectData(
                roleNameForAspect,
                roleMember.getTokenIssuerId(),
                roleMember.getTokenMatchKey(),
                roleMember.getTokenType(),
                roleMember.getAccessMatchType(),
                roleMember.getTokenMatchValue()));
      }
    }
    return new RoleInformation(
        identifier, nameSpaceToUse, roleName, accessUserAspects);
  }

  /** @return the Role name */
  public String getName() {
    return name;
  }

  /** @return the Role name space */
  public String getNameSpace() {
    return nameSpace;
  }

  /** @return the Role ID */
  public int getIdentifier() {
    return identifier;
  }

  /** @return the Role name without namespace */
  @Override
  public String toString() {
    return name;
  }

  @Override
  public int hashCode() {
    final int prime = 37;
    int result = 1;
    result = prime * result + identifier;
    result = prime * result + ((name == null) ? 0 : name.hashCode());
    if (nameSpace != null) {
      result = prime * result + nameSpace.hashCode();
    }
    return result;
  }

  @Override
  public boolean equals(final Object obj) { // NOPMD
    if (this == obj) {
        return true;
    }
    if (obj == null) {
        return false;
    }
    if (getClass() != obj.getClass()) {
        return false;
    }
    RoleInformation other = (RoleInformation) obj;
    if (identifier != other.identifier) {
        return false;
    }
    if (name == null) {
      if (other.name != null) {
          return false;
      }
    } else if (!name.equals(other.name)) {
        return false;
    }
    if (nameSpace == null) {
      if (other.nameSpace != null) {
          return false;
      }
    } else if (!nameSpace.equals(other.nameSpace)) {
        return false;
    }
    return true;
  }


  /**
   * @return aspects
   */
  public List<AccessUserAspectData> getAccessUserAspects() {
    return accessUserAspects;
  }
}
