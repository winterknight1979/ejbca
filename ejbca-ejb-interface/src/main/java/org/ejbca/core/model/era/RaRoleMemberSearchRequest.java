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
import java.util.List;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for role members from RA UI.
 *
 * @version $Id: RaRoleMemberSearchRequest.java 25310 2017-02-21 16:47:29Z
 *     samuellb $
 */
public class RaRoleMemberSearchRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private List<Integer> roleIds = new ArrayList<>();
  /** Param. */
  private List<Integer> caIds = new ArrayList<>();
  /** Param. */
  private List<String> tokenTypes = new ArrayList<>();
  /** Param. */
  private String genericSearchString = "";
  // private boolean genericSearchExact = false;

  /** Default constructor. */
  public RaRoleMemberSearchRequest() { }

  /**
   * Copy constructor.
   *
   * @param request req
   */
  public RaRoleMemberSearchRequest(final RaRoleMemberSearchRequest request) {
    roleIds.addAll(request.roleIds);
    caIds.addAll(request.caIds);
    genericSearchString = request.genericSearchString;
    // genericSearchExact = request.genericSearchExact;
  }

  /**
   * @return roles
   */
  public List<Integer> getRoleIds() {
    return roleIds;
  }

  /**
   * @param theroleIds roles
   */
  public void setRoleIds(final List<Integer> theroleIds) {
    this.roleIds = theroleIds;
  }

  /**
   * @return IDs
   */
  public List<Integer> getCaIds() {
    return caIds;
  }

  /**
   * @param thecaIds IDs
   */
  public void setCaIds(final List<Integer> thecaIds) {
    this.caIds = thecaIds;
  }

  /**
   * @return Types
   */
  public List<String> getTokenTypes() {
    return tokenTypes;
  }

  /**
   * @param thetokenTypes Types
   */
  public void setTokenTypes(final List<String> thetokenTypes) {
    this.tokenTypes = thetokenTypes;
  }

  /**
   * @return Search
   */
  public String getGenericSearchString() {
    return genericSearchString;
  }
  /**
   * Prefix string to search for in the subject DN, or full serial number.
   *
   * @param agenericSearchString string
   */
  public void setGenericSearchString(final String agenericSearchString) {
    this.genericSearchString = agenericSearchString;
  }
  //    public boolean isGenericSearchString() { return genericSearchExact; }
  //    public void setGenericSearchString(final boolean genericSearchExact) {
  // this.genericSearchExact = genericSearchExact; }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public boolean equals(final Object o) {
      return EqualsBuilder.reflectionEquals(this, o);
  }
}
