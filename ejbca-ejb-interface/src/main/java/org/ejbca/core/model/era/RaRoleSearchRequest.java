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
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for role from RA UI.
 *
 * @version $Id: RaRoleSearchRequest.java 25399 2017-03-06 20:37:51Z samuellb $
 */
public class RaRoleSearchRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private String genericSearchString = "";

  /** Default constructor. */
  public RaRoleSearchRequest() { }

  /**
   * Copy constructor.
   *
   * @param request req
   */
  public RaRoleSearchRequest(final RaRoleSearchRequest request) {
    genericSearchString = request.genericSearchString;
  }

  /**
   * @return String
   */
  public String getGenericSearchString() {
    return genericSearchString;
  }

  /**
   * @param agenericSearchString String
   */
  public void setGenericSearchString(final String agenericSearchString) {
    this.genericSearchString = agenericSearchString;
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public boolean equals(final Object other) {
    return EqualsBuilder.reflectionEquals(this, other);
  }
}
