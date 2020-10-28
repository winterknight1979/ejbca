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

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;

/** Primary key for HardTokenPropertyData. */
public class HardTokenPropertyDataPK implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private String id;
  /** Param. */
  private String property;

  /**
   * Empty.
   */
  public HardTokenPropertyDataPK() { }

  /**
   * @param anid ID
   * @param aproperty Prop
   */
  public HardTokenPropertyDataPK(final String anid, final String aproperty) {
    setId(anid);
    setProperty(aproperty);
  }

  /**
   * @return ID
   */
  // @Column
  public String getId() {
    return id;
  }

  /**
   * @param anid ID
   */
  public void setId(final String anid) {
    this.id = anid;
  }

  /**
   * @return prop
   */
  // @Column
  public String getProperty() {
    return property;
  }

  /**
   * @param aproperty prop
   */
  public void setProperty(final String aproperty) {
    this.property = aproperty;
  }

  @Override
  public int hashCode() {
    int hashCode = 0;
    if (id != null) {
      hashCode += id.hashCode();
    }
    if (property != null) {
      hashCode += property.hashCode();
    }
    return hashCode;
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof HardTokenPropertyDataPK)) {
      return false;
    }
    HardTokenPropertyDataPK pk = (HardTokenPropertyDataPK) obj;
    if (id == null || !id.equals(pk.id)) {
      return false;
    }
    if (property == null || !property.equals(pk.property)) {
      return false;
    }
    return true;
  }
}
