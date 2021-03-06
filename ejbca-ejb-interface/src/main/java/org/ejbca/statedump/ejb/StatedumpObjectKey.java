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
package org.ejbca.statedump.ejb;

import java.io.Serializable;
import org.apache.commons.lang.StringUtils;

/**
 * Identifies an object in EJBCA.
 *
 * @version $Id: StatedumpObjectKey.java 22518 2016-01-04 11:49:52Z samuellb $
 */
public final class StatedumpObjectKey implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final String type;
  /** Param. */
  private final int id;
  /** Param. */
  private final String name;

  /**
   * @param atype type
   * @param anid ID
   * @param aname name
   */
  public StatedumpObjectKey(
      final String atype, final int anid, final String aname) {
    this.type = atype;
    this.id = anid;
    this.name = aname;
  }

  /**
   * @return Typee
   */
  public String getType() {
    return type;
  }

  /**
   * @return ID
   */
  public int getId() {
    return id;
  }

  /**
   * @return Name
   */
  public String getName() {
    return name;
  }

  @Override
  public String toString() {
    return type + " " + name + " (" + id + ")";
  }

  @Override
  public boolean equals(final Object o) {
    if (o instanceof StatedumpObjectKey) {
      final StatedumpObjectKey sc = (StatedumpObjectKey) o;
      return StringUtils.equals(sc.getType(), type)
          && StringUtils.equals(sc.getName(), name)
          && sc.getId() == id;
    }
    return false;
  }

  @Override
  public int hashCode() {
    return id ^ type.hashCode() ^ (name.hashCode() + 1);
  }
}
