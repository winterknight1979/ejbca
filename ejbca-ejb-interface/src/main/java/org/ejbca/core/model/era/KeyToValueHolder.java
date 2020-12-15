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

/**
 * Generic implementation which will hold any serializable object, as well as
 * its ID and name.
 *
 * @version $Id: KeyToValueHolder.java 24056 2016-07-29 10:10:23Z mikekushner $
 * @param <T> Type
 */
public class KeyToValueHolder<T extends Serializable> implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final int id;
  /** Param. */
  private final String name;
  /** Param. */
  private final T value;

  /**
   * @param anid ID
   * @param aname Name
   * @param avalue Value
   */
  public KeyToValueHolder(
          final Integer anid, final String aname, final T avalue) {
    this.id = anid;
    this.name = aname;
    this.value = avalue;
  }

  /**
   * @return OD
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

  /**
   * @return Value
   */
  public T getValue() {
    return value;
  }
}
