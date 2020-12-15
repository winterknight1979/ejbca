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

/**
 * @version $Id: StatedumpOverride.java 22688 2016-02-01 16:24:56Z samuellb $
 */
public class StatedumpOverride {

  public enum Type {
        /** Type. */
    VALUE,
    /** Type. */
    PREFIX,
    /** Type. */
    APPEND,
    /** Type. */
    REGEX;
  }

  /** Param. */
  private final Type type;
  /** Param. */
  private final Object value; // depends on value of type

  /**
   * Used inside StatedumpImportOptions.
   *
   * @param atype type
   * @param avalue value
   */
  StatedumpOverride(final Type atype, final Object avalue) {
    super();
    this.type = atype;
    this.value = avalue;
  }

  /**
   * @return Type
   */
  public Type getType() {
    return type;
  }

  /**
   * @return Value
   */
  public Object getValue() {
    return value;
  }
}
