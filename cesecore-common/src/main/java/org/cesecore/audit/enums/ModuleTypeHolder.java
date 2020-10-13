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
package org.cesecore.audit.enums;

/**
 * Simple implementation of ModuleType that holds the identifier.
 *
 * @version $Id: ModuleTypeHolder.java 26796 2017-10-12 04:29:58Z anatom $
 */
public class ModuleTypeHolder implements ModuleType {

  private static final long serialVersionUID = 1L;

  /** Value. */
  private final String value;

  /**
   * Constructor.
   *
   * @param aValue Value
   */
  public ModuleTypeHolder(final String aValue) {
    this.value = aValue;
  }

  @Override
  public String toString() {
    return value;
  }

  @Override
  public boolean equals(final ModuleType aValue) {
    if (aValue == null) {
      return false;
    }
    return this.value.equals(aValue.toString());
  }
}
