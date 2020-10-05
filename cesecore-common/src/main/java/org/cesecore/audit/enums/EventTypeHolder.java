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

/** @version $Id: EventTypeHolder.java 17625 2013-09-20 07:12:06Z netmackan $ */
public class EventTypeHolder implements EventType {
  private static final long serialVersionUID = 1955829966673283680L;

  /** Value. */
  private final String value;

  /**
   * Constructor.
   *
   * @param avalue Value
   */
  public EventTypeHolder(final String avalue) {
    this.value = avalue;
  }

  @Override
  public String toString() {
    return value;
  }

  @Override
  public boolean equals(final EventType aValue) {
    if (aValue == null) {
      return false;
    }
    return this.value.equals(aValue.toString());
  }
}
