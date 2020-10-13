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
package org.cesecore.util.query.clauses;

import org.cesecore.util.query.Elem;

/**
 * Query ORDER BY element.
 *
 * @version $Id: Order.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public class Order implements Elem {
  private static final long serialVersionUID = 4277517808022497240L;

  public enum Value {
      /** Ascending. */
    ASC,
    /** Descending. */
    DESC
  }

  /** Name. */
  private final String name;
  /** Order. */
  private final Value order;

  /**
   * @param aName Name
   * @param anOrder Order
   */
  public Order(final String aName, final Value anOrder) {
    this.name = aName;
    this.order = anOrder;
  }

  /**
   * @return Name
   */
  public String getName() {
    return name;
  }

  /**
   * @return Order
   */
  public Value getOrder() {
    return order;
  }
}
