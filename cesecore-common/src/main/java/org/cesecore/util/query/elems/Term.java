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
package org.cesecore.util.query.elems;

import org.cesecore.util.query.Elem;

/**
 * Query term. Each term is composed as followed: [name] [operator] [value]
 *
 * @version $Id: Term.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public final class Term implements Elem {

  private static final long serialVersionUID = 3569353821030638847L;
  /** Name. */
  private final String name;
  /** Value. */
  private final Object value;
  /** Op. */
  private final RelationalOperator operator;

  /**
   * @param anOperator Op
   * @param aName Name
   * @param aValue Value
   */
  public Term(
      final RelationalOperator anOperator,
      final String aName,
      final Object aValue) {
    this.name = aName;
    this.value = aValue;
    this.operator = anOperator;
  }


  /**
   * @return name
   */
  public String getName() {
    return name;
  }

  /** @return Value. */
  public Object getValue() {
    return value;
  }

  /**
   * @return Operator.
   */
  public RelationalOperator getOperator() {
    return operator;
  }
}
