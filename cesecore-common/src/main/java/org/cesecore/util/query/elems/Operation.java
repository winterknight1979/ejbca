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
 * Operation is a combination of Terms. Terms are logiclly related by logical
 * operators @see LogicOperator
 *
 * @version $Id: Operation.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public final class Operation implements Elem {

  private static final long serialVersionUID = -4989405964837453338L;
  /** Term. */
  private final Term term;
  /** Operator. */
  private final LogicOperator operator;
  /** Element. */
  private final Elem element;

  /**
   * @param anOperator Op
   * @param term1 Term
   * @param anElement Elem
   */
  public Operation(
      final LogicOperator anOperator, final Term term1, final Elem anElement) {
    super();
    this.operator = anOperator;
    this.term = term1;
    this.element = anElement;
  }

  /**
   * @return term.
   */
  public Term getTerm() {
    return term;
  }

  /**
   * @return Operator.
   */
  public LogicOperator getOperator() {
    return operator;
  }

  /**
   * @return Element.
   */
  public Elem getElement() {
    return element;
  }
}
