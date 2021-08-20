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
package org.cesecore.util.query;

import java.io.Serializable;
import java.util.AbstractMap;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.LogicOperator;
import org.cesecore.util.query.elems.Operation;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;

/**
 * This class is a DSL sugar to all possible Criterias.
 *
 * @version $Id: Criteria.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public final class Criteria implements Serializable {

  private static final long serialVersionUID = 3186042047323993627L;

  private Criteria() { }
  /**
   * @param name Name
   * @param value Value
   * @return Element
   */
  public static Elem eq(final String name, final Object value) {
    return new Term(RelationalOperator.EQ, name, value);
  }

  /**
   * @param name name
   * @param value value
   * @return the query with an appended "not equal to" condition
   */
  public static Elem neq(final String name, final Object value) {
    return new Term(RelationalOperator.NEQ, name, value);
  }

  /**
   * @param name name
   * @param value value
   * @return the query with an appended "greater than or equal to" condition
   */
  public static Elem geq(final String name, final Object value) {
    return new Term(RelationalOperator.GE, name, value);
  }

  /**
   * @param name name
   * @param value value
   * @return the query with an appended "greater than" condition
   */
  public static Elem grt(final String name, final Object value) {
    return new Term(RelationalOperator.GT, name, value);
  }

  /**
   * @param name name
   * @param value value
   * @return the query with an appended "less than or equal to" condition
   */
  public static Elem leq(final String name, final Object value) {
    return new Term(RelationalOperator.LE, name, value);
  }

  /**
   * @param name name
   * @param value value
   * @return the query with an appended "less than to" condition
   */
  public static Elem lsr(final String name, final Object value) {
    return new Term(RelationalOperator.LT, name, value);
  }

  /**
   * @param name name
   * @param after after
   * @param before before
   * @return the query with an appended "between" condition
   */
  public static Elem between(
      final String name, final Object after, final Object before) {
    return new Term(
        RelationalOperator.BETWEEN,
        name,
        new AbstractMap.SimpleEntry<Object, Object>(after, before));
  }

/**
 * @param name name
 * @param value value
 * @return Element
 */
  public static Elem like(final String name, final Object value) {
    return new Term(RelationalOperator.LIKE, name, value);
  }

  /**
   * @param name Name
   * @return Element
   */
  public static Elem isNull(final String name) {
    return new Term(RelationalOperator.NULL, name, null);
  }

  /**
   * @param name Name
   * @return Element
   */
  public static Elem isNotNull(final String name) {
    return new Term(RelationalOperator.NOTNULL, name, null);
  }

  /**
   * @param first First
   * @param second Second
   * @return First &amp;&amp; Second
   */
  public static Elem and(final Elem first, final Elem second) {
    return new Operation(LogicOperator.AND, (Term) first, second);
  }

  /**
   * @param first First
   * @param second Second
   * @return First || Second
   */
  public static Elem or(final Elem first, final Elem second) {
    return new Operation(LogicOperator.OR, (Term) first, second);
  }
  /**
   * @param name name
   * @return Element
   */
  public static Elem orderAsc(final String name) {
    return new Order(name, Order.Value.ASC);
  }

  /**
   * @param name name
   * @return Element
   */
  public static Elem orderDesc(final String name) {
    return new Order(name, Order.Value.DESC);
  }
}
