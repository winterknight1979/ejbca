/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.cesecore.util.IndexEnum;

/**
 * This class contains a representation of mathematical conditions, i.e &lt;,
 * &lt;=, &gt;, &gt;=.
 *
 * @version $Id: KeyValidatorDateConditions.java 30982 2019-01-04 12:53:31Z
 *     samuellb $
 */
public enum KeyValidatorDateConditions implements IndexEnum {
  /** Condition for strictly less than a given date. */
  LESS_THAN(0, "VALIDATORDATECONDITION_LESS_THAN", "<"),
  /** Condition for less than or equal to a given date. */
  LESS_OR_EQUAL(1, "VALIDATORDATECONDITION_LESS_OR_EQUAL", "≤"),
  /** Condition for strictly greater than a given date. */
  GREATER_THAN(2, "VALIDATORDATECONDITION_GREATER_THAN", ">"),
  /** Condition for greater than or equal to a given date. */
  GREATER_OR_EQUAL(3, "VALIDATORDATECONDITION_GREATER_OR_EQUAL", "≥");

    /** Index. */
  private int index;
  /** Label. */
  private String label;
  /** expr. */
  private String expression;

  /**
   * Creates a new instance.
   *
   * @param anIndex index
   * @param aLabel resource key or label.
   * @param anExpression expression
   */
  KeyValidatorDateConditions(
      final int anIndex, final String aLabel, final String anExpression) {
    this.index = anIndex;
    this.label = aLabel;
    this.expression = anExpression;
  }

  /**
   * Gets the index.
   *
   * @return index
   */
  @Override
  public int getIndex() {
    return index;
  }

  /**
   * Gets the resource key or label.
   *
   * @return label
   */
  public String getLabel() {
    return label;
  }

  /**
   * Return a key validator date condition given its index.
   *
   * @param index index
   * @return conditions
   */
  public static KeyValidatorDateConditions fromIndex(final int index) {
    for (final KeyValidatorDateConditions condition
        : KeyValidatorDateConditions.values()) {
      if (condition.getIndex() == index) {
        return condition;
      }
    }
    return null;
  }

  /**
   * Gets an Integer list instance containing all indices.
   *
   * @return indices
   */
  public static List<Integer> index() {
    final List<Integer> result = new ArrayList<Integer>();
    for (KeyValidatorDateConditions condition : values()) {
      result.add(condition.getIndex());
    }
    return result;
  }

  /**
   * Evaluates a date matches the given condition.
   *
   * @param value the reference value.
   * @param testValue the test value.
   * @param index the index of the condition.
   * @return true if the condition matches.
   */
  public static boolean evaluate(
      final Date value, final Date testValue, final int index) {
    boolean result = false;
    if (value == null || testValue == null) {
      return true;
    }
    if (index == LESS_THAN.index) {
      result = testValue.before(value);
    } else if (index == LESS_OR_EQUAL.index) {
      result = new Date(testValue.getTime() - 1).before(value);
    } else if (index == GREATER_THAN.index) {
      result = testValue.after(value);
    } else if (index == GREATER_OR_EQUAL.index) {
      result = !new Date(value.getTime() + 1).after(testValue);
    }
    return result;
  }

  @Override
  public String toString() {
    return expression;
  }
}
