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
import java.util.List;
import org.cesecore.util.IndexEnum;

/**
 * Contains different actions which occur whenever a Validator in EJBCA fails.
 *
 * @version $Id: KeyValidationFailedActions.java 30982 2019-01-04 12:53:31Z
 *     samuellb $
 */
public enum KeyValidationFailedActions implements IndexEnum {
    /** No-op. */
  DO_NOTHING(0, "VALIDATORFAILEDACTION_DO_NOTHING"),
  /** Info. */
  LOG_INFO(1, "VALIDATORFAILEDACTION_LOG_INFO"),
  /** Warn. */
  LOG_WARN(2, "VALIDATORFAILEDACTION_LOG_WARN"),
  /** Error. */
  LOG_ERROR(3, "VALIDATORFAILEDACTION_LOG_ERROR"),
  /** Abort. */
  ABORT_CERTIFICATE_ISSUANCE(
      4, "VALIDATORFAILEDACTION_ABORT_CERTIFICATE_ISSUANCE");

    /** Index. */
  private int index;
  /** Label. */
  private String label;

  /**
   * Creates a new instance.
   *
   * @param anIndex index
   * @param aLabel resource key or label.
   */
  KeyValidationFailedActions(final int anIndex, final String aLabel) {
    this.index = anIndex;
    this.label = aLabel;
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
   * Gets an Integer list instance containing all index.
   *
   * @return indices
   */
  public static List<Integer> index() {
    final List<Integer> result = new ArrayList<Integer>();
    for (KeyValidationFailedActions condition : values()) {
      result.add(condition.getIndex());
    }
    return result;
  }

  /**
   * Retrieve an action from its index.
   *
   * @param index the index of the action
   * @return the corresponding action enum or null if not found
   */
  public static KeyValidationFailedActions fromIndex(final int index) {
    for (final KeyValidationFailedActions action : values()) {
      if (action.getIndex() == index) {
        return action;
      }
    }
    return null;
  }
}
