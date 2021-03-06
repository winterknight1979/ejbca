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
package org.cesecore.util.ui;

import org.cesecore.internal.InternalResources;

/**
 * Validator which will validate an integer to greater or equal to 0.
 *
 * @version $Id: PositiveIntegerValidator.java 24964 2017-01-02 08:15:35Z
 *     mikekushner $
 */
public class PositiveIntegerValidator
    implements DynamicUiPropertyValidator<Integer> {

  private static final long serialVersionUID = 1L;

  /** Type. */
  private static final String VALIDATOR_TYPE = "positiveIntegerValidator";

  /**Resource.
   */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  @Override
  public void validate(final Integer value) throws PropertyValidationException {
    validateInteger(value);
  }

  @Override
  public String getValidatorType() {
    return VALIDATOR_TYPE;
  }

  /**
   * @param value Value
   * @throws PropertyValidationException Fail
   */
  public static void validateInteger(final Integer value)
      throws PropertyValidationException {
    if (value.intValue() < 0) {
      throw new PropertyValidationException(
          INTRES.getLocalizedMessage(
              "dynamic.property.validation.positiveinteger.failure",
              value.toString()));
    }
  }
}
