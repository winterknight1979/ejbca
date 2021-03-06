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

package org.ejbca.core.model.ra;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * Exception is cast when values of an end entity field does not match a
 * specific rule in the function FieldValidator.validate().
 *
 * @version $Id: CustomFieldException.java 25012 2017-01-16 09:36:04Z
 *     mikekushner $
 */
public class CustomFieldException extends EjbcaException {

  private static final long serialVersionUID = -4270699717178908309L;

  /** Null constructor.
   */
  public CustomFieldException() {
    super(ErrorCode.FIELD_VALUE_NOT_VALID);
  }

  /**
   * @param message Message
   */
  public CustomFieldException(final String message) {
    super(ErrorCode.FIELD_VALUE_NOT_VALID, message);
  }

  /**
   * @param cause cause
   */
  public CustomFieldException(final Exception cause) {
    super(ErrorCode.FIELD_VALUE_NOT_VALID, cause);
  }

  /**
   * @param message Message
   * @param cause Cause
   */
  public CustomFieldException(final String message, final Throwable cause) {
    super(ErrorCode.FIELD_VALUE_NOT_VALID, message, cause);
  }
}
