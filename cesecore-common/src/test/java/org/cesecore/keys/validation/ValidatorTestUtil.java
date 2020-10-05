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

/**
 * Static helper key validator tests.
 *
 * @version $Id: ValidatorTestUtil.java 27654 2017-12-22 13:56:31Z mikekushner $
 */
package org.cesecore.keys.validation;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @version $Id: ValidatorTestUtil.java 27654 2017-12-22 13:56:31Z mikekushner $
 */
public final class ValidatorTestUtil {

  /**
   * Factory method to create key validators.
   *
   * @param type the key validator type (see {@link ValidatorBase#TYPE}
   * @param name the logical name
   * @param description the description text
   * @param notBefore the certificates validity not before
   * @param notBeforeCondition the certificates validity not before condition
   * @param notAfter the certificates validity not after
   * @param notAfterCondition the certificates validity not after condition
   * @param failedAction the failed action to be performed.
   * @param certificateProfileIds list of IDs of certificate profile to be
   *     applied to.
   * @return the concrete key validator instance.
   * @throws IllegalAccessException fail
   * @throws InstantiationException fail
   * @throws SecurityException fail
   * @throws NoSuchMethodException fail
   * @throws InvocationTargetException fail
   * @throws IllegalArgumentException fail
   */
  public static final KeyValidator createKeyValidator(
      Class<? extends KeyValidator> type,
      final String name,
      final String description,
      final Date notBefore,
      final int notBeforeCondition,
      final Date notAfter,
      final int notAfterCondition,
      final int failedAction,
      final Integer... certificateProfileIds)
      throws InstantiationException, IllegalAccessException,
          IllegalArgumentException, InvocationTargetException,
          NoSuchMethodException, SecurityException {
    KeyValidator result = type.getConstructor().newInstance();
    result.setProfileName(name);
    if (null != description) {
      result.setDescription(description);
    }
    if (null != notBefore) {
      result.setNotBefore(notBefore);
    }
    if (-1 < notBeforeCondition) {
      result.setNotBeforeCondition(notBeforeCondition);
    }
    if (null != notAfter) {
      result.setNotAfter(notAfter);
    }
    if (-1 < notAfterCondition) {
      result.setNotAfterCondition(notAfterCondition);
    }
    if (-1 < failedAction) {
      result.setFailedAction(failedAction);
    }
    final List<Integer> ids = new ArrayList<Integer>();
    for (Integer id : certificateProfileIds) {
      ids.add(id);
    }
    result.setCertificateProfileIds(ids);
    return result;
  }

  /** Avoid instantiation. */
  private ValidatorTestUtil() {}
}
