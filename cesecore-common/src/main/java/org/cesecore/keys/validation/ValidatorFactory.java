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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import org.apache.commons.collections.CollectionUtils;

/**
 * Reads in the implementations of the Validator interface.
 *
 * @version $Id: ValidatorFactory.java 27845 2018-01-10 15:15:37Z mikekushner $
 */
public enum ValidatorFactory {
    /** Singleton instance. */
  INSTANCE;

    /** Lookup table. */
  private Map<String, Validator> identifierToImplementationMap =
      new HashMap<>();

  ValidatorFactory() {
    ServiceLoader<Validator> svcloader = ServiceLoader.load(Validator.class);
    for (Validator type : svcloader) {
      type.initialize();
      identifierToImplementationMap.put(
          type.getValidatorTypeIdentifier(), type);
    }
  }

  /**
   * @return All implementations
   */
  public Collection<Validator> getAllImplementations() {
    return identifierToImplementationMap.values();
  }

  /**
   * @param excludeClasses Exclusions
   * @return Implementations
   */
  public Collection<Validator> getAllImplementations(
      final List<Class<?>> excludeClasses) {
    if (CollectionUtils.isNotEmpty(excludeClasses)) {
      final Collection<Validator> result = new ArrayList<Validator>();
      for (Validator validator : getAllImplementations()) {
        if (!excludeClasses.contains(validator.getClass())) {
          result.add(validator);
        }
      }
      return result;
    } else {
      return getAllImplementations();
    }
  }

  /**
   * @param identifier ID
   * @return Archetype
   */
  public Validator getArcheType(final String identifier) {
    return identifierToImplementationMap.get(identifier).clone();
  }
}
