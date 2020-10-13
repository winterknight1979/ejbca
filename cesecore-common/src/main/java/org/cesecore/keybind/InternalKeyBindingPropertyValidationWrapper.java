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
package org.cesecore.keybind;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * This class wraps the result of an internal key binding validation. It
 * contains a defensive copy of the properties map allowing values entered as
 * strings to be recast as their proper values, and also contains lists of
 * invalid values for diagnostic purposes.
 *
 * @version $Id: InternalKeyBindingPropertyValidationWrapper.java 19902
 *     2014-09-30 14:32:24Z anatom $
 */
public class InternalKeyBindingPropertyValidationWrapper {
    /** Invalid. */
  private Map<String, Class<?>> invalidValues = new HashMap<String, Class<?>>();
  /** Unknown. */
  private List<String> unknownProperties = new ArrayList<String>();
  /** Props. */
  private Map<String, Serializable> propertiesCopy =
      new LinkedHashMap<String, Serializable>();

  /**
   * @return bool
   */
  public boolean arePropertiesValid() {
    return invalidValues.isEmpty() && unknownProperties.isEmpty();
  }

  /**
   * @return properties
   */
  public Map<String, Class<?>> getInvalidValues() {
    return invalidValues;
  }

  /**
   * @return properties
   */
  public List<String> getUnknownProperties() {
    return unknownProperties;
  }

  /**
   * @return properties
   */
  public Map<String, Serializable> getPropertiesCopy() {
    return propertiesCopy;
  }

  /**
   * @param value value
   * @param expected class
   */
  public void addInvalidValue(final String value, final Class<?> expected) {
    invalidValues.put(value, expected);
  }

  /**
   * @param value value
   */
  public void addUnknownProperty(final String value) {
    unknownProperties.add(value);
  }

  /**
   * @param key key
   * @param value value
   */
  public void addProperty(final String key, final Serializable value) {
    propertiesCopy.put(key, value);
  }
}
