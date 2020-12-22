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
package org.ejbca.ui.cli.infrastructure.parameter;

import java.util.HashMap;
import java.util.Map;

/**
 * A wrapper for the standard java HashMap. Restricted functionality, with some
 * added extras.
 *
 * @version $Id: ParameterContainer.java 19902 2014-09-30 14:32:24Z anatom $
 */
public final class ParameterContainer {

    /** Param. */
  private Map<String, ParameterInformation> parameters =
      new HashMap<String, ParameterInformation>();

  /** Default. */
  public ParameterContainer() { }

  /**
   * Copy constructor.
   *
   * @param parameterContainer container
   */
  public ParameterContainer(final ParameterContainer parameterContainer) {
    this.parameters =
        new HashMap<String, ParameterContainer.ParameterInformation>(
            parameterContainer.parameters);
  }

  /**
   * Returns parameter value, or null if parameter does not exist.
   *
   * @param key Key
   * @return parameter value, or null if parameter was not set
   */
  public String get(final String key) {
    if (parameters.containsKey(key)) {
      return parameters.get(key).getValue();
    } else {
      return null;
    }
  }

  /**
   * @param key key
   * @return bool
   */
  public boolean isStandalone(final String key) {
    if (parameters.containsKey(key)) {
      return false;
    } else {
      return parameters.get(key).isStandalone();
    }
  }

  /**
   * @param key key
   */
  public void remove(final String key) {
    parameters.remove(key);
  }

  /**
   * @param key Key
   * @param value Val
   * @param isStandalone Bool
   */
  public void put(
      final String key, final String value, final boolean isStandalone) {
    parameters.put(key, new ParameterInformation(value, isStandalone));
  }

  /**
   * @param key key
   * @return bool
   */
  public boolean containsKey(final String key) {
    return parameters.containsKey(key);
  }

  private static final class ParameterInformation {
        /** Param. */
    private final String value;
    /** Param. */
    private final boolean isStandalone;

    private ParameterInformation(
        final String avalue, final boolean aisStandalone) {
      this.value = avalue;
      this.isStandalone = aisStandalone;
    }

    public boolean isStandalone() {
      return isStandalone;
    }

    public String getValue() {
      return value;
    }
  }
}
