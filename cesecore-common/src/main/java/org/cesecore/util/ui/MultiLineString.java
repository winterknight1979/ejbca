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

import java.io.Serializable;

/**
 * Representation of a multi-line String (text area) for use with
 * DynamicUiProperty.
 *
 * <p>Since the type of DynamicUiProperty determines how it should be rendered
 * (for example in this case a HTML input of type "textarea"), this class is
 * needed as a distinction from a regular String (that is assumed to be a single
 * line).
 *
 * @version $Id: MultiLineString.java 23803 2016-07-06 15:40:37Z jeklund $
 */
public class MultiLineString implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Value. */
  private String value;

  /**
   * @param aValue Value
   */
  public MultiLineString(final String aValue) {
    this.value = aValue;
  }

  /**
   * @return Value
   */
  public String getValue() {
    return value;
  }

  /**
   * @param aValue Value
   */
  public void setValue(final String aValue) {
    this.value = aValue;
  }
}
