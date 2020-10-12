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
 * POJO for a set of radio buttons in a Dynamic UI Property.
 *
 * @version $Id: RadioButton.java 34324 2020-01-17 12:22:39Z henriks $
 */
public class RadioButton implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Label. */
  private String label;

  /**
   * @param aLabel Label
   */
  public RadioButton(final String aLabel) {
    this.label = aLabel;
  }

  /**
   * @return label
   */
  public String getLabel() {
    return label;
  }

  /**
   * @param aLabel Label
   */
  public void setLabel(final String aLabel) {
    this.label = aLabel;
  }

  @Override
  public String toString() {
    return label;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((label == null) ? 0 : label.hashCode());
    return result;
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
        return true;
    }
    if (obj == null) {
        return false;
    }
    if (getClass() != obj.getClass()) {
        return false;
    }
    RadioButton other = (RadioButton) obj;
    if (label == null) {
      return other.label == null;
    }
    return label.equals(other.label);
  }

  /**
   * @param encodedValue Value
   * @return bool
   */
  public boolean equals(final String encodedValue) {
    return equals(
        DynamicUiProperty.getAsObject(encodedValue, RadioButton.class));
  }
}
