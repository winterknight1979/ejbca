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
package org.ejbca.core.model.ca.publisher;

import java.io.Serializable;
import java.util.List;

/**
 * Helper class for UIs that want to present a nice view of the configurable
 * properties of a Custom Publisher.
 *
 * <p>All properties are interpreted as String values.
 *
 * @version $Id: CustomPublisherProperty.java 30398 2018-11-05 17:34:20Z
 *     mikekushner $
 */
public class CustomPublisherProperty implements Serializable {

  private static final long serialVersionUID = 1L;

  /** config. */
  public static final int UI_TEXTINPUT = 0;
  /** config. */
  public static final int UI_SELECTONE = 1;
  /** config. */
  public static final int UI_BOOLEAN = 2;
  /** config. */
  public static final int UI_TEXTOUTPUT = 3;
  /** config. */
  public static final int UI_TEXTINPUT_PASSWORD = 3;

  /** Name. */
  private final String name;
  /** Type. */
  private final int type;
  /** Options. */
  private final List<String> options;
  /** Texts. */
  private final List<String> optionTexts;
  /** Value. */
  private String value;

  /**
   * Representation of a property where the user can select from a list of
   * choices.
   *
   * @param aname name of the property
   * @param atype one of CustomPublisherProperty.UI_* constants (only
   *     UI_SELECTONE makes sense in the current implementation)
   * @param theoptions a list of selectable values
   * @param theoptionTexts a list of tests to apply to show the user for each of
   *     selectable values
   * @param avalue the current value of this property
   */
  public CustomPublisherProperty(
      final String aname,
      final int atype,
      final List<String> theoptions,
      final List<String> theoptionTexts,
      final String avalue) {
    this.name = aname;
    this.type = atype;
    this.options = theoptions;
    this.optionTexts = theoptionTexts;
    this.value = avalue;
  }

  /**
   * Representation of a property where the user can select from a list of
   * choices.
   *
   * @param aname name of the property
   * @param atype one of CustomPublisherProperty.UI_* constants (only
   *     UI_TEXTINPUT or UI_BOOLEAN makes sense in the current implementation)
   * @param avalue the current value of this property
   */
  public CustomPublisherProperty(
      final String aname, final int atype, final String avalue) {
    this.name = aname;
    this.type = atype;
    this.options = null;
    this.optionTexts = null;
    this.value = avalue;
  }

  /** @return the current value of this property (as String) */
  public String getValue() {
    return value;
  }

  /**
   * Set the current value of this property (as String).
   *
   * @param ovalue Value
   */
  public void setValue(final String ovalue) {
    String lvalue = null;
    if (ovalue != null) {
      lvalue = ovalue.trim();
    }
    this.value = lvalue;
  }

  /** @return the name of this property */
  public String getName() {
    return name;
  }
  /** @return one of the CustomPublisherProperty.UI_* constants */
  public int getType() {
    return type;
  }
  /**
   * @return a List of values this property can have or null if this does not
   *     apply to the type
   */
  public List<String> getOptions() {
    return options;
  }
  /**
   * @return a List of user-friendly texts corresponding to the values this
   *     property can have or null if this does not apply to the type
   */
  public List<String> getOptionTexts() {
    return optionTexts;
  }
}
