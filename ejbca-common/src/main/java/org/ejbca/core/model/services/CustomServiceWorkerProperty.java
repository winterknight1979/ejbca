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
package org.ejbca.core.model.services;

import java.util.List;

/**
 * Helper class for rendering an UI for a custom service worker.
 *
 * @version $Id: CustomServiceWorkerProperty.java 22117 2015-10-29 10:53:42Z
 *     mikekushner $
 */
public class CustomServiceWorkerProperty {

      /** Config. */
  public static final int UI_TEXTINPUT = 0;
  /** Config. */
  public static final int UI_SELECTONE = 1;
  /** Config. */
  public static final int UI_BOOLEAN = 2;
  /** Config. */
  public static final int UI_SELECTMANY = 3;

  /** Param. */
  private final String name;
  /** Param. */
  private final int type;
  /** Param. */
  private final List<String> options;
  /** Param. */
  private final List<String> optionTexts;
  /** Param. */
  private String value;

  /**
   * Construct a UI object with a list of options to choose from.
   *
   * @param aname The name of the property this object should map to.
   * @param atype One of CustomServiceWorkerProperty.UI_* constants.
   * @param theoptions Selectable options.
   * @param theoptionTexts Label of the options in the same order.
   * @param avalue The current value of this component.
   */
  public CustomServiceWorkerProperty(
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
   * Construct a simple UI object with free text or boolean value.
   *
   * @param aname The name of the property this object should map to.
   * @param atype One of CustomServiceWorkerProperty.UI_* constants.
   * @param avalue The current value of this component.
   */
  public CustomServiceWorkerProperty(
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

  /** @param ovalue Set the current value of this property (as String) */
  public void setValue(final String ovalue) {
    String avalue = ovalue;
    if (avalue != null) {
      avalue = avalue.trim();
    }
    this.value = avalue;
  }

  /** @return the current value of this component as a boolean. */
  public boolean getBooleanValue() {
    return Boolean.valueOf(getValue());
  }
  /** @param avalue Set the current value of this component as a boolean. */
  public void setBooleanValue(final boolean avalue) {
    setValue(Boolean.valueOf(avalue).toString());
  }
  /**
   * @return the current value of this component as a "select many" component.
   */
  public String[] getMultiValue() {
    return getValue().split(";");
  }
  /**
   * @param values Set the current value of this component as a "select many"
   *     component.
   */
  public void setMultiValue(final String[] values) {
    final StringBuilder sb = new StringBuilder();
    for (final String avalue : values) {
      if (sb.length() > 0) {
        sb.append(';');
      }
      sb.append(avalue);
    }
    setValue(sb.toString());
  }

  /** @return the name of this property */
  public String getName() {
    return name;
  }
  /** @return one of the CustomPublisherProperty.UI_* constants */
  public int getType() {
    return type;
  }
  /** @return true if this is a free text input field. */
  public boolean isTypeText() {
    return type == UI_TEXTINPUT;
  }
  /** @return true if this is a boolean input field. */
  public boolean isTypeBoolean() {
    return type == UI_BOOLEAN;
  }
  /** @return true if this is a "select one" input field. */
  public boolean isTypeSelectOne() {
    return type == UI_SELECTONE;
  }
  /** @return true if this is a "select many" input field. */
  public boolean isTypeSelectMany() {
    return type == UI_SELECTMANY;
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
