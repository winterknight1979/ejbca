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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An enum domain class representing all key validator base parameter options.
 *
 * @version $Id: KeyValidatorSettingsTemplate.java 28140 2018-01-30 12:40:30Z
 *     andresjakobs $
 */
public enum KeyValidatorSettingsTemplate {

  // @formatter:off
    /** profile. */
  USE_CERTIFICATE_PROFILE_SETTINGS(
      0, "VALIDATORSETTINGSTEMPLATE_USE_CP_SETTINGS"),
  /** forum. */
  USE_CAB_FORUM_SETTINGS(1, "VALIDATORSETTINGSTEMPLATE_USE_CAB_FORUM_SETTINGS"),
  /** custom. */
  USE_CUSTOM_SETTINGS(2, "VALIDATORSETTINGSTEMPLATE_USE_CUSTOM_SETTINGS");
  // @formatter:on

  /** The unique option index. */
  private int option;

  /** The resource key or label. */
  private String label;

  /**
   * Creates a new instance.
   *
   * @param anOption option index
   * @param aLabel resource key or label.
   */
  KeyValidatorSettingsTemplate(
          final int anOption, final String aLabel) {
    this.option = anOption;
    this.label = aLabel;
  }

  /**
   * Gets the option index.
   *
   * @return index
   */
  public int getOption() {
    return option;
  }

  /**
   * Gets the resource key or label.
   *
   * @return label
   */
  public String getLabel() {
    return label;
  }

  /**
   * Gets an Integer list instance containing all options.
   *
   * @return indices
   */
  public static List<Integer> types() {
    final List<Integer> result = new ArrayList<Integer>();
    for (KeyValidatorSettingsTemplate option : values()) {
      result.add(option.getOption());
    }
    return result;
  }

  /**
   * Gets a String list instance containing all I18N label keys.
   *
   * @return keys
   */
  public static Map<Integer, String> map() {
    final Map<Integer, String> result = new LinkedHashMap<Integer, String>();
    for (KeyValidatorSettingsTemplate option : values()) {
      result.put(option.getOption(), option.getLabel());
    }
    return result;
  }

  /**
   * Gets the KeyValidatorBaseParameterOptions object with the option
   * optionIndex.
   *
   * @param optionIndex the options index
   * @return the option.
   */
  public static KeyValidatorSettingsTemplate optionOf(
      final int optionIndex) {
    KeyValidatorSettingsTemplate result = null;
    for (KeyValidatorSettingsTemplate option : values()) {
      if (option.getOption() == optionIndex) {
        result = option;
      }
    }
    return result;
  }
}
