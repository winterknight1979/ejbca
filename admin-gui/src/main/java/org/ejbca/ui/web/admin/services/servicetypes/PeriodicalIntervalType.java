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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.faces.model.SelectItem;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class used to populate the fields in the custominterval.jsp subview page.
 *
 * @version $Id: PeriodicalIntervalType.java 28844 2018-05-04 08:31:02Z samuellb
 *     $
 */
public class PeriodicalIntervalType extends IntervalType {

  private static final long serialVersionUID = -1076212040665563240L;

  /** Param. */
  public static final String NAME = "PERIODICALINTERVAL";

  /** Param. */
  public static final String DEFAULT_UNIT = PeriodicalInterval.UNIT_MINUTES;
  /** Param. */
  public static final String DEFAULT_VALUE = "5";

  /** Param. */
  private String unit;
  /** Param. */
  private String value;

  /** Construct. */
  public PeriodicalIntervalType() {
    super("periodicalinterval.jsp", NAME, true);
    this.unit = DEFAULT_UNIT;
    this.value = DEFAULT_VALUE;
  }

  @Override
  public String getClassPath() {
    return org.ejbca.core.model.services.intervals.PeriodicalInterval.class
        .getName();
  }

  @Override
  public Properties getProperties(final ArrayList<String> errorMessages)
      throws IOException {
    Properties retval = new Properties();

    try {
      int val = Integer.parseInt(value);
      if (val < 1) {
        throw new NumberFormatException();
      }
    } catch (NumberFormatException e) {
      errorMessages.add("PERIODICALVALUEERROR");
    }
    retval.setProperty(PeriodicalInterval.PROP_VALUE, value);
    retval.setProperty(PeriodicalInterval.PROP_UNIT, unit);
    return retval;
  }

  @Override
  public void setProperties(final Properties properties) throws IOException {
    value =
        properties.getProperty(PeriodicalInterval.PROP_VALUE, DEFAULT_VALUE);
    unit = properties.getProperty(PeriodicalInterval.PROP_UNIT, DEFAULT_UNIT);
  }

  @Override
  public boolean isCustom() {
    return false;
  }

  /**
   * @return unit
   */
  public String getUnit() {
    return unit;
  }

  /**
   * @param aunit unit
   */
  public void setUnit(final String aunit) {
    this.unit = aunit;
  }

  /**
   * @return units
   */
  public List<SelectItem> getAvailableUnits() {
    final List<SelectItem> retval =
        new ArrayList<>(PeriodicalInterval.AVAILABLE_UNITS.length);
    for (final String key : PeriodicalInterval.AVAILABLE_UNITS) {
      retval.add(
          new SelectItem(
              key, EjbcaJSFHelper.getBean().getText().get(key).toLowerCase()));
    }
    return retval;
  }

  /**
   * @return value
   */
  public String getValue() {
    return value;
  }

  /**
   * @param avalue value
   */
  public void setValue(final String avalue) {
    this.value = avalue;
  }
}
