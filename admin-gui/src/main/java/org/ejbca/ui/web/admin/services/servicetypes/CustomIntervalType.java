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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.ui.web.admin.CustomLoader;

/**
 * Class used to populate the fields in the custominterval.jsp subview page.
 *
 * @version $Id: CustomIntervalType.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class CustomIntervalType extends IntervalType {

  private static final long serialVersionUID = -8378607303311336382L;

  /** Param. */
  public static final String NAME = "CUSTOMINTERVAL";

  /** Param. */
  public CustomIntervalType() {
    super("custominterval.jsp", NAME, true);
  }

  /** Param. */
  private String autoClassPath;
  /** Param. */
  private String manualClassPath;

  /** Param. */
  private String propertyText;

  /** @return the propertyText */
  public String getPropertyText() {
    return propertyText;
  }

  /** @param apropertyText the propertyText to set */
  public void setPropertyText(final String apropertyText) {
    this.propertyText = apropertyText;
  }

  /**
   * Sets the class path, and detects if it is an auto-detected class or a
   * manually specified class.
   *
   * @param classPath CP
   */
  public void setClassPath(final String classPath) {

    if (CustomLoader.isDisplayedInList(classPath, IInterval.class)) {
      autoClassPath = classPath;
      manualClassPath = "";
    } else {
      autoClassPath = "";
      manualClassPath = classPath;
    }
  }

  @Override
  public String getClassPath() {
    return autoClassPath != null && !autoClassPath.isEmpty()
        ? autoClassPath
        : manualClassPath;
  }

  /**
   * @param classPath CP
   */
  public void setAutoClassPath(final String classPath) {
    autoClassPath = classPath;
  }

  /**
   * @return CP
   */
  public String getAutoClassPath() {
    return autoClassPath;
  }

  /**
   * @param classPath CP
   */
  public void setManualClassPath(final String classPath) {
    manualClassPath = classPath;
  }

  /**
   * @return CP
   */
  public String getManualClassPath() {
    return manualClassPath;
  }

  @Override
  public Properties getProperties(final ArrayList<String> errorMessages)
      throws IOException {
    Properties retval = new Properties();
    retval.load(new ByteArrayInputStream(getPropertyText().getBytes()));
    return retval;
  }

  @Override
  public void setProperties(final Properties properties) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    properties.store(baos, null);
    setPropertyText(new String(baos.toByteArray()));
  }

  @Override
  public boolean isCustom() {
    return true;
  }
}
