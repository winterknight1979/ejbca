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
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Properties;

/**
 * Abstract base class of all type of service components. Used to manages
 * available and compatible JSF SubViews.
 *
 * @version $Id: ServiceType.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public abstract class ServiceType implements Serializable {

  private static final long serialVersionUID = -1788904631086719809L;
  /** Param. */
  private final String jSFSubViewPage;
  /** Param. */
  private final String name;
  /** Param. */
  private final boolean translatable;

  /**
   * @param subViewPage the name of the subViewPage to link in the page
   * @param aname the name of the page when it is selected in the GUI
   * @param istranslatable if the name should be looked up in the resource files
   *     or not.
   */
  public ServiceType(
      final String subViewPage,
      final String aname, final boolean istranslatable) {
    super();
    jSFSubViewPage = subViewPage;
    this.name = aname;
    this.translatable = istranslatable;
  }

  /** @return the name of the subViewPage to link in the page */
  public String getJSFSubViewPage() {
    return jSFSubViewPage;
  }

  /** @return the name of the page when it is selected in the GUI */
  public String getName() {
    return name;
  }

  /** @return if the name should be looked up in the resource files or not. */
  public boolean isTranslatable() {
    return translatable;
  }

  /**
   * All implementing classes should populate the properties.
   *
   * @param errorMessages error
   * @return props
   * @throws IOException fail
   */
  public abstract Properties getProperties(ArrayList<String> errorMessages)
      throws IOException;

  /**
   * All implementing classes should populate the gui data.
   *
   * @param properties props
   * @throws IOException fail
   */
  public abstract void setProperties(Properties properties) throws IOException;

  /**
   * The classPath of the component in the model.
   *
   * @return string
   */
  public abstract String getClassPath();

  /**
   * Return true if this type is a custom type.
   *
   * @return bool
   */
  public abstract boolean isCustom();
}
