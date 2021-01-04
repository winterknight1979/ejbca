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
package org.ejbca.ui.psm.jsf;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import javax.faces.component.html.HtmlSelectOneMenu;
import org.apache.log4j.Logger;
import org.cesecore.util.ui.DynamicUiComponent;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * MyFaces HTML UI drop-down box for component implementing the {@link
 * PropertyChangeListener} interface to get noticed for dynamic UI property
 * changes.
 *
 * @version $Id: JsfDynamicUiHtmlSelectOneMenu.java 28530 2018-03-21 06:55:55Z
 *     mikekushner $
 */
public class JsfDynamicUiHtmlSelectOneMenu extends HtmlSelectOneMenu
    implements DynamicUiComponent, PropertyChangeListener {

  /** Class logger. */
  private static final Logger LOG =
      Logger.getLogger(JsfDynamicUiHtmlSelectOneMenu.class);

  /** DynamicUIProperty reference. */
  private DynamicUiProperty<?> dynamicUiProperty;

  /** Default constructor. */
  public JsfDynamicUiHtmlSelectOneMenu() { }

  /**
   * Sets the dynamic UI property reference.
   *
   * @param property the dynamic UI property.
   */
  void setDynamicUiProperty(final DynamicUiProperty<?> property) {
    this.dynamicUiProperty = property;
    this.dynamicUiProperty.addDynamicUiComponent(this);
  }

  @Override
  public void propertyChange(final PropertyChangeEvent event) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "Property change event for dynamic UI property " + dynamicUiProperty
                  != null
              ? dynamicUiProperty.getName()
              : null + " fired: " + event);
    }
    if (event.getOldValue() != event.getNewValue()) {
      setValue(event.getNewValue());
    }
  }
}
