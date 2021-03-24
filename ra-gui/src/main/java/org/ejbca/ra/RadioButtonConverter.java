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
package org.ejbca.ra;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.ConverterException;
import javax.faces.convert.FacesConverter;

/**
 * Handles conversions of radio buttons from the UI. Radio buttons will
 * generally be handled in the UI as encoded strings, so this converter simply
 * treats them as such.
 *
 * @version $Id: RadioButtonConverter.java 26057 2017-06-22 08:08:34Z anatom $
 */
@FacesConverter("radioButtonConverter")
public class RadioButtonConverter implements Converter {

  @Override
  public Object getAsObject(
      final FacesContext context,
      final UIComponent component,
      final String value) {
    if (value == null || value.isEmpty()) {
      return null;
    }
    return value;
  }

  @Override
  public String getAsString(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ConverterException {
    if (value == null) {
      return null;
    }
    return (String) value;
  }
}
