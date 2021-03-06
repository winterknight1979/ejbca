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

import java.util.Locale;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;
import javax.faces.convert.FacesConverter;

/**
 * Used in preferences section of RA GUI to convert selected locale and make it
 * digestible by Preferences.xhtml and vice versa.
 *
 * @version $Id: LocaleConverter.java 26958 2017-10-31 14:36:52Z aminkh $
 */
@FacesConverter("localeConverter")
public class LocaleConverter implements Converter {

  @Override
  public Object getAsObject(
      final FacesContext context,
      final UIComponent component,
      final String value) {

    if (value == null || value.isEmpty()) {
      return null;
    }
    return Locale.forLanguageTag(value.replace("_", "-"));
  }

  @Override
  public String getAsString(
      final FacesContext context,
      final UIComponent component,
      final Object value) {

    Locale locale = (Locale) value;
    return locale.toString();
  }
}
