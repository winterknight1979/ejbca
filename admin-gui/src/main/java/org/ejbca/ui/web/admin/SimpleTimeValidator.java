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

package org.ejbca.ui.web.admin;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import org.apache.log4j.Logger;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringUtil;
import org.cesecore.util.TimeUnitFormat;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * JSF validator to check that the input does not contain any invalid characters
 * and is a valid time unit format (i.e. '3y 6mo -10d 6h +30m 30s').
 *
 * @version $Id: SimpleTimeValidator.java 25545 2017-03-20 16:50:07Z mikekushner
 *     $
 */
public class SimpleTimeValidator implements Validator {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(SimpleTimeValidator.class);

  @Override
  public void validate(
      final FacesContext facesContext,
      final UIComponent component,
      final Object object)
      throws ValidatorException {
    final String value = (String) object;
    final TimeUnitFormat format =
        SimpleTime.getTimeUnitFormatOrThrow(
            (String) component.getAttributes().get("precision"));
    long minimumValue = Long.MIN_VALUE;
    if (null != component.getAttributes().get("minimumValue")) {
      minimumValue =
          Long.parseLong(
              (String) component.getAttributes().get("minimumValue"));
    }
    long maximumValue = Long.MAX_VALUE;
    if (null != component.getAttributes().get("maximumValue")) {
      maximumValue =
          Long.parseLong(
              (String) component.getAttributes().get("maximumValue"));
    }
    boolean failed = true;
    if (StringUtil.hasSqlStripChars(value).isEmpty()) {
      try {
        final long millis = format.parseMillis(value);
        if (minimumValue <= millis && millis <= maximumValue) {
          failed = false;
        }
      } catch (NumberFormatException e) {
        // NOOP
      }
    }
    if (failed) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Validating component "
                + component.getClientId(facesContext)
                + " with value \""
                + value
                + "\" failed.");
      }
      final String message =
          EjbcaJSFHelper.getBean()
              .getEjbcaWebBean()
              .getText("INVALIDTIMEFORMAT");
      throw new ValidatorException(
          new FacesMessage(FacesMessage.SEVERITY_ERROR, message, null));
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Validating component "
                + component.getClientId(facesContext)
                + " with value \""
                + value
                + "\"");
      }
    }
  }
}
