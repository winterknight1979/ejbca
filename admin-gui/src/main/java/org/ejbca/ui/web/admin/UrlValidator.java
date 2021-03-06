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

import java.net.URI;
import java.net.URISyntaxException;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * JSF validator to check that input fields are valid urls.
 *
 * @version $Id: UrlValidator.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class UrlValidator implements Validator {
    /** Param. */
  private static final Logger LOG = Logger.getLogger(UrlValidator.class);

  @Override
  public void validate(
      final FacesContext facesContext,
      final UIComponent uiComponent,
      final Object o)
      throws ValidatorException {
    StringBuilder url = new StringBuilder();
    String urlValue = o.toString();
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Validating component "
              + uiComponent.getClientId(facesContext)
              + " with value \""
              + urlValue
              + "\"");
    }

    url.append(urlValue);
    try {
      new URI(url.toString());
    } catch (URISyntaxException e) {
      final String msg =
          EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDURL");
      throw new ValidatorException(
          new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
    }
  }
}
