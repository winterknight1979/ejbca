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
package org.ejbca.ra.jsfext;

import java.util.Map;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.RequiredValidator;
import javax.faces.validator.ValidatorException;
import org.apache.log4j.Logger;

/**
 * Extended variant of RequiredValidator that requires request parameter
 * "validationRequiredFromRequest" set to true to be sent alongside with request
 * to process validation. Use for component that validation is NOT needed for
 * ALL POST requests. Beside the request parameter
 * "validationRequiredFromRequest" input component has to have attribute
 * "_required" set to true (or expression that evaluates to true) to perform
 * validation.
 *
 * <p>DO NOT try to rename the "_required" into "required". It will be treated
 * as &lt;h:inputText required="..."&gt; thus breaking the
 * extendedRequiredValidator.
 *
 * <p>Example usage: &lt;h:inputText
 * value="#{someBean.componentForWhichValidationIsNotAllwaysRequired}"&gt;
 * &lt;f:validator validatorId="extendedRequiredValidator" /&gt; &lt;f:attribute
 * name="_required" value="true" /&gt; &lt;f:ajax event="change" execute="@this"
 * listener="#{someBean.someMethodThatDoesntValidateRequired}" render="..."/&gt;
 * &lt;/h:inputText&gt; &lt;h:commandButton
 * action="#{someBean.someMethodThatDoesntValidateRequired}"&gt;
 * &lt;/h:commandButton&gt; &lt;h:commandButton
 * action="#{someBean.someMethodThatValidatesRequired}"&gt; &lt;f:param
 * name="validationRequiredFromRequest" value="true" /&gt;
 * &lt;/h:commandButton&gt;
 *
 * @version $Id: ExtendedRequiredValidator.java 24496 2016-10-10 15:25:13Z marko
 *     $
 */
@FacesValidator("extendedRequiredValidator")
public class ExtendedRequiredValidator extends RequiredValidator {

  private static final Logger log =
      Logger.getLogger(ExtendedRequiredValidator.class);

  @Override
  public void validate(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    Object _required = component.getAttributes().get("_required");
    boolean required = false;
    if (_required != null) {
      required =
          Boolean.parseBoolean(
              _required
                  .toString()); // _required can be of String or Boolean type
    }
    Map<String, String> params =
        FacesContext.getCurrentInstance()
            .getExternalContext()
            .getRequestParameterMap();
    String validationRequiredFromRequest =
        params.get("validationRequiredFromRequest");
    if (log.isTraceEnabled()) {
      log.trace(
          "validationRequiredFromRequest="
              + validationRequiredFromRequest
              + ", _required="
              + required
              + ", clientId="
              + component.getClientId()
              + " value="
              + value);
    }

    if (!required
        || validationRequiredFromRequest == null
        || validationRequiredFromRequest.equalsIgnoreCase("false")) {
      if (log.isTraceEnabled()) {
        log.trace(
            "Ignoring extendedRequiredValidator for component "
                + component.getClientId());
      }
      return;
    }

    super.validate(context, component, value);
  }
}
