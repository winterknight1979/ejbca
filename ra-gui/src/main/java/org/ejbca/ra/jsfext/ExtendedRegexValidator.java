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
import javax.faces.validator.RegexValidator;
import javax.faces.validator.ValidatorException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * Extended variant of RegexValidator handy to be used when regex pattern value
 * is going to be evaluated during view render time, which is the use-case for
 * many UI components like h:dataTable and ui:repeat. Also the validator
 * requires request parameter "validationRequiredFromRequest" set to true to be
 * sent alongside with request to perform validation. Use for component that
 * validation is NOT needed for ALL POST requests.
 *
 * <p>Example usage: &lt;ui:repeat value="#{someBean.instances}"
 * var="instance"&gt; &lt;h:inputText id="id" value="#{instance.value}"&gt;
 * &lt;f:validator validatorId="extendedRegexValidator" /&gt; &lt;f:attribute
 * name="pattern" value="#{instance.required ? instance.regexPattern : ''}"
 * /&gt; &lt;f:ajax event="change" execute="@this"
 * listener="#{someBean.someMethodThatDoesntInvokeExtendedRegexValidator}"
 * render="..."/&gt; &lt;/h:inputText&gt; &lt;/ui:repeat&gt; &lt;h:commandButton
 * action="#{someBean.someMethodThatDoesntInvokeExtendedRegexValidator}"&gt;
 * &lt;/h:commandButton&gt; &lt;h:commandButton
 * action="#{someBean.someMethodThatInvokesExtendedRegexValidator}"&gt;
 * &lt;f:param name="validationRequiredFromRequest" value="true" /&gt;
 * &lt;/h:commandButton&gt;
 *
 * @version $Id: ExtendedRegexValidator.java 24512 2016-10-13 14:28:20Z marko $
 */
@FacesValidator("extendedRegexValidator")
public class ExtendedRegexValidator extends RegexValidator {

  private static final Logger log =
      Logger.getLogger(ExtendedRegexValidator.class);

  @Override
  public void validate(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    String pattern = (String) component.getAttributes().get("pattern");
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
              + ", pattern="
              + pattern
              + ", clientId="
              + component.getClientId()
              + ", value="
              + value);
    }

    if (validationRequiredFromRequest == null
        || validationRequiredFromRequest.equalsIgnoreCase("false")) {
      if (log.isTraceEnabled()) {
        log.trace(
            "Ignoring extendedRegexValidator for component "
                + component.getClientId());
      }
      return;
    }

    // Applying regex pattern
    if (pattern != null
        && StringUtils.isNotBlank(pattern)
        && StringUtils.isNotBlank(value.toString())) {
      setPattern(pattern);
      super.validate(context, component, value);
    }
  }
}
