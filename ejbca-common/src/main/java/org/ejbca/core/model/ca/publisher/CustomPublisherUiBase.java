/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ca.publisher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.cesecore.authentication.tokens.AuthenticationToken;

/** @version $Id$ */
public abstract class CustomPublisherUiBase extends CustomPublisherContainer
    implements CustomPublisherUiSupport {

  private static final long serialVersionUID = 1L;
  /** Map. */
  private final Map<String, CustomPublisherProperty> properties =
      new LinkedHashMap<>();

  /** Default constructor. */
  public CustomPublisherUiBase() {
    super();
    init(new Properties());
  }

  /**
   * @param publisher pub
   */
  public CustomPublisherUiBase(final BasePublisher publisher) {
    super(publisher);
  }

  /**
   * @param property prop
   */
  protected void addProperty(final CustomPublisherProperty property) {
    properties.put(property.getName(), property);
  }

  @Override
  public List<CustomPublisherProperty> getCustomUiPropertyList(
      final AuthenticationToken authenticationToken) {
    return new ArrayList<>(properties.values());
  }

  @Override
  public List<String> getCustomUiPropertyNames() {
    return new ArrayList<>(properties.keySet());
  }

  @Override
  public int getPropertyType(final String label) {
    CustomPublisherProperty property = properties.get(label);
    if (property == null) {
      return -1;
    } else {
      return property.getType();
    }
  }
}
