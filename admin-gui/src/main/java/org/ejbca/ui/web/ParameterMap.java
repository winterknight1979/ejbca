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
package org.ejbca.ui.web;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

/**
 * A map of parameters that implements the usual HttpServletRequest methods.
 * Used by HttpUploads.
 *
 * @version $Id: ParameterMap.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class ParameterMap extends HashMap<String, String[]> {

  private static final long serialVersionUID = 1L;

  /** Construct. **/
  public ParameterMap() {
    super();
  }

  /**
   * @param map Map
   */
  public ParameterMap(final Map<String, String[]> map) {
    super(map);
  }

  /**
   * @param name Name
   * @return Param.
   */
  public String getParameter(final String name) {
    String[] values = get(name);
    if (values == null || values.length == 0) {
      return null;
    }

    return StringUtils.join(values, ";");
  }

  /**
   * @param name Name
   * @return Vals
   */
  public String[] getParameterValues(final String name) {
    return get(name);
  }

  /**
   * @param name name
   * @return bool
   */
  public boolean contains(final String name) {
    return containsKey(name);
  }
}
