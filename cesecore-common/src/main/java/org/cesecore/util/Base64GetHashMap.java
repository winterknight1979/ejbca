/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.util;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of HashMap that base64 decodes all String's that you 'get',
 * if they start with 'B64', i.e. it base64 decodes string of form
 * "B64:&lt;base64 encoded string&gt;". It only tries to decode objects of type
 * String.
 *
 * @version $Id: Base64GetHashMap.java 17625 2013-09-20 07:12:06Z netmackan $
 */
@SuppressWarnings("rawtypes")
public class Base64GetHashMap extends LinkedHashMap {

  private static final long serialVersionUID = 510436675714264809L;

  /** Default. */
  public Base64GetHashMap() {
    super();
  }

  /**
   * @param m Map
   */
  @SuppressWarnings("unchecked")
  public Base64GetHashMap(final Map<?, ?> m) {
    super(m);
  }

  @Override
  public Object get(final Object key) {
    Object o = super.get(key);
    if (o == null) {
      return o;
    }
    if (o instanceof String) {
      String s = (String) o;
      return StringUtil.getBase64String(s);
    }
    return o;
  }
}
