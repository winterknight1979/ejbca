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
 * An implementation of HashMap that base64 encodes all String's that you 'put',
 * it encodes them to form "B64:&lt;base64 encoded string&gt;". It only encodes
 * objects of type String.
 *
 * @version $Id: Base64PutHashMap.java 24742 2016-11-15 13:59:14Z jeklund $
 */
public class Base64PutHashMap extends LinkedHashMap<Object, Object> {

  private static final long serialVersionUID = 785586648964618032L;

  /** Default. */
  public Base64PutHashMap() {
    super();
  }

  /**
   * @param m Map
   */
  public Base64PutHashMap(final Map<?, ?> m) {
    super(m);
  }

  @Override
  public Object put(final Object key, final Object value) {
    if (value == null) {
      return super.put(key, value);
    }
    if (value instanceof String) {
      String s = StringUtil.putBase64String((String) value, true);
      return super.put(key, s);
    }
    return super.put(key, value);
  }
}
