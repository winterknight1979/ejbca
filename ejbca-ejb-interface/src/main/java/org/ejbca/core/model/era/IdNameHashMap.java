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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Provides looking up operation with two separate keys (id or name) over a map.
 *
 * @version $Id: IdNameHashMap.java 25899 2017-05-25 00:02:09Z jeklund $
 * @param <T> type
 */
public class IdNameHashMap<T extends Serializable> implements Serializable {

  private static final long serialVersionUID = 1L;

  private final Map<String, KeyToValueHolder<T>> nameMap = new HashMap<>();
  private final Map<Integer, KeyToValueHolder<T>> idMap = new HashMap<>();

  public Map<String, KeyToValueHolder<T>> getNameMap() {
    return nameMap;
  }

  public Map<Integer, KeyToValueHolder<T>> getIdMap() {
    return idMap;
  }

  public KeyToValueHolder<T> put(
      final int id, final String name, final T value) {
    if (nameMap.containsKey(name) || idMap.containsKey(id)) {
      return null;
    }
    KeyToValueHolder<T> newValue = new KeyToValueHolder<T>(id, name, value);
    nameMap.put(name, newValue);
    idMap.put(id, newValue);
    return newValue;
  }

  public KeyToValueHolder<T> get(final int id) {
    return idMap.get(id);
  }

  public T getValue(final int id) {
    final KeyToValueHolder<T> keyToValueHolder = idMap.get(id);
    return keyToValueHolder == null ? null : keyToValueHolder.getValue();
  }

  public KeyToValueHolder<T> get(final String name) {
    return nameMap.get(name);
  }

  public void putAll(final IdNameHashMap<T> m) {
    nameMap.putAll(m.getNameMap());
    idMap.putAll(m.getIdMap());
  }

  public Set<String> nameKeySet() {
    return nameMap.keySet();
  }

  public Set<Integer> idKeySet() {
    return idMap.keySet();
  }

  public boolean containsKey(final int key) {
    return idMap.containsKey(key);
  }

  public boolean containsKey(final String key) {
    return nameMap.containsKey(key);
  }

  public Collection<KeyToValueHolder<T>> values() {
    return idMap.values();
  }

  public int size() {
    return idMap.size();
  }

  public void clear() {
    idMap.clear();
    nameMap.clear();
  }

  public boolean isEmpty() {
    return idMap.isEmpty();
  }
}
