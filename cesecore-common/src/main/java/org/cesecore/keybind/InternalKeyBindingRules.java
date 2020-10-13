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

package org.cesecore.keybind;

import java.util.HashMap;
import java.util.Map;

/**
 * Authorization Rules for InternalKeyBindings.
 *
 * @version $Id: InternalKeyBindingRules.java 19902 2014-09-30 14:32:24Z anatom
 *     $
 */
public enum InternalKeyBindingRules {
    /** Base. */
  BASE("/internalkeybinding", ""),
  /** Delete. */
  DELETE(BASE.resource() + "/delete", "DELETE"),
  /** Modify. */
  MODIFY(BASE.resource() + "/modify", "MODIFY"),
  /** View. */
  VIEW(BASE.resource() + "/view", "VIEW");

    /** Reverse lookup table. */
  private static final Map<String, InternalKeyBindingRules>
      REV_RESOURCE_LOOKUP;

  static {
    REV_RESOURCE_LOOKUP = new HashMap<String, InternalKeyBindingRules>();
    for (InternalKeyBindingRules rule : InternalKeyBindingRules.values()) {
      REV_RESOURCE_LOOKUP.put(rule.resource(), rule);
    }
  }

  /** Resource. */
  private final String resource;
  /** Ref. */
  private final String reference;

  /**
   * @param aResource resource
   * @param aReference ref
   */
  InternalKeyBindingRules(
          final String aResource, final String aReference) {
    this.resource = aResource;
    this.reference = aReference;
  }

  /**
   * @return resource
   */
  public String resource() {
    return this.resource;
  }

  @Override
  public String toString() {
    return this.resource;
  }

  /**
   * @return ref
   */
  public String getReference() {
    return reference;
  }

  /**
   * @param resource resource
   * @return rules
   */
  public static InternalKeyBindingRules getFromResource(final String resource) {
    return REV_RESOURCE_LOOKUP.get(resource);
  }
}
