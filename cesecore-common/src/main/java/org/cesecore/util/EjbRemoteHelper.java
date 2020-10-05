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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.cesecore.jndi.JndiHelper;

/**
 * Helper methods to get EJB session interfaces.
 *
 * @version $Id: EjbRemoteHelper.java 29630 2018-08-14 08:55:21Z mikekushner $
 */
public enum EjbRemoteHelper {
  INSTANCE;

  /** The main EJBCA EJB jar. */
  public static final String MODULE_EJBCA = "ejbca-ejb";

  /** The main CESeCore EJB jar. */
  public static final String MODULE_CESECORE = "cesecore-ejb";

  /** The additional CESeCore EJB jar. */
  public static final String MODULE_CESECORE_OTHER = "cesecore-other-ejb";

  /** The EJB used by system tests. */
  public static final String MODULE_TEST = "systemtests-ejb";

  /** The EJB used by system test ProtocolLookupServerHttpTest. */
  public static final String MODULE_UNIDFNR = "unidfnr-ejb";

  public static final String MODULE_EDITION_SPECIFIC = "edition-specific-ejb";

  private Map<Class<?>, Object> interfaceCache;

  /**
   * Returns a cached remote session bean.
   *
   * @param key the @Remote-appended interface for this session bean
   * @param <T> type
   * @return the sought interface, or null if it doesn't exist in JNDI context.
   */
  public <T> T getRemoteSession(final Class<T> key) {
    return getRemoteSession(key, null);
  }

  /**
   * Returns a cached remote session bean.
   *
   * @param key the @Remote-appended interface for this session bean
   * @param <T> type
   * @param module the module where the bean is deployed, i.e. systemtests-ejb
   *     or cesecore-other-ejb, if null defaults to cesecore-ejb for packages
   *     under org.cesecore, otherwise ejbca-ejb.
   * @return the sought interface, or null if it doesn't exist in JNDI context.
   */
  public <T> T getRemoteSession(final Class<T> key, String module) {
    if (interfaceCache == null) {
      interfaceCache = new ConcurrentHashMap<Class<?>, Object>();
    }
    @SuppressWarnings("unchecked")
    T session = (T) interfaceCache.get(key);
    if (session == null) {
      if (module == null) {
        if (key.getName().startsWith("org.cesecore")) {
          module = EjbRemoteHelper.MODULE_CESECORE;
        } else if (key.getName().endsWith("UnidfnrSessionRemote")) {
          module = EjbRemoteHelper.MODULE_UNIDFNR;
        } else {
          module = EjbRemoteHelper.MODULE_EJBCA;
        }
      }
      session = JndiHelper.getRemoteSession(key, module);
      if (session != null) {
        interfaceCache.put(key, session);
      }
    }
    return session;
  }
}
