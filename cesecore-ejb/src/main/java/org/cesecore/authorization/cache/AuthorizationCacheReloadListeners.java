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
package org.cesecore.authorization.cache;

import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.cesecore.authorization.access.AuthorizationCacheReload;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;

/**
 * Singleton for broadcasting AuthorizationCacheReload events to subscribers.
 *
 * @version $Id: AuthorizationCacheReloadListeners.java 26057 2017-06-22
 *     08:08:34Z anatom $
 */
public enum AuthorizationCacheReloadListeners {
  /** Singleton. */
    INSTANCE;

    /** Events. */
  private final Set<AuthorizationCacheReloadListener> authCacheReloadEvent =
      new HashSet<>();
  /** Logger. */
  private final Logger log =
      Logger.getLogger(AuthorizationCacheReloadListeners.class);

  /**
   * Broadcast the specified event to all registered listeners.
   *
   * @param event Event
   */
  public void onReload(final AuthorizationCacheReload event) {
    for (final AuthorizationCacheReloadListener observer
        : authCacheReloadEvent) {
      observer.onReload(event);
    }
  }

  /**
   * Subscribe the listener to AuthorizationCacheReload events.
   *
   * @param authorizationCacheReloadListener Listener
   */
  public void addListener(
      final AuthorizationCacheReloadListener authorizationCacheReloadListener) {
    authCacheReloadEvent.add(authorizationCacheReloadListener);
    if (log.isDebugEnabled()) {
      log.debug(
          "'"
              + authorizationCacheReloadListener.getListenerName()
              + "' is now subscribing to AuthorizationCacheReload events.");
    }
  }
}
