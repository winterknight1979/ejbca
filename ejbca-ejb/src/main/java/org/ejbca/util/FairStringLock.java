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

package org.ejbca.util;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;

/**
 * Util for locking based on a String. This class can of course not do locking
 * distributed over several JVMs/EJBCA nodes. Currently not used by any classes
 * in EJBCA.
 *
 * <p>Example usage: String username = null; boolean lockedByThisRequest =
 * false; ... try { ... lockedByThisRequest = true;
 * FairStringLock.getInstance("SomeFairStringLock").lock(username); ... }
 * finally { if (lockedByThisRequest) {
 * FairStringLock.getInstance("SomeFairStringLock").unlock(username); } }
 *
 * @version $Id: FairStringLock.java 22142 2015-11-03 14:15:51Z mikekushner $
 */
public final class FairStringLock {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(FairStringLock.class);

  /** Param. */
  private static Map<String, FairStringLock> instanceMap =
      new HashMap<String, FairStringLock>();
  /** Param. */
  private static ReentrantLock instanceMapLock = new ReentrantLock(true);

  /** Param. */
  private final Map<String, ReentrantLock> lockMap =
      new HashMap<String, ReentrantLock>();
  /** Param. */
  private final ReentrantLock accessMapLock = new ReentrantLock(true);

  /** Param. */
  private final String instanceName;

  /**
   * @param instanceName name
   */
  private FairStringLock(final String instanceName) {
    this.instanceName = instanceName;
  }

  /**
   * @param aninstanceName Name
   * @return Lock
   */
  public static FairStringLock getInstance(final String aninstanceName) {
    instanceMapLock.lock();
    FairStringLock instance = instanceMap.get(aninstanceName);
    if (instance == null) {
      instance = new FairStringLock(aninstanceName);
      instanceMap.put(aninstanceName, instance);
    }
    instanceMapLock.unlock();
    return instance;
  }

  /**
   * @param lockName lock
   */
  public void lock(final String lockName) {
    if (lockName == null) {
      return;
    }
    accessMapLock.lock();
    ReentrantLock reentrantLock = lockMap.get(lockName);
    if (reentrantLock == null) {
      reentrantLock = new ReentrantLock(true);
      lockMap.put(lockName, reentrantLock);
      reentrantLock.lock();
      accessMapLock.unlock();
    } else {
      accessMapLock.unlock();
      boolean gotProperLock = false;
      do {
        reentrantLock.lock();
        accessMapLock.lock();
        ReentrantLock storedReentrantLock = lockMap.get(lockName);
        if (reentrantLock.equals(storedReentrantLock)) {
          gotProperLock = true;
        } else {
          if (storedReentrantLock == null) {
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Instance \""
                      + instanceName
                      + "\" had removed \""
                      + lockName
                      + "\" while waiting for the lock.");
            }
            // So it was left for garbage collection.. write it back in the map
            lockMap.put(lockName, reentrantLock);
          } else {
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Instance \""
                      + instanceName
                      + "\" had created a new \""
                      + lockName
                      + "\" while a waiting for the lock.");
            }
            reentrantLock.unlock();
            reentrantLock = storedReentrantLock;
          }
        }
        accessMapLock.unlock();
      } while (!gotProperLock);
    }
  }

  /**
   * @param lockName lock
   */
  public void unlock(final String lockName) {
    if (lockName == null) {
      return;
    }
    accessMapLock.lock();
    ReentrantLock reentrantLock = lockMap.get(lockName);
    if (reentrantLock != null) {
      if (!reentrantLock.hasQueuedThreads()) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Instance \""
                  + instanceName
                  + "\" removed reference \""
                  + lockName
                  + "\".");
        }
        // No one is waiting for this lock so leave it for garbage collection
        lockMap.remove(lockName);
      }
      reentrantLock.unlock();
    } else {
      LOG.warn(
          "Instance \""
              + instanceName
              + "\" tried to unlock an non-existing entry \""
              + lockName
              + "\"");
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Unlocking. Instance \""
              + instanceName
              + "\" is currently containing "
              + lockMap.keySet().size()
              + " references.");
    }
    accessMapLock.unlock();
  }
}
