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

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreRuntimeException;

/**
 * A concurrent cache allows multiple threads to cache data. Only one thread
 * will be allowed to generate data for one particular key, and other threads
 * will block.
 *
 * <p>All methods in this class and inner classes are thread-safe.
 *
 * @version $Id: ConcurrentCache.java 27456 2017-12-07 10:59:06Z samuellb $
 * @param <K> Key type
 * @param <V> Value type
 */
public final class ConcurrentCache<K, V> {

    /** Ligger. */
  private static final Logger LOG = Logger.getLogger(ConcurrentCache.class);
  /** Cache. */
  private final ConcurrentHashMap<K, InternalEntry<V>> cache =
      new ConcurrentHashMap<>();
   /** Semaphores. */
  private final ConcurrentMap<K, Object> semaphores = new ConcurrentHashMap<>();

  /** No limit. */
  public static final long NO_LIMIT = -1L;

  /** @see #setEnabled */
  private volatile boolean enabled = true;
  /** @see #setCloseOnEviction */
  private volatile boolean closeOnEviction = false;
  /** @see #setMaxEntries */
  private volatile long maxEntries = NO_LIMIT;

  /** Number. */
  private final AtomicLong numEntries = new AtomicLong(0L);
  /** Remove. */
  private final Set<K> pendingRemoval =
      Collections.newSetFromMap(new ConcurrentHashMap<K, Boolean>());
  /** Lock. */
  private final Lock isCleaning = new ReentrantLock();
  /** Last. */
  private volatile long lastCleanup = 0L;
  /** interval. */
  private volatile long cleanupInterval = 1000L;

  /**
   * Internal entries are stored in the ConcurrentMap.
   *
   * @param <V> Value type
   */
  private static final class InternalEntry<V> {
    /** Value. */
    private final V value;
    /** Expire time . */
    private volatile long expire;

    /**
     * @param aValue Value.
     */
    private InternalEntry(final V aValue) {
      this.value = aValue;
      this.expire = Long.MAX_VALUE;
    }
  }

  /**
   * A reference to a cache entry, with a get and put method to read/write data
   * from/to the cache.
   *
   * <p>All methods are thread safe, but only one thread should operate on an
   * Entry object.
   */
  public final class Entry {
      /** Key. */
    private final K key;
    /** Value. */
    private InternalEntry<V> entry;
    /**
     * If non-null, then other threads are waiting on this semaphore for data on
     * the same key in the cache.
     */
    private final Object ourSemaphore;

    private Entry(final K aKey, final InternalEntry<V> anEentry) {
      this.key = aKey;
      this.entry = anEentry;
      this.ourSemaphore = null;
    }

    private Entry(
        final K aKey,
        final InternalEntry<V> anEntry,
        final Object ourNewSemaphore) {
      if (ourNewSemaphore == null) {
        throw new IllegalArgumentException("ourSemaphore may not be null");
      }
      this.key = aKey;
      this.entry = anEntry;
      this.ourSemaphore = ourNewSemaphore;
    }

    /** @return true if the key existed in the cache. */
    public boolean isInCache() {
      return entry != null;
    }

    /**
     * @return the value read from the cache when the Entry was created. Calls
     *     to putValue() on this particular Entry change the return value.
     */
    public V getValue() {
      if (entry == null) {
        throw new IllegalStateException(
            "Tried to read from non-existent cache entry");
      }
      return entry.value;
    }

    /**
     * Updates the value in this Entry as well as in the underlying cache. The
     * expire time is set to be "infinite". Thread-safe.
     *
     * @param value value
     */
    public void putValue(final V value) {
      if (key != null) {
        entry = new InternalEntry<>(value);
        cache.put(key, entry);
      }
    }

    /**
     * Sets the validity of the value. After the cache entry expires, the next
     * request for it will fail (on purpose) so it can be updated. Requests that
     * happen while the expired entry is being updated will still use the
     * expired value, so they don't have to block.
     *
     * @param validFor Cache validity in milliseconds.
     */
    public void setCacheValidity(final long validFor) {
      if (entry != null) {
        entry.expire = System.currentTimeMillis() + validFor;
      }
    }

    /**
     * Must be called if other threads might be waiting for this cache entry
     * (i.e. if isInCache() returns false)
     */
    public void close() {
      if (ourSemaphore != null) {
        synchronized (ourSemaphore) {
          semaphores.remove(key);
          ourSemaphore.notifyAll();
        }
      }
    }
  }

  /** Creates an empty concurrent cache. */
  public ConcurrentCache() {
    // Do nothing
  }

  /**
   * Creates a concurrent cache initialized with the mapping defined in the
   * given map. Can be used for rebuilding the cache in the background for
   * instance.
   *
   * @param map map
   * @param validFor Time in milliseconds which the entry will be valid for, or
   *     -1L for forever.
   * @see ConcurrentCache#getKeys()
   */
  public ConcurrentCache(
      final Map<? extends K, ? extends V> map, final long validFor) {
    for (Map.Entry<? extends K, ? extends V> mapEntry : map.entrySet()) {
      final InternalEntry<V> intEntry =
          new InternalEntry<V>(mapEntry.getValue());
      if (validFor != -1L) {
        intEntry.expire = System.currentTimeMillis() + validFor;
      }
      cache.put(mapEntry.getKey(), intEntry);
    }
  }

  /**
   * "Opens" a cache entry. If the entry already exists, then an {@link Entry}
   * that maps to the existing entry is returned. Otherwise, a semaphore is used
   * to prevent multiple threads from creating the new cache entry. Only the
   * first thread is returned an Entry with isInCache()==false, later threads
   * will block and wait for the first thread.
   *
   * <p>For non-existent entries (i.e. isInCache()==false), the caller is
   * expected to put a value in it and call close() on the Entry.
   *
   * @param key Key in the cache.
   * @param timeout Timeout in milliseconds. The call will only be allowed to
   *     block for (approximately) this amount of time.
   * @return An Entry object that maps to an entry in the cache (existing or
   *     blank), or null if a timeout occurred.
   * @throws NullPointerException if key is null.
   */
  public Entry openCacheEntry(final K key, final long timeout) {
    final long timeAtEntry = System.currentTimeMillis();

      Objects.requireNonNull(key, "key may not be null");


    if (!enabled) {
      return new Entry(null, null);
    }

    if (maxEntries != NO_LIMIT) {
      pendingRemoval.remove(key); // always mark as used
    }

    // Fast path if cached
    InternalEntry<V> entry = cache.get(key);
    final long toExpire = entry != null ? entry.expire : 0L;
    if (entry != null && toExpire > timeAtEntry) {
      // Found valid entry in cache
      logFound(key, entry);
      cleanupIfNeeded();
      return new Entry(key, entry);
    } else if (entry != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Cache entry has expired " + key + ", expiry=" + entry.expire);
      }
      numEntries.decrementAndGet();
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Entry was not present in cache " + key);
      }
    }

    // Make sure only one thread enters "opens" the cache entry in write mode.
    // Subsequent attempts to open it will block until the first cache entry has
    // been closed.
    final Object ourSemaphore = new Object();
    final Object theirSemaphore = semaphores.putIfAbsent(key, ourSemaphore);
    if (theirSemaphore == null) {
      // We were first
      numEntries.incrementAndGet();
      cleanupIfHighlyNeeded();
      return new Entry(key, null, ourSemaphore);
    }

    // Someone else was first

    // Check if we can return an existing entry (ECA-4936)
    if (entry != null) {
      LOG.debug("Returning existing cache entry for now");
      LOG.trace("<ConcurrentCache.openCacheEntry");
      cleanupIfNeeded();
      return new Entry(key, entry);
    }

    // Wait for a fresh entry to be created
    waitForEntry(key, timeout, timeAtEntry, theirSemaphore);

    // Return cached result from other thread, or null on failure
    return getCached(key);
  }

/**
 * @param key Key
 * @param entry Entry
 */
private void logFound(final K key, final InternalEntry<V> entry) {
    if (LOG.isDebugEnabled()) {
        LOG.debug("Found valid entry in cache for key " + key);
        if (LOG.isTraceEnabled()) {
          LOG.debug("Value: " + entry.value);
          LOG.trace("<ConcurrentCache.openCacheEntry");
        }
      }
}

/**
 * @param key Key
 * @return Entry
 */
private Entry getCached(final K key) {
    InternalEntry<V> entry;
    entry = cache.get(key);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Got "
              + (entry != null ? entry.value : "null")
              + " after waiting for cache");
      LOG.trace("<ConcurrentCache.openCacheEntry");
    }
    return entry != null ? new Entry(key, entry) : null;
}

/**
 * @param key Key
 * @param timeout TO
 * @param timeAtEntry Time
 * @param theirSemaphore Sem
 * @throws CesecoreRuntimeException Fail
 */
private void waitForEntry(final K key, final long timeout,
        final long timeAtEntry, final Object theirSemaphore)
        throws CesecoreRuntimeException {
    try {
      synchronized (theirSemaphore) {
        if (!cache.containsKey(key)) {
          cleanupIfNeeded();
          theirSemaphore.wait(timeout);
          while (!cache.containsKey(key)
              && System.currentTimeMillis() < timeAtEntry + timeout) {
            theirSemaphore.wait(timeout / 10L + 1L);
          }
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new CesecoreRuntimeException(e); // should preferably not be catched
    }
}

  /**
   * @return a set of the keys in the cache. Useful for rebuilding the cache in
   *     the background.
   * @see ConcurrentCache#ConcurrentCache(Map, long)
   */
  public Set<K> getKeys() {
    return new HashSet<>(cache.keySet());
  }

  /**
   * Enables or disables caching. If disabled, nothing will be cached and
   * openCacheEntry will always immediately return an non-existent entry (this
   * may also cause concurrent attempts to fetch/build/etc the same object).
   *
   * <p>Disabling the cache doesn't stop any currently "open" cache entries from
   * being written to.
   *
   * <p>The default is enabled.
   *
   * @param isEnabled bool
   */
  public void setEnabled(final boolean isEnabled) {
    this.enabled = isEnabled;
  }

  /**
   * @return bool
   * @see ConcurrentCache#setEnabled
   */
  public boolean isEnabled() {
    return enabled;
  }

  /**
   * Turns on or off automatic closure of values on eviction from the cache.
   * Automatic closure can only be done on objects that implement the {@link
   * Closeable} interface. Exceptions from the close() method are debug logged
   * and swallowed.
   *
   * <p>The default is false.
   *
   * @param aCloseOnEviction bool
   */
  public void setCloseOnEviction(final boolean aCloseOnEviction) {
    this.closeOnEviction = aCloseOnEviction;
  }

  /**
   * @return bool
   * @see ConcurrentCache#setCloseOnEviction
   */
  public boolean isCloseOnEviction() {
    return closeOnEviction;
  }

  /**
   * Sets the desired maximum number of entries in the cache. This is not a
   * strict limit, and the cache may temporarily exceed this number.
   *
   * <p>The value {@link ConcurrentCache#NO_LIMIT} (-1) is the default.
   *
   * @param aMaxEntries Max number of entries
   */
  public void setMaxEntries(final long aMaxEntries) {
    if (aMaxEntries == NO_LIMIT || aMaxEntries > 0L) {
      this.maxEntries = aMaxEntries;
    } else {
      throw new IllegalArgumentException(
          "max entries must be either a positive value or -1");
    }
  }

  /**
   * @return max number of entries
   * @see ConcurrentCache#setMaxEntries
   */
  public long getMaxEntries() {
    return maxEntries;
  }

  /**
   * Sets the minimum time in milliseconds between two cleanup runs.
   *
   * <p>The default is 1000 (= 1 second).
   *
   * @param milliseconds cleanup interval
   */
  public void setCleanupInterval(final long milliseconds) {
    cleanupInterval = milliseconds;
  }

  /**
   * @return cleanup interval
   * @see ConcurrentCache#setCleanupInterval
   */
  public long getCleanupInterval() {
    return cleanupInterval;
  }

  private void cleanupIfNeeded() {
    if (maxEntries != NO_LIMIT && numEntries.get() > maxEntries) {
      cleanup();
    }
  }

  private void cleanupIfHighlyNeeded() {
    // More than 1.5 times the limit
    if (maxEntries != NO_LIMIT && 2L * numEntries.get() > 3L * maxEntries) {
      cleanup();
    }
  }

  /**
   * Used internally for testing.
   *
   * @param min min
   * @param max max
   */
  void checkNumberOfEntries(final long min, final long max) { // NOPMD
    long a = numEntries.get();
    long b = cache.size();
    if (a != b) {
      throw new IllegalStateException(
          "cache.size() and numEntries does not match ("
              + a
              + " and "
              + b
              + ")");
    }
    if (a < min) {
      throw new IllegalStateException(
          "number of entries (" + a + ") is less than minimum (" + min + ").");
    }
    if (a > max) {
      throw new IllegalStateException(
          "number of entries ("
              + a
              + ") is greater than maximum ("
              + max
              + ").");
    }
  }

  /**
   * Removes expired entries, and randomly selected entries that have not been
   * used since the last call.
   */
  private void cleanup() {
    List<Closeable> valuesToClose = null;
    final long startTime = System.currentTimeMillis();
    if (startTime < lastCleanup + cleanupInterval || !isCleaning.tryLock()) {
      return;
    }
    try {
      final float ratioToRemove;
      final Random random;
      if (maxEntries == NO_LIMIT) {
        ratioToRemove = 0;
        random = null;
      } else {
        // Remove a bit extra
        ratioToRemove =
            Math.max(0.0F, 1.0F - 0.8F * maxEntries / numEntries.get());

        // Remove items that have not been accessed since they were last marked
        // as "pending removal"
        if (closeOnEviction) {
          valuesToClose = new ArrayList<>();
        }
        for (K key : pendingRemoval) {
          InternalEntry<V> evicted = cache.remove(key);
          if (closeOnEviction && evicted.value instanceof Closeable) {
            valuesToClose.add((Closeable) evicted.value);
          }
          numEntries.decrementAndGet();
        }
        pendingRemoval.clear();
        random = new Random(System.nanoTime());
      }

      final long now = System.currentTimeMillis();
      final Iterator<Map.Entry<K, InternalEntry<V>>> iter =
          cache.entrySet().iterator();
      while (iter.hasNext()) {
        final Map.Entry<K, InternalEntry<V>> mapEntry = iter.next();
        if (mapEntry.getValue().expire <= now) {
          iter.remove();
          numEntries.decrementAndGet();
        } else if (maxEntries != NO_LIMIT
            && random.nextFloat() < ratioToRemove) {
          pendingRemoval.add(mapEntry.getKey());
        }
      }
    } finally {
      isCleaning.unlock();

      final long endTime = System.currentTimeMillis();
      lastCleanup = endTime;
      if (LOG.isDebugEnabled()) {
        LOG.debug("Clean up took " + (endTime - startTime) + " ms");
      }
    }

    closeValues(valuesToClose);
  }

/**
 * @param valuesToClose vals
 */
private void closeValues(final List<Closeable> valuesToClose) {
    if (valuesToClose != null) {
      for (final Closeable closable : valuesToClose) {
        try {
          closable.close();
        } catch (IOException e) {
          LOG.debug("Exception ocurring when closing evicted value.", e);
        }
      }
    }
}

  /** Removes all entries in the cache. */
  public void clear() {
    if (closeOnEviction) {
      isCleaning.lock();
      try {
        for (final InternalEntry<V> entry : cache.values()) {
          if (entry.value instanceof Closeable) {
            try {
              ((Closeable) entry.value).close();
            } catch (IOException e) {
              LOG.debug(
                  "Exception ocurring when closing value during cache"
                      + " clearing.",
                  e);
            }
          }
        }
        cache.clear();
      } finally {
        isCleaning.unlock();
      }
    } else {
      cache.clear();
    }
    numEntries.set(0L);
    pendingRemoval.clear();
    lastCleanup = 0L;
  }
}
