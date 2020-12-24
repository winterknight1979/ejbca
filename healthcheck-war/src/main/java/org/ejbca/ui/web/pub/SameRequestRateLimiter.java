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
package org.ejbca.ui.web.pub;

import java.util.concurrent.locks.ReentrantLock;

/**
 * Helper class for use when multiple threads a requesting something that will
 * end up with the same result.
 *
 * <p>Instead of allowing each request to proceed, only the first will return a
 * ticket where isFirst() is false. Example use:
 *
 * <p>final static SameRequestRateLimiter&lt;Object&gt; srrl = new
 * SameRequestRateLimiter&lt;Object&gt;(); ...
 * SameRequestRateLimiter&lt;Object&gt;.Result result = srrl.getResult(); if
 * (result.isFirst()) { try { // Perform common action result.setValue(...); }
 * catch (Throwable t) { result.setError(t); } } Object resultValue =
 * result.getValue(); ...
 *
 * @version $Id: SameRequestRateLimiter.java 20084 2014-10-27 13:00:50Z jeklund
 *     $
 * @param <T> Type
 */
public class SameRequestRateLimiter<T> {

  /**
   * Lock for keeping all but the first thread hanging and waiting for the first
   * thread to calculate the result.
   */
  private final ReentrantLock rateLimiterLock = new ReentrantLock(false);
  /** Lock for modifying the current shared Result object. */
  private final ReentrantLock resultObjectLock = new ReentrantLock(false);
  /**
   * Shared Result object between all the threads that asks for the result while
   * the first calling thread is calculating the result.
   */
  private Result result = null;

  public class Result {
        /** Param. */
    private boolean isFirst = true;
    /** Param. */
    private T value;
    /** Param. */
    private Throwable throwable = null;

    /** @return true if the setValue should be called. */
    public boolean isFirst() {
      return isFirst;
    }

    /**
     * @return the result if isFirst returns false or setValue has been called.
     */
    public T getValue() {
      if (isFirst) {
        // Programming/meatware problem..
        throw new IllegalStateException(
            "Current thread should have called setValue first!");
      }
      if (throwable != null) {
        throw new RuntimeException(throwable);
      }
      return value;
    }

    /**
     * Store result of operation and release all pending threads.
     *
     * @param avalue Value
     */
    public void setValue(final T avalue) {
      // Acquire a lock for modifying the class level result reference (we will
      // reset it)
      resultObjectLock.lock();
      try {
        this.isFirst = false; // Allow getValue() method to be called.
        this.value = avalue;
        result =
            null; // First new thread entering getResult() will start working on
                  // a new Result.
        /*
         * At this point we have a result of the operation and other
         * threads waiting in the getResult() method
         * are allowed to proceed and return the shared Result object.
         */
        rateLimiterLock.unlock();
      } finally {
        resultObjectLock.unlock();
      }
    }

    /**
     * Store resulting exception and release all pending threads.
     *
     * @param athrowable Exception
     */
    public void setError(final Throwable athrowable) {
      // Acquire a lock for modifying the class level result reference (we will
      // reset it)
      resultObjectLock.lock();
      try {
        this.isFirst = false; // Allow getValue() method to be called.
        this.throwable = athrowable;
        result =
            null; // First new thread entering getResult() will start working on
                  // a new Result.
        /*
         * At this point we have a result of the operation and other
         * threads waiting in the getResult() method
         * are allowed to proceed and return the shared Result object.
         */
        rateLimiterLock.unlock();
      } finally {
        resultObjectLock.unlock();
      }
    }
  }

  /** @return a result object that is shared by multiple threads. */
  public Result getResult() {
    /*
     * Create a new shared Result object, if no such exist. This will only
     *  happen during:
     * 1. First call to this method after this class has been instantiated.
     * 2. First call to this method after the previous Result object has
     * been assigned a value and is no longer
     *    referenced by this instance.
     */
    resultObjectLock.lock();
    // Declared as a method local reference, so we can return the value even if
    // the class level reference has been reset.
    final Result aresult;
    try {
      if (this.result == null) {
        this.result = new Result();
      }
      aresult = this.result;
    } finally {
      resultObjectLock.unlock();
    }
    /*
     * Acquire a lock on this instance. The first thread passed this point
     * will not release the lock, leaving all
     * other threads waiting here.
     *
     * Once the first thread has a result and set it on the Result object,
     *  the lock will be releases and the other
     * threads will be able to return the same result object
     */
    rateLimiterLock.lock();
    try {
      return aresult;
    } finally {
      if (!aresult.isFirst()) {
        rateLimiterLock.unlock();
      }
    }
  }
}
