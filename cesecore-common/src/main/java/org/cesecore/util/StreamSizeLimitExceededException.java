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

/**
 * Thrown when there's too much data, e.g. in a stream when using
 * FileTools.streamCopyWithLimit
 *
 * @version $Id: StreamSizeLimitExceededException.java 22658 2016-01-28
 *     10:11:11Z mikekushner $
 */
public class StreamSizeLimitExceededException extends Exception {

  private static final long serialVersionUID = 1L;

  /** Default constructor. */
  public StreamSizeLimitExceededException() {
    super();
  }

  /**
   * @param message message
   */
  public StreamSizeLimitExceededException(final String message) {
    super(message);
  }

  /**
   * @param message message
   * @param cause cause
   */
  public StreamSizeLimitExceededException(
          final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * @param cause cause
   */
  public StreamSizeLimitExceededException(final Throwable cause) {
    super(cause);
  }
}
