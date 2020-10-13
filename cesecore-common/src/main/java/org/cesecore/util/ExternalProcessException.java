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

import java.util.List;
import org.cesecore.CesecoreException;

/**
 * The external process exception is the base exception to handle (platform
 * dependent) external process calls ({@link ExternalProcessTools}.
 *
 * @version $Id: ExternalProcessException.java 27706 2018-01-02 13:50:59Z
 *     andresjakobs $
 */
public class ExternalProcessException extends CesecoreException {

  private static final long serialVersionUID = 1L;

  /** List. */
  private List<String> out;

  /** Default constructor. */
  public ExternalProcessException() {
    super();
  }

  /**
   * Parameterized constructor.
   *
   * @param message the message.
   * @param cause the cause
   */
  public ExternalProcessException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Parameterized constructor.
   *
   * @param message the message.
   * @param cause the cause
   * @param anOut the list.
   */
  public ExternalProcessException(
      final String message, final Throwable cause, final List<String> anOut) {
    super(message, cause);
    this.out = anOut;
  }

  /**
   * Parameterized constructor.
   *
   * @param message the message.
   */
  public ExternalProcessException(final String message) {
    super(message);
  }

  /**
   * Parameterized constructor.
   *
   * @param message the message.
   * @param anOut the list.
   */
  public ExternalProcessException(
      final String message, final List<String> anOut) {
    super(message);
    this.out = anOut;
  }

  /**
   * Parameterized constructor.
   *
   * @param cause the cause.
   */
  public ExternalProcessException(final Exception cause) {
    super(cause);
  }

  /**
   * Gets the list of exit code ({@link ExternalProcessTools#EXIT_CODE_PREFIX}),
   * STDOUT and ERROUT.
   *
   * @return the list.
   */
  public List<String> getOut() {
    return out;
  }

  /**
   * Sets the list of exit code ({@link ExternalProcessTools#EXIT_CODE_PREFIX}),
   * STDOUT and ERROUT.
   *
   * @param anOut the list.
   */
  public void setOut(final List<String> anOut) {
    this.out = anOut;
  }
}
