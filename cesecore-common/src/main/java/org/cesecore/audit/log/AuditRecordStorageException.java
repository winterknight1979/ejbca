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
package org.cesecore.audit.log;

import javax.ejb.ApplicationException;

/**
 * Handles secure audit log storage exceptions.
 *
 * @version $Id: AuditRecordStorageException.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
@ApplicationException(rollback = true)
public class AuditRecordStorageException extends RuntimeException {

  private static final long serialVersionUID = -2049206241984967597L;

  /** Empty exception. */
  public AuditRecordStorageException() {
    super();
  }

  /**
   * Exception with message.
   *
   * @param message Message
   */
  public AuditRecordStorageException(final String message) {
    super(message);
  }

  /**
   * Exception with cause.
   *
   * @param t Cause
   */
  public AuditRecordStorageException(final Throwable t) {
    super(t);
  }

  /**
   * Exception with cause and message.
   *
   * @param s Message
   * @param t Cause
   */
  public AuditRecordStorageException(final String s, final Throwable t) {
    super(s, t);
  }
}
