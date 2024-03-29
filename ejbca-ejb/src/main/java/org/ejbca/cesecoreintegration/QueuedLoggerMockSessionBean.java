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
package org.ejbca.cesecoreintegration;

import javax.ejb.Stateless;

import org.cesecore.audit.AuditLogger;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.queued.QueuedLoggerSessionLocal;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.TrustedTime;

/**
 * Mock implementation of QueuedDevice interface to allow the secure audit code
 * imported from CESeCore to stay the same without bundling the queued
 * implementation.
 *
 * @version $Id: QueuedLoggerMockSessionBean.java 19901 2014-09-30 14:29:38Z
 *     anatom $
 */
@Stateless
public class QueuedLoggerMockSessionBean implements QueuedLoggerSessionLocal {

    /** Param. */
  private static final String UNSUPPORTED =
      "Unsupported operation. QueuedDevice is not bundled with EJBCA.";

  @Override
  public void log(
      final TrustedTime trustedTime,
      final AuditLogger.Event event,
      final ModuleType module,
      final ServiceType service,
      final String authToken,
      final String customId,
      final AuditLogger.Details details)
      throws AuditRecordStorageException {
    throw new RuntimeException(UNSUPPORTED);
  }
}
