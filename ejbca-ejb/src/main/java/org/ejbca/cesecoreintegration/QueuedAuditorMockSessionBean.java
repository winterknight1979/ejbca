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

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.Stateless;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.impl.queued.QueuedAuditorSessionLocal;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.query.QueryCriteria;

/**
 * Mock implementation of QueuedDevice interface to allow the secure audit code
 * imported from CESeCore to stay the same without bundling the queued
 * implementation.
 *
 * @version $Id: QueuedAuditorMockSessionBean.java 19901 2014-09-30 14:29:38Z
 *     anatom $
 */
@Stateless
public class QueuedAuditorMockSessionBean implements QueuedAuditorSessionLocal {
    /** Param. */
  private static final String UNSUPPORTED =
      "Unsupported operation. QueuedDevice is not bundled with EJBCA.";

  @Override
  public void prepareReset() throws AuditLogResetException {
    throw new RuntimeException(UNSUPPORTED);
  }

  @Override
  public void reset() throws AuditLogResetException {
    throw new RuntimeException(UNSUPPORTED);
  }

  @Override
  public AuditLogExportReport exportAuditLogs(
      final AuthenticationToken token,
      final CryptoToken cryptoToken,
      final Date timestamp,
      final boolean deleteAfterExport,
      final Map<String, Object> signatureDetails,
      final Properties properties,
      final Class<? extends AuditExporter> exporter)
      throws AuditLogExporterException {
    throw new RuntimeException(UNSUPPORTED);
  }

  @Override
  public List<? extends AuditLogEntry> selectAuditLogs(
      final AuthenticationToken token,
      final int startIndex,
      final int max,
      final QueryCriteria criteria,
      final Properties properties) {
    throw new RuntimeException(UNSUPPORTED);
  }

  @Override
  public AuditLogValidationReport verifyLogsIntegrity(
      final AuthenticationToken token,
      final Date date,
      final Properties properties)
      throws AuditLogValidatorException {
    throw new RuntimeException(UNSUPPORTED);
  }

  @Override
  public void delete(final AuthenticationToken token, final Date timestamp) {
    throw new RuntimeException(UNSUPPORTED);
  }
}
