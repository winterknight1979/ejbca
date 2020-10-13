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
package org.cesecore.audit.audit;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * This class represents the audit log validation report. It's generated during
 * validation.
 *
 * @version $Id: AuditLogValidationReport.java 17625 2013-09-20 07:12:06Z
 *     netmackan $
 */
public class AuditLogValidationReport implements Serializable {

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AuditLogValidationReport.class);

  private static final long serialVersionUID = 1L;

  /** Errors. */
  private final List<AuditLogReportElem> errors;
  /** Warnings. */
  private final List<AuditLogReportElem> warns;

  /** Constructor. */
  public AuditLogValidationReport() {
    this.errors = new ArrayList<AuditLogReportElem>();
    this.warns = new ArrayList<AuditLogReportElem>();
  }

  /** @return list of errors in this report. */
  public List<AuditLogReportElem> errors() {
    return errors;
  }

  /**
   * Add a new error to the report list.
   *
   * @param error The error to be added.
   */
  public void error(final AuditLogReportElem error) {
    LOG.warn(
        String.format(
            "ERROR: auditlog sequence: %d -> %d. Reason: %s",
            error.getFirst(), error.getSecond(), error.getReasons()));
    this.errors.add(error);
  }

  /** @return a list of warnings in this report. */
  public List<AuditLogReportElem> warnings() {
    return this.warns;
  }

  /**
   * Add a new warning to the report.
   *
   * @param warning The warning.
   */
  public void warn(final AuditLogReportElem warning) {
    LOG.info(
        String.format(
            "WARN: auditlog sequence: %d -> %d. Reason: %s",
            warning.getFirst(), warning.getSecond(), warning.getReasons()));
    this.warns.add(warning);
  }
}
