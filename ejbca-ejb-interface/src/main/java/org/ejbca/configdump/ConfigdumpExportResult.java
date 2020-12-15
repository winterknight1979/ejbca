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
package org.ejbca.configdump;

import java.io.Serializable;
import java.util.List;

/**
 * Holds information about the status of a Configdump export operation.
 *
 * @version $Id: ConfigdumpExportResult.java 28674 2018-04-11 15:17:34Z aminkh $
 */
public final class ConfigdumpExportResult implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Errors. */
  private final List<String> reportedErrors;

  /** warnings. */
  private final List<String> reportedWarnings;

  /**
   * @param thereportedErrors errors
   * @param thereportedWarnings warnings
   */
  public ConfigdumpExportResult(
      final List<String> thereportedErrors,
      final List<String> thereportedWarnings) {
    this.reportedErrors = thereportedErrors;
    this.reportedWarnings = thereportedWarnings;
  }

  /** @return Errors. */
  public List<String> getReportedErrors() {
    return reportedErrors;
  }

  /**
   * @return warnings
   */
  public List<String> getReportedWarnings() {
    return reportedWarnings;
  }

  /**
   * @return bool
   */
  public boolean isSuccessful() {
    return reportedErrors.isEmpty();
  }
}
