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
package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;
import java.util.Map;

/**
 * Generic configuration parameters for the {@link
 * CertificateTransparency#fetchSCTList} methods, that are not specific to the
 * certificate profiles.
 *
 * @version $Id: CTSubmissionConfigParams.java 27506 2017-12-09 17:18:37Z
 *     samuellb $
 */
public final class CTSubmissionConfigParams implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logs. */
  private Map<Integer, CTLogInfo> configuredCTLogs;
  /** Policy. */
  private GoogleCtPolicy validityPolicy;

  /**
   * @return definitions (URL, public key, etc.) of the logs that can be used.
   */
  public Map<Integer, CTLogInfo> getConfiguredCTLogs() {
    return configuredCTLogs;
  }

  /**
   * @param aConfiguredCTLogs Logs
   * @see #getConfiguredCTLogs
   */
  public void setConfiguredCTLogs(
      final Map<Integer, CTLogInfo> aConfiguredCTLogs) {
    this.configuredCTLogs = aConfiguredCTLogs;
  }

  /**
   * Policy for setting min/max SCTs based on the validity.
   *
   * @return policy
   */
  public GoogleCtPolicy getValidityPolicy() {
    return validityPolicy;
  }

  /**
   * @param aValidityPolicy policy
   * @see #getValidityPolicy
   */
  public void setValidityPolicy(final GoogleCtPolicy aValidityPolicy) {
    this.validityPolicy = aValidityPolicy;
  }
}
