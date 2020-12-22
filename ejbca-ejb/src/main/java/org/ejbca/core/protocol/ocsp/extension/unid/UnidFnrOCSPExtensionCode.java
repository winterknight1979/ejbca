/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp.extension.unid;

/**
 * @version $Id: UnidFnrOCSPExtensionCode.java 28536 2018-03-21 11:48:07Z aminkh
 *     $
 */
public enum UnidFnrOCSPExtensionCode {
      /** Type. */
  ERROR_NO_ERROR(0),
  /** Type. */
  ERROR_UNKNOWN(1),
  /** Type. */
  ERROR_UNAUTHORIZED(2),
  /** Type. */
  ERROR_NO_FNR_MAPPING(3),
  /** Type. */
  ERROR_NO_SERIAL_IN_DN(4),
  /** Type. */
  ERROR_SERVICE_UNAVAILABLE(5),
  /** Type. */
  ERROR_CERT_REVOKED(6);

    /** Code. */
  private final int errorCode;

  UnidFnrOCSPExtensionCode(final int anerrorCode) {
    this.errorCode = anerrorCode;
  }

  /**
   * @return value
   */
  public int getValue() {
    return errorCode;
  }
}
