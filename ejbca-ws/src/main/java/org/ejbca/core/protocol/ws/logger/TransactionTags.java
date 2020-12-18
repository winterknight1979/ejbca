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
package org.ejbca.core.protocol.ws.logger;

public enum TransactionTags {
      /** Tag. */
  METHOD,
  /** Tag. */
  ERROR_MESSAGE,
  /** Tag. */
  ADMIN_DN,
  /** Tag. */
  ADMIN_ISSUER_DN,
  /** Tag. */
  ADMIN_REMOTE_IP,
  /** Tag. */
  ADMIN_FORWARDED_IP;

    /**
     * @return tag
     */
  @SuppressWarnings("el-syntax")
  public String getTag() {
    return "${" + toString() + "}";
  }
}
