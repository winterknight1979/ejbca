/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.scep;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.ScepConfiguration;

/**
 * Interface for SCEP plugins which require perform operations.
 *
 * @version $Id: ScepOperationPlugin.java 33852 2019-11-14 13:27:03Z
 *     jekaterina_b_helmes $
 */
public interface ScepOperationPlugin {

  /**
   * Performs an operation on this extension.
   *
   * @param authenticationToken an authentication token for any operations that
   *     may require one
   * @param reqmsg the requestmessage to perform operations on
   * @param scepConfig the SCEP configuration, if required
   * @param alias alias of the SCEP configuration
   * @return true if the operation succeeded
   * @throws AuthorizationDeniedException if request was denied due to
   *     authorization error
   */
  boolean performOperation(
      AuthenticationToken authenticationToken,
      ScepRequestMessage reqmsg,
      ScepConfiguration scepConfig,
      String alias)
      throws AuthorizationDeniedException;
}
