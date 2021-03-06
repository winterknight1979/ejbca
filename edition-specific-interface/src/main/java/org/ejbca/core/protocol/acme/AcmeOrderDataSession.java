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
package org.ejbca.core.protocol.acme;

import java.util.List;
import java.util.Set;

/**
 * @version $Id: AcmeOrderDataSession.java 25797 2017-05-04 15:52:00Z tarmor $
 */
public interface AcmeOrderDataSession {

  /**
   * @param orderId the ID of the order
   * @return the sought order, or null if none exists
   */
  AcmeOrder getAcmeOrder(String orderId);

  /**
   * @param accountId the ID of the order's associated account
   * @return the sought order, or null if none exists
   */
  Set<AcmeOrder> getAcmeOrdersByAccountId(String accountId);

  /**
   * @param fingerprint the fingerprint filed of the order entry
   * @return the sought orders, or null if none exists
   */
  Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(String fingerprint);

  /**
   * Create or update the AcmeOrder.
   *
   * @param acmeOrder order
   * @return the persisted version of the AcmeOrder.
   */
  String createOrUpdate(AcmeOrder acmeOrder);

  /**
   * Create or update the AcmeOrders.
   *
   * @param acmeOrders orders
   * @return the list of persisted versions of the AcmeOrders.
   */
  List<String> createOrUpdate(List<AcmeOrder> acmeOrders);

  /**
   * Remove the AcmeOrder.
   *
   * @param orderId ID
   */
  void remove(String orderId);

  /**
   * Remove the AcmeOrders.
   *
   * @param orderIds IDs
   */
  void removeAll(List<String> orderIds);
}
