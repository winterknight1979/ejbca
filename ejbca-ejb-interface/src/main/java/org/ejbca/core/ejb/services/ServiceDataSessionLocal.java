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
package org.ejbca.core.ejb.services;

import java.util.List;
import javax.ejb.Local;
import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * @author mikek
 * @version $Id: ServiceDataSessionLocal.java 19902 2014-09-30 14:32:24Z anatom
 *     $
 */
@Local
public interface ServiceDataSessionLocal extends ServiceDataSession {

  /**
   * @param name name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  ServiceData findByName(String name);

  /**
   * @param id ID
   * @return the name of the service with the given id
   */
  String findNameById(Integer id);

  /** @return return the query results as a List. */
  List<ServiceData> findAll();

  /**
   * Adds a new ServiceData object with the given parameters to persistence.
   *
   * @param id ID
   * @param name name
   * @param serviceConfiguration config
   */
  void addServiceData(
      Integer id, String name, ServiceConfiguration serviceConfiguration);

  /**
   * Update the named ServiceData entity with a new ServiceConfiguration.
   *
   * @param name name
   * @param serviceConfiguration config
   * @return true if the ServiceData exists and was updated.
   */
  boolean updateServiceConfiguration(
      String name, ServiceConfiguration serviceConfiguration);

  /**
   * Removes given parameter from persistence.
   *
   * @param id data
   */
  void removeServiceData(Integer id);

  /**
   * Updates a database row with the matching values. This way we can ensure
   * atomic operation for acquiring the semaphore for a service, independent of
   * the underlying database isolation level.
   *
   * @param serviceId id
   * @param oldRunTimeStamp stamp
   * @param oldNextRunTimeStamp stamp
   * @param newRunTimeStamp stamp
   * @param newNextRunTimeStamp stamp
   * @return true if 1 row was updated
   */
  boolean updateTimestamps(
      Integer serviceId,
      long oldRunTimeStamp,
      long oldNextRunTimeStamp,
      long newRunTimeStamp,
      long newNextRunTimeStamp);
}
