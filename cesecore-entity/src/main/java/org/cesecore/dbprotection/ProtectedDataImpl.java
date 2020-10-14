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
package org.cesecore.dbprotection;

/**
 * Interface that is inherited by actual implementations used to provide
 * database integrity protection.
 *
 * @version $Id: ProtectedDataImpl.java 29874 2018-09-13 09:38:35Z samuellb $
 */
public interface ProtectedDataImpl {

  /**
   * Sets the table name if the entity being protected.
   *
   * @param table table
   */
  void setTableName(String table);

  /**
   * Creates and sets the actual database integrity protection, or does nothing.
   *
   * @param obj object
   */
  void protectData(ProtectedData obj);

  /**
   * Reads and verifies the actual database integrity protection, or does
   * nothing.
   *
   * @param obj object
   */
  void verifyData(ProtectedData obj);

  /**
   * @param obj Object
   * @return Protection
   */
  String calculateProtection(ProtectedData obj);

  /**
   * Throws DatabaseProtectionException if erroronverifyfail is enabled in
   * databaseprotection.properties and logs a "row protection failed" message on
   * ERROR level.
   *
   * @param e exception
   * @throws DatabaseProtectionException the exception given as parameter if
   *     erroronverifyfail is enabled
   */
  void onDataVerificationError(DatabaseProtectionException e);
}
