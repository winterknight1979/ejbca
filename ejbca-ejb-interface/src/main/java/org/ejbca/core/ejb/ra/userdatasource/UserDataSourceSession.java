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
package org.ejbca.core.ejb.ra.userdatasource;

import java.util.Collection;
import java.util.HashMap;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;

/**
 * @version $Id: UserDataSourceSession.java 19902 2014-09-30 14:32:24Z anatom $
 */
public interface UserDataSourceSession {

  /**
   * Main method used to fetch userdata from the given user data sources See
   * BaseUserDataSource class for further documentation about function Checks
   * that the administrator is authorized to fetch userdata.
   *
   * @param admin admin
   * @param userdatasourceids a Collection (Integer) of userdatasource Ids.
   * @param searchstring string
   * @return Collection of UserDataSourceVO, empty if no userdata could be
   *     found.
   * @throws AuthorizationDeniedException fail
   * @throws UserDataSourceException fail
   * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
   */
  Collection<UserDataSourceVO> fetch(
      AuthenticationToken admin,
      Collection<Integer> userdatasourceids,
      String searchstring)
      throws AuthorizationDeniedException, UserDataSourceException;

  /**
   * method used to remove userdata from the given user data sources. This
   * functionality is optianal of a user data implementation and is not certain
   * it is implemented See BaseUserDataSource class for further documentation
   * about function
   *
   * <p>Checks that the administrator is authorized to remove userdata.
   *
   * @param admin admin
   * @param userdatasourceids a Collection (Integer) of userdatasource Ids.
   * @param searchstring dtring
   * @param removeMultipleMatch bool
   * @return true if the user was remove successfully from at least one of the
   *     user data sources.
   * @throws AuthorizationDeniedException fail
   * @throws MultipleMatchException fail
   * @throws UserDataSourceException fail
   * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
   */
  boolean removeUserData(
      AuthenticationToken admin,
      Collection<Integer> userdatasourceids,
      String searchstring,
      boolean removeMultipleMatch)
      throws AuthorizationDeniedException, MultipleMatchException,
          UserDataSourceException;

  /**
   * Test the connection to a user data source.
   *
   * @param admin admin
   * @param userdatasourceid the id of the userdatasource to test.
   * @throws UserDataSourceConnectionException fail
   * @throws AuthorizationDeniedException fail
   * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
   */
  void testConnection(AuthenticationToken admin, int userdatasourceid)
      throws UserDataSourceConnectionException, AuthorizationDeniedException;

  /**
   * Adds a user data source to the database.
   *
   * @param admin admin
   * @param name name
   * @param userdatasource DS
   * @throws UserDataSourceExistsException if user data source already exists
   * @throws AuthorizationDeniedException fail
   */
  void addUserDataSource(
      AuthenticationToken admin, String name, BaseUserDataSource userdatasource)
      throws UserDataSourceExistsException, AuthorizationDeniedException;

  /**
   * Adds a user data source to the database. Used for importing and exporting
   * profiles from xml-files.
   *
   * @param admin admin
   * @param id ID
   * @param name name
   * @param userdatasource DS
   * @throws UserDataSourceExistsException if user data source already exists.
   * @throws AuthorizationDeniedException fail
   */
  void addUserDataSource(
      AuthenticationToken admin,
      int id,
      String name,
      BaseUserDataSource userdatasource)
      throws UserDataSourceExistsException, AuthorizationDeniedException;

  /**
   * Updates user data source data.
   *
   * @param admin admin
   * @param name name
   * @param userdatasource DS
   * @throws AuthorizationDeniedException fail
   */
  void changeUserDataSource(
      AuthenticationToken admin, String name, BaseUserDataSource userdatasource)
      throws AuthorizationDeniedException;

  /**
   * Adds a user data source with the same content as the original.
   *
   * @param admin admin
   * @param oldname name
   * @param newname name
   * @throws UserDataSourceExistsException if user data source already exists
   * @throws AuthorizationDeniedException fail
   */
  void cloneUserDataSource(
      AuthenticationToken admin, String oldname, String newname)
      throws UserDataSourceExistsException, AuthorizationDeniedException;

  /**
   * Removes a user data source.
   *
   * @param admin admin
   * @param name name
   * @return DS
   * @throws AuthorizationDeniedException fail
   */
  boolean removeUserDataSource(AuthenticationToken admin, String name)
      throws AuthorizationDeniedException;

  /**
   * Renames a user data source
   *
   * @param admin admin
   * @param oldname name
   * @param newname name
   * @throws UserDataSourceExistsException if user data source already exists
   * @throws AuthorizationDeniedException fail
   */
  void renameUserDataSource(
      AuthenticationToken admin, String oldname, String newname)
      throws UserDataSourceExistsException, AuthorizationDeniedException;

  /**
   * Retrieves a Collection of id:s (Integer) to authorized user data sources.
   *
   * @param admin admin
   * @param includeAnyCA indicates if sources with anyca set should be included
   * @return Collection of id:s (Integer)
   */
  Collection<Integer> getAuthorizedUserDataSourceIds(
      AuthenticationToken admin, boolean includeAnyCA);

  /**
   * Method creating a hashmap mapping user data source id (Integer) to user
   * data source name (String).
   *
   * @param admin admin
   * @return map
   */
  HashMap<Integer, String> getUserDataSourceIdToNameMap(
      AuthenticationToken admin);

  /**
   * Retrieves a named user data source.
   *
   * @param admin admin
   * @param name name
   * @return DS
   */
  BaseUserDataSource getUserDataSource(AuthenticationToken admin, String name);

  /**
   * Finds a user data source by id.
   *
   * @param admin admin
   * @param id ID
   * @return DS
   */
  BaseUserDataSource getUserDataSource(AuthenticationToken admin, int id);

  /**
   * Help method used by user data source proxys to indicate if it is time to
   * update it's data.
   *
   * @param admin admin
   * @param userdatasourceid DS
   * @return count
   */
  int getUserDataSourceUpdateCount(
      AuthenticationToken admin, int userdatasourceid);

  /**
   * Returns a user data source id, given it's user data source name
   *
   * @param admin admin
   * @param name name
   * @return the id or 0 if the user data source cannot be found.
   */
  int getUserDataSourceId(AuthenticationToken admin, String name);

  /**
   * Returns a user data source name given its id.
   *
   * @param admin admin
   * @param id ID
   * @return the name or null if id doesnt exists
   */
  String getUserDataSourceName(AuthenticationToken admin, int id);
}
