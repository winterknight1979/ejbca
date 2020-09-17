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
 
package org.ejbca.core.model.ra.userdatasource;

import java.util.Collection;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;





/**
 * Interface containing methods that need to be implemented in order 
 * to have a custom user data source. All Custom user data sources must implement this interface.
 * 
 * @version $Id: ICustomUserDataSource.java 22117 2015-10-29 10:53:42Z mikekushner $
 */

public interface ICustomUserDataSource {
	
	/**
	 *  Method called to all newly created IUserDataSource to set it up with
	 *  saved configuration.
	 * @param properties Props
	 */
	public abstract void init(Properties properties);
	
	/**
	 * @param admin Admin
	 * @param searchstring String 
	 * @return VO
	 * @throws UserDataSourceException FAil
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#fetch(AuthenticationToken, String)
	 */   
	public Collection<UserDataSourceVO> fetch(AuthenticationToken admin, String searchstring) throws UserDataSourceException;
	
	/**
	 * @param admin Admin
	 * @param searchstring String 
	 * @param removeMultipleMatch bnool 
	 * @return Bool
	 * @throws MultipleMatchException Error
	 * @throws UserDataSourceException Error
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#removeUserData(AuthenticationToken, String, boolean)
	 */   
	public boolean removeUserData(AuthenticationToken admin, String searchstring, boolean removeMultipleMatch) throws MultipleMatchException, UserDataSourceException;
	
	
	/**
	 * @param admin Admin
	 * @throws UserDataSourceConnectionException  Error
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
	 */    
	public abstract void testConnection(AuthenticationToken admin) throws UserDataSourceConnectionException;
	

}

