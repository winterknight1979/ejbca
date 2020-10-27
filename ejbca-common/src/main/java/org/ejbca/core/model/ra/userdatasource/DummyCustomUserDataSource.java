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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.core.model.SecConst;

/**
 * This is an class used for testing and example purposes. I supposed to
 * illustrate how to implement a custom userdata source to EJBCA.
 *
 * @version $Id: DummyCustomUserDataSource.java 22117 2015-10-29 10:53:42Z
 *     mikekushner $
 */
public class DummyCustomUserDataSource implements ICustomUserDataSource {

    /** logger. */
  private static Logger log = Logger.getLogger(DummyCustomUserDataSource.class);

  /** Creates a new instance of DummyCustomUserDataSource. */
  public DummyCustomUserDataSource() { }

  /**
   *
   * @param properties props
   * @see
   *     org.ejbca.core.model.ra.userdatasource.ICustomUserDataSource#init(java.util.Properties)
   */
  public void init(final Properties properties) {
    // This method sets up the communication with the publisher

    log.debug("Initializing DummyCustomUserDataSource");
  }

  /**
   * A dummy fetch implementation that returns a EndEntityInformation if the
   * searchstring "per" is given Othervise a empty collection is returned.
   *
   * @param admin token
   * @param searchstring search
   * @return results
   *
   * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
   */
  public Collection<UserDataSourceVO> fetch(
      final AuthenticationToken admin, final String searchstring)
      throws UserDataSourceException {

    List<UserDataSourceVO> result = new ArrayList<UserDataSourceVO>();
    if (searchstring.equalsIgnoreCase("per")) {
      EndEntityInformation endEntityInformation =
          new EndEntityInformation(
              "PER",
              "CN=PER,C=SE",
              1,
              "RFC822NAME=per@test.com",
              "per@test.com",
              0,
              new EndEntityType(EndEntityTypes.ENDUSER),
              1,
              1,
              null,
              null,
              SecConst.TOKEN_SOFT_BROWSERGEN,
              0,
              null);
      result.add(new UserDataSourceVO(endEntityInformation));
    }

    return result;
  }

  /**
   * @param admin token
   * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource */
  public void testConnection(final AuthenticationToken admin)
      throws UserDataSourceConnectionException {
    log.debug("DummyCustomUserDataSource, Testing connection");
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() throws Throwable {
    log.debug("DummyCustomUserDataSource, closing connection");
    // This method closes the communication with the publisher.

    super.finalize();
  }

  @Override
  public boolean removeUserData(
      final AuthenticationToken admin,
      final String searchstring,
      final boolean removeMultipleMatch)
      throws UserDataSourceException {
    log.debug(
        "DummyCustomUserDataSource, remove User Data  called with searchstring"
            + " : "
            + searchstring);
    return true;
  }
}
