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
package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.Date;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Holds an authentication token (admin) and a timestamp.
 *
 * @version $Id: TimeAndAdmin.java 23883 2016-07-12 21:16:07Z samuellb $
 */
public final class TimeAndAdmin implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Date. */
  private final Date date;
  /** Token. */
  private final AuthenticationToken admin;

  /**
   * @param adate Date
   * @param anadmin Token
   */
  public TimeAndAdmin(final Date adate, final AuthenticationToken anadmin) {
    this.date = adate;
    this.admin = anadmin;
  }

  /**
   * @return date
   */
  public Date getDate() {
    return date;
  }

  /**
   * @return token
   */
  public AuthenticationToken getAdmin() {
    return admin;
  }
}
