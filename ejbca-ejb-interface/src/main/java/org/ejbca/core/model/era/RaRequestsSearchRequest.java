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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.Date;

/**
 * Contains search parameters for searchForApprovalRequests.
 *
 * @version $Id: RaRequestsSearchRequest.java 24905 2016-12-14 15:26:52Z
 *     samuellb $
 */
public class RaRequestsSearchRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private boolean searchingWaitingForMe;
  /** Param. */
  private boolean searchingPending;
  /** Param. */
  private boolean searchingHistorical; // processed
  /** Param. */
  private boolean searchingExpired;
  /** Param. */
  private Date startDate;
  /** Param. */
  private Date endDate;
  /** Param. */
  private Date expiresBefore;
  /** Param. */
  private boolean includeOtherAdmins;

  /**
   * @return bool
   */
  public boolean isSearchingWaitingForMe() {
    return searchingWaitingForMe;
  }

  /**
   * @param issearchingWaitingForMe bool
   */
  public void setSearchingWaitingForMe(final boolean issearchingWaitingForMe) {
    this.searchingWaitingForMe = issearchingWaitingForMe;
  }

  /**
   * @return bool
   */
  public boolean isSearchingPending() {
    return searchingPending;
  }

  /**
   * @param issearchingPending bool
   */
  public void setSearchingPending(final boolean issearchingPending) {
    this.searchingPending = issearchingPending;
  }

  /**
   * @return bool
   */
  public boolean isSearchingHistorical() {
    return searchingHistorical;
  }

  /**
   * @param issearchingHistorical bool
   */
  public void setSearchingHistorical(final boolean issearchingHistorical) {
    this.searchingHistorical = issearchingHistorical;
  }

  /**
   * @return bool
   */
  public boolean isSearchingExpired() {
    return searchingExpired;
  }

  /**
   * @param issearchingExpired bool
   */
  public void setSearchingExpired(final boolean issearchingExpired) {
    this.searchingExpired = issearchingExpired;
  }

  /**
   * @return Date
   */
  public Date getStartDate() {
    return startDate;
  }

  /**
   * @param astartDate Date
   */
  public void setStartDate(final Date astartDate) {
    this.startDate = astartDate;
  }

  /**
   * @return Date
   */
  public Date getEndDate() {
    return endDate;
  }

  /**
   * @param anendDate Date
   */
  public void setEndDate(final Date anendDate) {
    this.endDate = anendDate;
  }

  /**
   * @return Date
   */
  public Date getExpiresBefore() {
    return expiresBefore;
  }

  /**
   * @param anexpiresBefore Date
   */
  public void setExpiresBefore(final Date anexpiresBefore) {
    this.expiresBefore = anexpiresBefore;
  }

  /**
   * @return bool
   */
  public boolean getIncludeOtherAdmins() {
    return includeOtherAdmins;
  }

  /**
   * @param isincludeOtherAdmins bool
   */
  public void setIncludeOtherAdmins(final boolean isincludeOtherAdmins) {
    this.includeOtherAdmins = isincludeOtherAdmins;
  }
}
