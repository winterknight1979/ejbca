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
 * @version $Id: RaRequestsSearchRequest.java 24905 2016-12-14 15:26:52Z samuellb $
 */
public class RaRequestsSearchRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean searchingWaitingForMe;
    private boolean searchingPending;
    private boolean searchingHistorical; // processed
    private boolean searchingExpired;
    private Date startDate;
    private Date endDate;
    private Date expiresBefore;
    private boolean includeOtherAdmins;
    
    
    public boolean isSearchingWaitingForMe() {
        return searchingWaitingForMe;
    }
    
    public void setSearchingWaitingForMe(final boolean searchingWaitingForMe) {
        this.searchingWaitingForMe = searchingWaitingForMe;
    }
    
    public boolean isSearchingPending() {
        return searchingPending;
    }
    
    public void setSearchingPending(final boolean searchingPending) {
        this.searchingPending = searchingPending;
    }
    
    public boolean isSearchingHistorical() {
        return searchingHistorical;
    }
    
    public void setSearchingHistorical(final boolean searchingHistorical) {
        this.searchingHistorical = searchingHistorical;
    }
    
    public boolean isSearchingExpired() {
        return searchingExpired;
    }
    
    public void setSearchingExpired(final boolean searchingExpired) {
        this.searchingExpired = searchingExpired;
    }

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(final Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(final Date endDate) {
        this.endDate = endDate;
    }

    public Date getExpiresBefore() {
        return expiresBefore;
    }
    
    public void setExpiresBefore(final Date expiresBefore) {
        this.expiresBefore = expiresBefore;
    }

    public boolean getIncludeOtherAdmins() {
        return includeOtherAdmins;
    }

    public void setIncludeOtherAdmins(final boolean includeOtherAdmins) {
        this.includeOtherAdmins = includeOtherAdmins;
    }

}
