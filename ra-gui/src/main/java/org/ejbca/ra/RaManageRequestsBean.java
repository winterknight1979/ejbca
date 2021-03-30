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
package org.ejbca.ra;

import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRequestsSearchRequest;
import org.ejbca.core.model.era.RaRequestsSearchResponse;

/**
 * Backing bean for Manage Requests page (for a list of requests).
 *
 * @see RaManageRequestBean
 * @version $Id: RaManageRequestsBean.java 28085 2018-01-24 09:20:32Z henriks $
 *     TODO: Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaManageRequestsBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG =
      Logger.getLogger(RaManageRequestsBean.class);

  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

  /** Param. */
  @ManagedProperty(value = "#{raAccessBean}")
  private RaAccessBean raAccessBean;

  /**
   *
   * @param araAccessBean bean
   */
  public void setRaAccessBean(final RaAccessBean araAccessBean) {
    this.raAccessBean = araAccessBean;
  }

  /** Param. */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;

  /**
   *
   * @param araAuthenticationBean bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }

  /** Param. */
  @ManagedProperty(value = "#{raLocaleBean}")
  private RaLocaleBean raLocaleBean;

  /**
   *
   * @param araLocaleBean bean
   */
  public void setRaLocaleBean(final RaLocaleBean araLocaleBean) {
    this.raLocaleBean = araLocaleBean;
  }

  /** Param. */
  private RaRequestsSearchResponse lastExecutedResponse = null;

  /** Param. */
  private List<ApprovalRequestGUIInfo> resultsFiltered = new ArrayList<>();

  private enum ViewTab {
      /** Param. */
    TO_APPROVE,
    /** Param. */
    PENDING,
    /** Param. */
    PROCESSED,
    /** Param. */
    CUSTOM_SEARCH
  };

  /** Param. */
  private ViewTab viewTab = ViewTab.TO_APPROVE;
  /** Param. */
  private boolean customSearchingWaiting = true;
  /** Param. */
  private boolean customSearchingProcessed = true;
  /** Param. */
  private boolean customSearchingExpired = true;
  /** Param. */
  private String customSearchStartDate;
  /** Param. */
  private String customSearchEndDate;
  /** Param. */
  private String customSearchExpiresDays;

  private enum SortBy {
      /** Param. */
    ID,
    /** Param. */
    REQUEST_DATE,
    /** Param. */
    CA,
    /** Param. */
    TYPE,
    /** Param. */
    DISPLAY_NAME,
    /** Param. */
    REQUESTER_NAME,
    /** Param. */
    STATUS
  };

  /** Param. */
  private SortBy sortBy = SortBy.REQUEST_DATE;
  /** Param. */
  private boolean sortAscending = true;

  /**
   * @return Tab
   */
  public String getTab() {
    return viewTab != null ? viewTab.name().toLowerCase(Locale.ROOT) : null;
  }

  /**
   * @param avalue Value
   */
  public void setTab(final String avalue) {
    try {
      viewTab =
          !StringUtils.isBlank(avalue)
              ? ViewTab.valueOf(avalue.toUpperCase(Locale.ROOT))
              : ViewTab.TO_APPROVE;
    } catch (IllegalArgumentException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Invalid value for the 'tab' parameter: '" + avalue + "'");
      }
      viewTab = ViewTab.TO_APPROVE;
    }
  }

  /**
   * @return Bool
   */
  public boolean isViewingNeedsApproval() {
    return viewTab == ViewTab.TO_APPROVE;
  }

  /**
   * @return Bool
   */
  public boolean isViewingPendingApproval() {
    return viewTab == ViewTab.PENDING;
  }

  /**
   * @return Bool
   */
  public boolean isViewingProcessed() {
    return viewTab == ViewTab.PROCESSED;
  }

  /**
   * @return Bool
   */
  public boolean isViewingCustom() {
    return viewTab == ViewTab.CUSTOM_SEARCH;
  }

  /**
   * Search.
   */
  public void searchAndFilter() {
    final RaRequestsSearchRequest searchRequest = new RaRequestsSearchRequest();
    switch (viewTab) {
      case CUSTOM_SEARCH:
        try {
          // TODO timezone?
          if (!StringUtils.isBlank(customSearchStartDate)) {
            searchRequest.setStartDate(
                new SimpleDateFormat("yyyy-MM-dd")
                    .parse(customSearchStartDate.trim()));
          }
          if (!StringUtils.isBlank(customSearchEndDate)) {
            final Calendar cal = Calendar.getInstance();
            cal.setTime(
                new SimpleDateFormat("yyyy-MM-dd")
                    .parse(customSearchEndDate.trim()));
            cal.add(Calendar.DAY_OF_MONTH, 1);
            searchRequest.setEndDate(cal.getTime());
          }
          if (!StringUtils.isBlank(customSearchExpiresDays)) {
            final Calendar cal = Calendar.getInstance();
            cal.setTime(new Date());
            cal.add(
                Calendar.DAY_OF_MONTH,
                Integer.parseInt(customSearchExpiresDays.trim()));
            searchRequest.setExpiresBefore(cal.getTime());
            // Only requests in waiting state can expire
            customSearchingWaiting = true;
            customSearchingProcessed = false;
            customSearchingExpired = false;
          }
          searchRequest.setSearchingWaitingForMe(customSearchingWaiting);
          searchRequest.setSearchingPending(
              customSearchingWaiting); // those are also waiting
          searchRequest.setSearchingHistorical(customSearchingProcessed);
          searchRequest.setSearchingExpired(customSearchingExpired);
          searchRequest.setIncludeOtherAdmins(true);
        } catch (ParseException e) {
          // Text field is validated by f:validateRegex, so shouldn't happen
          throw new IllegalStateException("Invalid date value", e);
        }
        break;
      case TO_APPROVE:
        searchRequest.setSearchingWaitingForMe(true);
        break;
      case PENDING:
        searchRequest.setSearchingPending(true);
        break;
      case PROCESSED:
        searchRequest.setSearchingHistorical(true);
        break;
      default: break;
    }

    Map<Integer, String> raInfoMap =
        raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(
            raAuthenticationBean.getAuthenticationToken());

    lastExecutedResponse =
        raMasterApiProxyBean.searchForApprovalRequests(
            raAuthenticationBean.getAuthenticationToken(), searchRequest);

    final List<RaApprovalRequestInfo> reqInfos =
        lastExecutedResponse.getApprovalRequests();
    final List<ApprovalRequestGUIInfo> guiInfos = new ArrayList<>();

    /*
     * Based on the tabs in the GUI we have different criteria to show requests:
     * TO_APPROVE tab: Check if user is authorized to approve and also if she
     * has proper EEP. PENDING FOR APROVAL: Only those request issued by me
     * should be shown! PROCESSED & CUSTOM_SEARCH: Basically all the request
     * minus those which the user doesn't have power to approve.
     */
    for (final RaApprovalRequestInfo reqInfo : reqInfos) {
      final ApprovalRequestGUIInfo approvalRequestGuiInfo =
          new ApprovalRequestGUIInfo(reqInfo, raLocaleBean, raAccessBean);
      if (searchRequest.isSearchingWaitingForMe()
          && approvalRequestGuiInfo.isCanApprove()
          && !raInfoMap.isEmpty()) {
        guiInfos.add(approvalRequestGuiInfo);
      } else if (searchRequest.isSearchingPending()
          && (approvalRequestGuiInfo.isRequestedByMe()
              || approvalRequestGuiInfo.isCanView())) {
        guiInfos.add(approvalRequestGuiInfo);
      } else if (searchRequest.isSearchingHistorical()
          && !approvalRequestGuiInfo.isCanApprove()) {
        guiInfos.add(approvalRequestGuiInfo);
      } else if (searchRequest.isSearchingExpired()) {
        guiInfos.add(approvalRequestGuiInfo);
      }
    }

    resultsFiltered = guiInfos;
    sort();
  }

  /**
   * @return Bool
   */
  public boolean isCustomSearchingWaiting() {
    return customSearchingWaiting;
  }

  /**
   * @param iscustomSearchingWaiting Bool
   */
  public void setCustomSearchingWaiting(
          final boolean iscustomSearchingWaiting) {
    this.customSearchingWaiting = iscustomSearchingWaiting;
  }

  /**
   * @return Bool
   */
  public boolean isCustomSearchingProcessed() {
    return customSearchingProcessed;
  }

  /**
   * @param iscustomSearchingProcessed Bool
   */
  public void setCustomSearchingProcessed(
      final boolean iscustomSearchingProcessed) {
    this.customSearchingProcessed = iscustomSearchingProcessed;
  }

  /**
   * @return Bool
   */
  public boolean isCustomSearchingExpired() {
    return customSearchingExpired;
  }

  /**
   * @param iscustomSearchingExpired bool
   */
  public void setCustomSearchingExpired(
          final boolean iscustomSearchingExpired) {
    this.customSearchingExpired = iscustomSearchingExpired;
  }

  /**
   * @return Date
   */
  public String getCustomSearchStartDate() {
    return customSearchStartDate;
  }

  /**
   * @param startDate Date
   */
  public void setCustomSearchStartDate(final String startDate) {
    this.customSearchStartDate = StringUtils.trim(startDate);
  }

  /**
   * @return Date
   */
  public String getCustomSearchEndDate() {
    return customSearchEndDate;
  }

  /**
   * @param endDate Date
   */
  public void setCustomSearchEndDate(final String endDate) {
    this.customSearchEndDate = StringUtils.trim(endDate);
  }

  /**
   * @return Days
   */
  public String getCustomSearchExpiresDays() {
    return customSearchExpiresDays;
  }

  /**
   * @param acustomSearchExpiresDays Days
   */
  public void setCustomSearchExpiresDays(
          final String acustomSearchExpiresDays) {
    this.customSearchExpiresDays = StringUtils.trim(acustomSearchExpiresDays);
  }

  /**
   * @return list
   */
  public List<ApprovalRequestGUIInfo> getFilteredResults() {
    return resultsFiltered;
  }

  /**
   * @return bool
   */
  public boolean isMoreResultsAvailable() {
    return lastExecutedResponse != null
        && lastExecutedResponse.isMightHaveMoreResults();
  }

  // Sorting
  private void sort() {
    Collections.sort(
        resultsFiltered,
        new Comparator<ApprovalRequestGUIInfo>() {
          @Override
          public int compare(
              final ApprovalRequestGUIInfo o1,
              final ApprovalRequestGUIInfo o2) {
            int sortDir = (isSortAscending() ? 1 : -1);
            switch (sortBy) {
                // TODO locale-aware sorting
              case ID:
                return o1.getId().compareTo(o2.getId()) * sortDir;
              case CA:
                return o1.getCa().compareTo(o2.getCa()) * sortDir;
              case TYPE:
                return o1.getType().compareTo(o2.getType()) * sortDir;
              case DISPLAY_NAME:
                return o1.getDisplayName().compareTo(o2.getDisplayName())
                    * sortDir;
              case REQUESTER_NAME:
                return o1.getRequesterName().compareTo(o2.getRequesterName())
                    * sortDir;
              case STATUS:
                return o1.getStatus().compareTo(o2.getStatus()) * sortDir;
              case REQUEST_DATE:
              default:
                // We compare the date objects (o1.request.getRequestDate()) and
                // not the strings (o1.getRequestDate())
                return o1.request
                        .getApprovalData()
                        .getRequestDate()
                        .compareTo(
                            o2.request.getApprovalData().getRequestDate())
                    * sortDir;
            }
          }
        });
  }
  /**
   * @return sorted.
   */
  public String getSortedByRequestDate() {
    return getSortedBy(SortBy.REQUEST_DATE);
  }

  /**
   * Sort.
   */
  public void sortByRequestDate() {
    sortBy(
        SortBy.REQUEST_DATE,
        viewTab == ViewTab.PROCESSED || viewTab == ViewTab.CUSTOM_SEARCH);
  }

  /**
   * @return sorted.
   */
  public String getSortedByID() {
    return getSortedBy(SortBy.ID);
  }
  /**
   * Sort.
   */
  public void sortByID() {
    sortBy(SortBy.ID, false);
  }

  /**
   * @return sorted.
   */
  public String getSortedByCA() {
    return getSortedBy(SortBy.CA);
  }
  /**
   * Sort.
   */
  public void sortByCA() {
    sortBy(SortBy.CA, true);
  }

  /**
   * @return sorted.
   */
  public String getSortedByType() {
    return getSortedBy(SortBy.TYPE);
  }
  /**
   * Sort.
   */
  public void sortByType() {
    sortBy(SortBy.TYPE, true);
  }

  /**
   * @return sorted.
   */
  public String getSortedByDisplayName() {
    return getSortedBy(SortBy.DISPLAY_NAME);
  }
  /**
   * Sort.
   */
  public void sortByDisplayName() {
    sortBy(SortBy.DISPLAY_NAME, true);
  }

  /**
   * @return sorted.
   */
  public String getSortedByRequesterName() {
    return getSortedBy(SortBy.REQUESTER_NAME);
  }
  /**
   * Sort.
   */
  public void sortByRequesterName() {
    sortBy(SortBy.REQUESTER_NAME, true);
  }

  /**
   * @return sorted.
   */
  public String getSortedByStatus() {
    return getSortedBy(SortBy.STATUS);
  }

  /**
   * Sort.
   */
  public void sortByStatus() {
    sortBy(SortBy.STATUS, true);
  }

  /**
   * @return col
   */
  public String getSortColumn() {
    return sortBy.name();
  }

  /**
   * @param value col
   */
  public void setSortColumn(final String value) {
    try {
      sortBy =
          !StringUtils.isBlank(value)
              ? SortBy.valueOf(value.toUpperCase(Locale.ROOT))
              : SortBy.REQUEST_DATE;
    } catch (IllegalArgumentException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Invalid value for the 'sortColumn' parameter: '" + value + "'");
      }
      sortBy = SortBy.REQUEST_DATE;
    }
  }

  private String getSortedBy(final SortBy asortBy) {
    if (this.sortBy.equals(asortBy)) {
      return isSortAscending() ? "\u25bc" : "\u25b2";
    }
    return "";
  }

  /**
   * Set current sort column. Flip the order if the column was already selected.
   *
   * @param asortBy Column
   * @param isdefaultAscending Order
   */
  private void sortBy(final SortBy asortBy, final boolean isdefaultAscending) {
    if (this.sortBy.equals(asortBy)) {
      sortAscending = !isSortAscending();
    } else {
      sortAscending = isdefaultAscending;
    }
    this.sortBy = asortBy;
    sort();
  }

  /**
   * @return bool
   */
  public boolean isSortAscending() {
    return sortAscending;
  }

  /**
   * @param value bool
   */
  public void setSortAscending(final boolean value) {
    sortAscending = value;
  }
}
