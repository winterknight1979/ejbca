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

package org.ejbca.ui.web.admin.approval;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.TimeMatch;

/**
 * Managed bean in the actionapprovallist page.
 *
 * @version $Id: ListApproveActionManagedBean.java 28844 2018-05-04 08:31:02Z
 *     samuellb $
 */
public class ListApproveActionManagedBean extends BaseManagedBean {

  private static final long serialVersionUID = 1L;
  /** Param. */
  public static final int QUERY_MAX_NUM_ROWS = 300;
  /** Param. */
  private static final String TIME_5MIN = Integer.toString(5 * 60 * 1000);
  /** Param. */
  private static final String TIME_30MIN = Integer.toString(30 * 60 * 1000);
  /** Param. */
  private static final String TIME_8HOURS
      = Integer.toString(8 * 60 * 60 * 1000);
  /** Param. */
  private static final String ALL_STATUSES = Integer.toString(-9);
  /** Param. */
  private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
  /** Param. */
  private List<SelectItem> availableStatus;
  /** Param. */
  private String selectedStatus;
  /** Param. */
  private List<SelectItem> availableTimeSpans;
  /** Param. */
  private String selectedTimeSpan;

  /** Param. */
  private ApprovalDataVOViewList listData;

  /** Construct. */
  public ListApproveActionManagedBean() {
    setSelectedStatus("" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
    setSelectedTimeSpan(TIME_30MIN);
    list();
  }

  /**
   * @return Status
   */
  public List<SelectItem> getAvailableStatus() {
    if (availableStatus == null) {
      availableStatus = new ArrayList<>();
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
              getEjbcaWebBean().getText("WAITING", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_EXPIRED,
              getEjbcaWebBean().getText("EXPIRED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED,
              getEjbcaWebBean().getText("EXPIREDANDNOTIFIED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_EXECUTED,
              getEjbcaWebBean().getText("EXECUTED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_EXECUTIONFAILED,
              getEjbcaWebBean().getText("EXECUTIONFAILED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_EXECUTIONDENIED,
              getEjbcaWebBean().getText("EXECUTIONDENIED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_APPROVED,
              getEjbcaWebBean().getText("APPROVED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              "" + ApprovalDataVO.STATUS_REJECTED,
              getEjbcaWebBean().getText("REJECTED", true),
              ""));
      availableStatus.add(
          new SelectItem(
              ALL_STATUSES, getEjbcaWebBean().getText("ALL", true), ""));
    }
    return availableStatus;
  }

  /**
   * @param anavailableStatus Status
   */
  public void setAvailableStatus(final List<SelectItem> anavailableStatus) {
    this.availableStatus = anavailableStatus;
  }

  /**
   * @return time
   */
  public List<SelectItem> getAvailableTimeSpans() {
    if (availableTimeSpans == null) {
      availableTimeSpans = new ArrayList<>();
      availableTimeSpans.add(
          new SelectItem(
              TIME_5MIN,
              "5 " + getEjbcaWebBean().getText("MINUTES", true),
              ""));
      availableTimeSpans.add(
          new SelectItem(
              TIME_30MIN,
              "30 " + getEjbcaWebBean().getText("MINUTES", true),
              ""));
      availableTimeSpans.add(
          new SelectItem(
              TIME_8HOURS,
              "8 " + getEjbcaWebBean().getText("HOURS", true),
              ""));
      availableTimeSpans.add(
          new SelectItem("0", getEjbcaWebBean().getText("EVER", true), ""));
    }
    return availableTimeSpans;
  }

  /**
   * @param theavailableTimeSpans time
   */
  public void setAvailableTimeSpans(
          final List<SelectItem> theavailableTimeSpans) {
    this.availableTimeSpans = theavailableTimeSpans;
  }

  /**
   * @return list
   */
  public String list() {
    Query query = new Query(Query.TYPE_APPROVALQUERY);
    if (selectedStatus.equals(ALL_STATUSES)) {
      query.add(getStartDate(), new Date());
    } else if (selectedStatus.equals(
        Integer.toString(ApprovalDataVO.STATUS_EXPIRED))) {
      // Expired requests will remain set as Waiting in the database.
      query.add(
          ApprovalMatch.MATCH_WITH_STATUS,
          BasicMatch.MATCH_TYPE_EQUALS,
          Integer.toString(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL),
          Query.CONNECTOR_AND);
      query.add(
          TimeMatch.MATCH_WITH_EXPIRETIME,
          null,
          new Date(),
          Query.CONNECTOR_AND);
      query.add(getStartDate(), new Date());
    } else if (selectedStatus.equals(
        Integer.toString(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL))) {
      query.add(
          ApprovalMatch.MATCH_WITH_STATUS,
          BasicMatch.MATCH_TYPE_EQUALS,
          Integer.toString(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL),
          Query.CONNECTOR_ANDNOT);
      query.add(
          TimeMatch.MATCH_WITH_EXPIRETIME,
          null,
          new Date(),
          Query.CONNECTOR_AND);
      query.add(getStartDate(), new Date());
    } else {
      query.add(
          ApprovalMatch.MATCH_WITH_STATUS,
          BasicMatch.MATCH_TYPE_EQUALS,
          selectedStatus,
          Query.CONNECTOR_AND);
      query.add(getStartDate(), new Date());
    }
    List<ApprovalDataVO> result = new ArrayList<>();
    try {
      RAAuthorization raAuthorization =
          new RAAuthorization(
              EjbcaJSFHelper.getBean().getAdmin(),
              ejbLocalHelper.getGlobalConfigurationSession(),
              ejbLocalHelper.getAuthorizationSession(),
              ejbLocalHelper.getCaSession(),
              ejbLocalHelper.getEndEntityProfileSession());
      result =
          ejbLocalHelper
              .getApprovalSession()
              .query(
                  query,
                  0,
                  QUERY_MAX_NUM_ROWS,
                  raAuthorization.getCAAuthorizationString(),
                  raAuthorization.getEndEntityProfileAuthorizationString(
                      AccessRulesConstants.APPROVE_END_ENTITY));
      if (result.size() == QUERY_MAX_NUM_ROWS) {
        String messagestring =
            getEjbcaWebBean().getText("MAXAPPROVALQUERYROWS1", true)
                + " "
                + QUERY_MAX_NUM_ROWS
                + " "
                + getEjbcaWebBean().getText("MAXAPPROVALQUERYROWS2", true);
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage(
            "error",
            new FacesMessage(
                FacesMessage.SEVERITY_ERROR, messagestring, messagestring));
      }
    } catch (IllegalQueryException e) {
      addErrorMessage("INVALIDQUERY");
    } catch (AuthorizationDeniedException e) {
      addErrorMessage("AUTHORIZATIONDENIED");
    }
    listData = new ApprovalDataVOViewList(result);
    return null;
  }

  /** @return true if approval data is sorted by request date */
  public boolean isSortedByRequestDate() {
    // ApprovalDataVOViewList.sort treats null (initial value on page load) as
    // requestDate
    return getSort() == null || getSort().equals("requestDate");
  }

  /** @return true if approval data is sorted by approve action name */
  public boolean isSortedByApproveActionName() {
    return getSort() != null && getSort().equals("approveActionName");
  }

  /** @return true if approval data is sorted by requesting administrator */
  public boolean isSortedByRequestUsername() {
    return getSort() != null && getSort().equals("requestUsername");
  }

  /** @return true if approval data is sorted by request status */
  public boolean isSortedByStatus() {
    return getSort() != null && getSort().equals("status");
  }

  /**
   * Help method to list.
   *
   * @return Date
   */
  private Date getStartDate() {
    if (Integer.parseInt(selectedTimeSpan) == 0) {
      return new Date(0);
    }
    return new Date(new Date().getTime() - Integer.parseInt(selectedTimeSpan));
  }

  /**
   * @return classes
   */
  public String getRowClasses() {
    if (listData.size() == 0) {
      return "";
    }
    if (listData.size() == 1) {
      return "Row0";
    }
    return "Row0, Row1";
  }

  /**
   * @return Data
   */
  public List<ApprovalDataVOView> getListData() {
    return listData.getData();
  }

  /**
   * @return Sort
   */
  public String getSort() {
    return listData.getSort();
  }

  /**
   * @param sort sort
   */
  public void setSort(final String sort) {
    listData.setSort(sort);
  }

  /**
   * @return bool
   */
  public boolean isAscending() {
    return listData.isAscending();
  }

  /**
   * @param ascending bool
   */
  public void setAscending(final boolean ascending) {
    listData.setAscending(ascending);
  }

  /**
   * @return status
   */
  public String getSelectedStatus() {
    return selectedStatus;
  }

  /**
   * @param aselectedStatus status
   */
  public void setSelectedStatus(final String aselectedStatus) {
    this.selectedStatus = aselectedStatus;
  }

  /**
   * @return time
   */
  public String getSelectedTimeSpan() {
    return selectedTimeSpan;
  }

  /**
   * @param aselectedTimeSpan time
   */
  public void setSelectedTimeSpan(final String aselectedTimeSpan) {
    this.selectedTimeSpan = aselectedTimeSpan;
  }
}
