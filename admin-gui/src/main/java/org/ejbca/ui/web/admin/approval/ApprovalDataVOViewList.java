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

import java.io.Serializable;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import org.ejbca.core.model.approval.ApprovalDataVO;

/**
 * Class used to manage the list of approvaldatas resulted in the query.
 *
 * @version $Id: ApprovalDataVOViewList.java 28844 2018-05-04 08:31:02Z samuellb
 *     $
 */
public class ApprovalDataVOViewList extends AbstractList<ApprovalDataVOView>
    implements Serializable {

  private static final long serialVersionUID = 1680993305950225012L;
  /** Param. */
  private String sort;
  /** Param. */
  private boolean ascending;
  /** Param. */
  private final List<ApprovalDataVOView> listData;

  /**
   * @param approvalDataVOs VOs
   */
  public ApprovalDataVOViewList(
      final Collection<ApprovalDataVO> approvalDataVOs) {
    listData = new ArrayList<>();
    for (ApprovalDataVO approvalDataVO : approvalDataVOs) {
      listData.add(new ApprovalDataVOView(approvalDataVO));
    }
  }

  @Override
  public ApprovalDataVOView get(final int arg0) {
    return listData.get(arg0);
  }

  @Override
  public int size() {
    return listData.size();
  }

  /**
   * Sort the list.
   *
   * @param column Column
   * @param isascending Up or down
   */
  protected void sort(final String column, final boolean isascending) {
    Comparator<ApprovalDataVOView> comparator =
        new Comparator<ApprovalDataVOView>() {
          @Override
          public int compare(
              final ApprovalDataVOView c2, final ApprovalDataVOView c1) {
            if (column == null || column.equals("requestDate")) {
              return isascending
                  ? c1.getApproveActionDataVO()
                      .getRequestDate()
                      .compareTo(c2.getApproveActionDataVO().getRequestDate())
                  : c2.getApproveActionDataVO()
                      .getRequestDate()
                      .compareTo(c1.getApproveActionDataVO().getRequestDate());
            } else if (column.equals("approveActionName")) {
              return isascending
                  ? c1.getApproveActionName()
                      .compareTo(c2.getApproveActionName())
                  : c2.getApproveActionName()
                      .compareTo(c1.getApproveActionName());
            } else if (column.equals("requestUsername")) {
              return isascending
                  ? c1.getRequestAdminName().compareTo(c2.getRequestAdminName())
                  : c2.getRequestAdminName()
                      .compareTo(c1.getRequestAdminName());
            } else if (column.equals("status")) {
              return isascending
                  ? c1.getStatus().compareTo(c2.getStatus())
                  : c2.getStatus().compareTo(c1.getStatus());
            } else {
              return 0;
            }
          }
        };

    Collections.sort(listData, comparator);
  }

  /**
   * Is the default sort direction for the given column "ascending" ?
   *
   * @param sortColumn Column
   * @return always true
   */
  protected boolean isDefaultAscending(final String sortColumn) {
    return true;
  }

  /**
   * @param sortColumn column
   */
  public void sort(final String sortColumn) {
    if (sortColumn == null) {
      throw new IllegalArgumentException(
          "Argument sortColumn must not be null.");
    }

    if (sort.equals(sortColumn)) {
      // current sort equals new sortColumn -> reverse sort order
      ascending = !ascending;
    } else {
      // sort new column in default direction
      sort = sortColumn;
      ascending = isDefaultAscending(sort);
    }

    sort(sort, ascending);
  }

  /** Sprt. */
  public void sort() {
    sort(sort);
  }

  /**
   * @return Data
   */
  public List<ApprovalDataVOView> getData() {
    sort(getSort(), isAscending());
    return this;
  }

  /**
   * @param data Data
   */
  public void setData(final List<ApprovalDataVOView> data) { }

  /**
   * @return Sort
   */
  public String getSort() {
    return sort;
  }

  /**
   * @param asort Sort
   */
  public void setSort(final String asort) {
    this.sort = asort;
  }

  /**
   * @return bool
   */
  public boolean isAscending() {
    return ascending;
  }

  /**
   * @param isascending bool
   */
  public void setAscending(final boolean isascending) {
    this.ascending = isascending;
  }
}
