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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.roles.Role;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRoleSearchRequest;
import org.ejbca.core.model.era.RaRoleSearchResponse;

/**
 * Backing bean for the Roles page.
 *
 * @version $Id: RaRolesBean.java 25430 2017-03-09 16:37:36Z samuellb $ TODO:
 *     Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaRolesBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RaRolesBean.class);

  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

  /** Param. */
  @ManagedProperty(value = "#{raAccessBean}")
  private RaAccessBean raAccessBean;

  /**
   * @param araAccessBean bean
   */
  public void setRaAccessBean(final RaAccessBean araAccessBean) {
    this.raAccessBean = araAccessBean;
  }

  /** Param. */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;

  /**
   * @param araAuthenticationBean Bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }

  /** Param. */
  @ManagedProperty(value = "#{raLocaleBean}")
  private RaLocaleBean raLocaleBean;

  /**
   * @param araLocaleBean bean
   */
  public void setRaLocaleBean(final RaLocaleBean araLocaleBean) {
    this.raLocaleBean = araLocaleBean;
  }

  /** Param. */
  private String roleSearchString;

  /** Param. */
  private RaRoleSearchResponse lastExecutedResponse = null;

  /** Param. */
  private List<Role> resultsFiltered = new ArrayList<>();
  /** Param. */
  private boolean hasNamespaces;

  private enum SortBy {
      /** Param. */
    NAMESPACE,
    /** Param. */
    ROLE
  };

  /** Param. */
  private SortBy sortBy = SortBy.ROLE;
  /** Param. */
  private boolean sortAscending = true;

  /** Init. */
  public void initialize() {
    searchAndFilterCommon();
  }

  /**
   * @return Search
   */
  public String getRoleSearchString() {
    return roleSearchString;
  }

  /**
   * @param aroleSearchString search
   */
  public void setRoleSearchString(final String aroleSearchString) {
    this.roleSearchString = aroleSearchString;
  }

  /** Invoked action on search form post. */
  public void searchAndFilterAction() {
    searchAndFilterCommon();
  }

  /**
   * Invoked on criteria changes.
   *
   * @param event Event
   */
  public void searchAndFilterAjaxListener(final AjaxBehaviorEvent event) {
    searchAndFilterCommon();
  }

  /**
   * Determine if we need to query back end or just filter and execute the
   * required action.
   */
  private void searchAndFilterCommon() {
    // Get data
    final RaRoleSearchRequest searchRequest = new RaRoleSearchRequest();
    searchRequest.setGenericSearchString(roleSearchString);
    lastExecutedResponse =
        raMasterApiProxyBean.searchForRoles(
            raAuthenticationBean.getAuthenticationToken(), searchRequest);
    resultsFiltered = lastExecutedResponse.getRoles();

    // Check if we should show the namespace column
    hasNamespaces = false;
    for (final Role role : resultsFiltered) {
      if (!StringUtils.isEmpty(role.getNameSpace())) {
        hasNamespaces = true;
      }
    }

    sort();
  }

  /**
   * @return List
   */
  public List<Role> getFilteredResults() {
    return resultsFiltered;
  }

  /**
   * @return bool
   */
  public boolean isMoreResultsAvailable() {
    return lastExecutedResponse != null
        && lastExecutedResponse.isMightHaveMoreResults();
  }

  /**
   * @return bool
   */
  public boolean getHasNamespaces() {
    return hasNamespaces;
  }

  /**
   * @return search
   */
  public String getSearchStringPlaceholder() {
    return raLocaleBean.getMessage(
        hasNamespaces
            ? "roles_page_search_placeholder_with_namespaces"
            : "roles_page_search_placeholder_without_namespaces");
  }

  // Sorting
  private void sort() {
    Collections.sort(
        resultsFiltered,
        new Comparator<Role>() {
          @Override
          public int compare(final Role o1, final Role o2) {
            int sortDir = (isSortAscending() ? 1 : -1);
            switch (sortBy) {
                // TODO locale-aware sorting
              case NAMESPACE:

                  int difference =
                      o1.getNameSpace().compareTo(o2.getNameSpace());
                  if (difference == 0) {
                    return o1.getRoleName().compareTo(o2.getRoleName())
                        * sortDir; // Sort roles in the same namespace by role
                                   // name
                  }
                  return difference * sortDir;

              case ROLE:

                  difference = o1.getRoleName().compareTo(o2.getRoleName());
                  if (difference == 0) {
                    return o1.getNameSpace().compareTo(o2.getNameSpace())
                        * sortDir; // Sort roles with the same name by namespace
                  }
                  return difference * sortDir;

              default:
                throw new IllegalStateException("Invalid sortBy value");
            }
          }
        });
  }

  /**
   * @return Sorted
   */
  public String getSortedByNamespace() {
    return getSortedBy(SortBy.NAMESPACE);
  }

  /** Sort. */
  public void sortByNamespace() {
    sortBy(SortBy.NAMESPACE, true);
  }

  /**
   * @return Sorted
   */
  public String getSortedByRole() {
    return getSortedBy(SortBy.ROLE);
  }

  /** Sort. */
  public void sortByRole() {
    sortBy(SortBy.ROLE, true);
  }

  /**
   * @return col
   */
  public String getSortColumn() {
    return sortBy.name();
  }

  /**
   * @param value val
   */
  public void setSortColumn(final String value) {
    try {
      sortBy =
          !StringUtils.isBlank(value)
              ? SortBy.valueOf(value.toUpperCase(Locale.ROOT))
              : SortBy.ROLE;
    } catch (IllegalArgumentException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Invalid value for the 'sortColumn' parameter: '" + value + "'");
      }
      sortBy = SortBy.ROLE;
    }
  }

  /**
   * @param asortBy sort
   * @return sorted
   */
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
   * @param defaultAscending Order
   */
  private void sortBy(final SortBy asortBy, final boolean defaultAscending) {
    if (this.sortBy.equals(asortBy)) {
      sortAscending = !isSortAscending();
    } else {
      sortAscending = defaultAscending;
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
