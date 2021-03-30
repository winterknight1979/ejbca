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
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.Role;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRoleMemberSearchRequest;
import org.ejbca.core.model.era.RaRoleMemberSearchResponse;
import org.ejbca.core.model.era.RaRoleMemberTokenTypeInfo;

/**
 * Backing bean for the Role Members page.
 *
 * @version $Id: RaRoleMembersBean.java 25626 2017-03-30 17:09:50Z jeklund $
 *     TODO: Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaRoleMembersBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RaRoleMembersBean.class);

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
   * @param araLocaleBean bean
   */
  public void setRaLocaleBean(final RaLocaleBean araLocaleBean) {
    this.raLocaleBean = araLocaleBean;
  }

  /** Param. */
  private List<SelectItem> availableRoles = null;
  /** Param. */
  private List<SelectItem> availableCas = null;
  /** Param. */
  private List<SelectItem> availableTokenTypes = null;
  /** Param. */
  private Map<String, RaRoleMemberTokenTypeInfo> tokenTypeInfos;

  /** Param. */
  private String genericSearchString;
  /** Param. */
  private Integer criteriaRoleId;
  /** Param. */
  private Integer criteriaCaId;
  /** Param. */
  private String criteriaTokenType;
  /** Param. */
  private boolean fromRolesPage;

  /** Param. */
  private RaRoleMemberSearchResponse lastExecutedResponse = null;

  /** Param. */
  private List<RaRoleMemberGUIInfo> resultsFiltered = new ArrayList<>();
  /** Param. */
  private Map<Integer, String> caIdToNameMap;
  /** Param. */
  private Map<Integer, String> roleIdToNameMap;
  /** Param. */
  private Map<Integer, String> roleIdToNamespaceMap;
  /** Param. */
  private boolean hasMultipleNamespaces;

  private enum SortBy {
      /** Param. */
    ROLE,
    /** Param. */
    ROLENAMESPACE,
    /** Param. */
    CA,
    /** Param. */
    TOKENTYPE,
    /** Param. */
    TOKENMATCHVALUE,
    /** Param. */
    DESCRIPTION
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
  public String getGenericSearchString() {
    return genericSearchString;
  }

  /**
   * @param agenericSearchString Search
   */
  public void setGenericSearchString(final String agenericSearchString) {
    this.genericSearchString = agenericSearchString;
  }

  /**
   * @return ID
   */
  public Integer getCriteriaRoleId() {
    return criteriaRoleId;
  }

  /**
   * @param acriteriaRoleId ID
   */
  public void setCriteriaRoleId(final Integer acriteriaRoleId) {
    this.criteriaRoleId = acriteriaRoleId;
  }

  /**
   * @return ID
   */
  public Integer getCriteriaCaId() {
    return criteriaCaId;
  }

  /**
   * @param acriteriaCaId ID
   */
  public void setCriteriaCaId(final Integer acriteriaCaId) {
    this.criteriaCaId = acriteriaCaId;
  }

  /**
   * @return token
   */
  public String getCriteriaTokenType() {
    return criteriaTokenType;
  }

  /**
   * @param acriteriaTokenType token
   */
  public void setCriteriaTokenType(final String acriteriaTokenType) {
    this.criteriaTokenType = acriteriaTokenType;
  }

  /**
   * @return bool
   */
  public boolean isFromRolesPage() {
    return fromRolesPage;
  }

  /**
   * @param afromRolesPage bool
   */
  public void setFromRolesPage(final boolean afromRolesPage) {
    this.fromRolesPage = afromRolesPage;
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
    // First make sure we have all CA and Role names
    getAvailableCas();
    getAvailableRoles();

    // Make search request
    final RaRoleMemberSearchRequest searchRequest =
        new RaRoleMemberSearchRequest();
    if (criteriaCaId != null
        && criteriaCaId.intValue()
            != 0) { // JBoss EAP 6.4 sets the parameters to 0 instead of null
      searchRequest.setCaIds(new ArrayList<>(Arrays.asList(criteriaCaId)));
    }
    if (criteriaRoleId != null && criteriaRoleId.intValue() != 0) {
      searchRequest.setRoleIds(new ArrayList<>(Arrays.asList(criteriaRoleId)));
    }
    if (!StringUtils.isEmpty(criteriaTokenType)) {
      searchRequest.setTokenTypes(
          new ArrayList<>(Arrays.asList(criteriaTokenType)));
    }
    searchRequest.setGenericSearchString(genericSearchString);
    lastExecutedResponse =
        raMasterApiProxyBean.searchForRoleMembers(
            raAuthenticationBean.getAuthenticationToken(), searchRequest);

    // Add names of CAs and roles
    resultsFiltered = new ArrayList<>();
    for (final RoleMember member : lastExecutedResponse.getRoleMembers()) {
      final String caName =
          StringUtils.defaultString(
              caIdToNameMap.get(member.getTokenIssuerId()),
              raLocaleBean.getMessage("role_members_page_info_unknownca"));
      final String roleName =
          StringUtils.defaultString(roleIdToNameMap.get(member.getRoleId()));
      final String namespace = roleIdToNamespaceMap.get(member.getRoleId());
      final String tokenTypeText =
          raLocaleBean.getMessage(
              "role_member_token_type_" + member.getTokenType());
      resultsFiltered.add(
          new RaRoleMemberGUIInfo(
              member,
              caName,
              roleName,
              StringUtils.defaultString(namespace),
              tokenTypeText));
    }

    sort();
  }

  /**
   * @return list
   */
  public List<RaRoleMemberGUIInfo> getFilteredResults() {
    return resultsFiltered;
  }

  /**
   * @return bool
   */
  public boolean isMoreResultsAvailable() {
    return lastExecutedResponse.isMightHaveMoreResults();
  }

  // Sorting
  private void sort() {
    Collections.sort(
        resultsFiltered,
        new Comparator<RaRoleMemberGUIInfo>() {
          @Override
          public int compare(
              final RaRoleMemberGUIInfo o1, final RaRoleMemberGUIInfo o2) {
            int sortDir = (isSortAscending() ? 1 : -1);
            final RoleMember rm1 = o1.getRoleMember();
            final RoleMember rm2 = o2.getRoleMember();
            switch (sortBy) {
                // TODO locale-aware sorting
              case ROLE:

                  int diff =
                      o1.getRoleName().compareTo(o2.getRoleName()) * sortDir;
                  if (diff != 0) {
                    return diff;
                  } else {
                    return o1.getRoleNamespace()
                            .compareTo(o2.getRoleNamespace())
                        * sortDir;
                  }

              case ROLENAMESPACE:

                  diff =
                      o1.getRoleNamespace().compareTo(o2.getRoleNamespace())
                          * sortDir;
                  if (diff != 0) {
                    return diff;
                  } else {
                    return o1.getRoleName().compareTo(o2.getRoleName())
                        * sortDir;
                  }

              case CA:
                return o1.getCaName().compareTo(o2.getCaName()) * sortDir;
              case TOKENTYPE:
                return StringUtils.defaultString(rm1.getTokenType())
                        .compareTo(
                            StringUtils.defaultString(rm2.getTokenType()))
                    * sortDir;
              case TOKENMATCHVALUE:
                return StringUtils.defaultString(rm1.getTokenMatchValue())
                        .compareTo(
                            StringUtils.defaultString(rm2.getTokenMatchValue()))
                    * sortDir;
              case DESCRIPTION:
                return StringUtils.defaultString(rm1.getDescription())
                        .compareTo(
                            StringUtils.defaultString(rm2.getDescription()))
                    * sortDir;
              default:
                throw new IllegalStateException("Invalid sortBy value");
            }
          }
        });
  }

  /**
   * @return sorted
   */
  public String getSortedByRole() {
    return getSortedBy(SortBy.ROLE);
  }

  /** Sort. */
  public void sortByRole() {
    sortBy(SortBy.ROLE, true);
  }

  /**
   * @return sorted
   */
  public String getSortedByRoleNamespace() {
    return getSortedBy(SortBy.ROLENAMESPACE);
  }

  /** Sort. */
  public void sortByRoleNamespace() {
    sortBy(SortBy.ROLENAMESPACE, true);
  }

  /**
   * @return sorted
   */
  public String getSortedByCA() {
    return getSortedBy(SortBy.CA);
  }

  /** Sort. */
  public void sortByCA() {
    sortBy(SortBy.CA, true);
  }

  /**
   * @return sorted
   */
  public String getSortedByTokenType() {
    return getSortedBy(SortBy.TOKENTYPE);
  }

  /** Sort. */
  public void sortByTokenType() {
    sortBy(SortBy.TOKENTYPE, true);
  }

  /**
   * @return sorted
   */
  public String getSortedByTokenMatchValue() {
    return getSortedBy(SortBy.TOKENMATCHVALUE);
  }

  /** Sort. */
  public void sortByTokenMatchValue() {
    sortBy(SortBy.TOKENMATCHVALUE, true);
  }

  /**
   * @return sorted
   */
  public String getSortedByDescription() {
    return getSortedBy(SortBy.DESCRIPTION);
  }

  /** Sort. */
  public void sortByDescription() {
    sortBy(SortBy.DESCRIPTION, true);
  }

  /**
   * @return col
   */
  public String getSortColumn() {
    return sortBy.name();
  }

  /**
   * @param value value
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

  /**
   * @return bool
   */
  public boolean getHasMultipleNamespaces() {
    return hasMultipleNamespaces;
  }

  /**
   * @return bool
   */
  public boolean isOnlyOneRoleAvailable() {
    return getAvailableRoles().size() == 2;
  } // two including the "any role" choice

  /**
   * @return Roles
   */
  public List<SelectItem> getAvailableRoles() {
    if (availableRoles == null) {
      availableRoles = new ArrayList<>();
      final List<Role> roles =
          new ArrayList<>(
              raMasterApiProxyBean.getAuthorizedRoles(
                  raAuthenticationBean.getAuthenticationToken()));
      Collections.sort(roles);
      roleIdToNameMap = new HashMap<>();
      roleIdToNamespaceMap = new HashMap<>();
      String lastNamespace = null;
      hasMultipleNamespaces = false;
      for (final Role role : roles) {
        roleIdToNameMap.put(role.getRoleId(), role.getRoleName());
        if (!StringUtils.isEmpty(role.getNameSpace())) {
          roleIdToNamespaceMap.put(role.getRoleId(), role.getNameSpace());
        }
        // Check if there's more than one namespace. If so the namespaces are
        // shown in the GUI
        if (lastNamespace != null
            && !lastNamespace.equals(role.getNameSpace())) {
          hasMultipleNamespaces = true;
        }
        lastNamespace = role.getNameSpace();
      }
      availableRoles.add(
          new SelectItem(
              null,
              raLocaleBean.getMessage(
                  "role_members_page_criteria_role_optionany")));
      for (final Role role : roles) {
        final String label =
            hasMultipleNamespaces ? role.getRoleNameFull() : role.getRoleName();
        availableRoles.add(new SelectItem(role.getRoleId(), label));
      }
    }
    return availableRoles;
  }

  /**
   * @return bool
   */
  public boolean isOnlyOneCaAvailable() {
    return getAvailableCas().size() == 2;
  } // two including the "any CA" choice

  /**
   * @return list
   */
  public List<SelectItem> getAvailableCas() {
    if (availableCas == null) {
      availableCas = new ArrayList<>();
      final List<CAInfo> caInfos =
          new ArrayList<>(
              raMasterApiProxyBean.getAuthorizedCas(
                  raAuthenticationBean.getAuthenticationToken()));
      Collections.sort(
          caInfos,
          new Comparator<CAInfo>() {
            @Override
            public int compare(final CAInfo caInfo1, final CAInfo caInfo2) {
              return caInfo1.getName().compareTo(caInfo2.getName());
            }
          });
      caIdToNameMap = new HashMap<>();
      for (final CAInfo caInfo : caInfos) {
        caIdToNameMap.put(caInfo.getCAId(), caInfo.getName());
      }
      availableCas.add(
          new SelectItem(
              null,
              raLocaleBean.getMessage(
                  "role_members_page_criteria_ca_optionany")));
      for (final CAInfo caInfo : caInfos) {
        availableCas.add(new SelectItem(caInfo.getCAId(), caInfo.getName()));
      }
    }
    return availableCas;
  }

  /**
   * @return bool
   */
  public boolean isOnlyOneTokenTypeAvailable() {
    return getAvailableTokenTypes().size() == 2;
  } // two including the "any token type" choice

  /**
   * @return bool
   */
  public boolean getHasMultipleTokenTypes() {
    return getAvailableTokenTypes().size() > 2;
  } // dito

  /**
   * @return List
   */
  public List<SelectItem> getAvailableTokenTypes() {
    if (availableTokenTypes == null) {
      if (tokenTypeInfos == null) {
        tokenTypeInfos =
            raMasterApiProxyBean.getAvailableRoleMemberTokenTypes(
                raAuthenticationBean.getAuthenticationToken());
      }
      final List<String> tokenTypes = new ArrayList<>(tokenTypeInfos.keySet());
      Collections.sort(tokenTypes);
      availableTokenTypes = new ArrayList<>();
      availableTokenTypes.add(
          new SelectItem(
              null,
              raLocaleBean.getMessage(
                  "role_members_page_criteria_tokentype_optionany")));
      for (final String tokenType : tokenTypes) {
        availableTokenTypes.add(
            new SelectItem(
                tokenType,
                raLocaleBean.getMessage(
                    "role_member_token_type_" + tokenType)));
      }
    }
    return availableTokenTypes;
  }
}
