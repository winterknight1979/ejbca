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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.SerializationUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ra.jsfext.AddRemoveListState;

/**
 * Backing bean for the Edit Role page.
 *
 * @version $Id: RaRoleBean.java 34207 2020-01-08 13:22:50Z samuellb $ TODO: Use
 *     CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaRoleBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RaRoleBean.class);

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
  @ManagedProperty(value = "#{raRolesBean}")
  private RaRolesBean raRolesBean;

  /**
   * @param araRolesBean bean
   */
  public void setRaRolesBean(final RaRolesBean araRolesBean) {
    this.raRolesBean = araRolesBean;
  }

  /** Param. */
  private static final Object NEW_NAMESPACE_ITEM = "#NEW#";
  /**
   * Matches e.g. /endentityprofilesrules/12345/create_end_entity, but not
   * /endentityprofilesrules/12345.
   */
  private final Pattern detailedProfileRulePattern =
      Pattern.compile(".*/([-0-9]+)/.+$");

  /** Param. */
  private boolean initialized = false;

  /** Param. */
  private Integer roleId;
  /** Param. */
  private Integer cloneFromRoleId;
  /** Param. */
  private Role role;

  /** Param. */
  private String name;
  /** Param. */
  private String namespace;
  /** Param. */
  private String newNamespace;
  /** Param. */
  private boolean hasAccessToEmptyNamespace;
  /** Param. */
  private List<String> namespaces;
  /** Param. */
  private List<SelectItem> namespaceOptions = new ArrayList<>();

  /** Represents a checkbox for a rule in the GUI. */
  public final class RuleCheckboxInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    /** Param. */
    private final String accessRule;
    /** Param. */
    private final String label;
    /** Param. */
    private boolean allowed;

    /**
     * @param anaccessRule rule
     * @param labelMessageKey key
     */
    public RuleCheckboxInfo(
        final String anaccessRule, final String labelMessageKey) {
      this.accessRule = anaccessRule;
      this.label = raLocaleBean.getMessage(labelMessageKey);
      this.allowed =
          AccessRulesHelper.hasAccessToResource(
              role.getAccessRules(), anaccessRule);
    }

    /**
     * @return rule
     */
    public String getAccessRule() {
      return accessRule;
    }

    /**
     * @return label
     */
    public String getLabel() {
      return label;
    }

    /**
     * @return bool
     */
    public boolean isAllowed() {
      return allowed;
    }

    /**
     * @param isallowed bool
     */
    public void setAllowed(final boolean isallowed) {
      this.allowed = isallowed;
    }
  }

  /** Param. */
  private final List<RuleCheckboxInfo> endEntityRules = new ArrayList<>();
  /** Param. */
  private final AddRemoveListState<String> caListState =
      new AddRemoveListState<>();
  /** Param. */
  private final AddRemoveListState<String> endEntityProfileListState =
      new AddRemoveListState<>();
  /** Param. */
  private final Map<Integer, String> eeProfilesWithCustomPermissions =
      new HashMap<>();

  /**
   * @throws AuthorizationDeniedException fail
   */
  public void initialize() throws AuthorizationDeniedException {
    if (initialized) {
      return;
    }
    initialized = true;

    // Get namespaces
    namespaceOptions = new ArrayList<>();
    namespaces =
        raMasterApiProxyBean.getAuthorizedRoleNamespaces(
            raAuthenticationBean.getAuthenticationToken(),
            roleId != null ? roleId : Role.ROLE_ID_UNASSIGNED);
    Collections.sort(namespaces);
    hasAccessToEmptyNamespace = namespaces.contains("");
    if (hasAccessToEmptyNamespace) {
      namespaceOptions.add(
          new SelectItem(
              "", raLocaleBean.getMessage("role_page_namespace_none")));
      namespaceOptions.add(
          new SelectItem(
              NEW_NAMESPACE_ITEM,
              raLocaleBean.getMessage("role_page_namespace_createnew")));
    }
    for (final String anamespace : namespaces) {
      if (!anamespace.equals("")) {
        namespaceOptions.add(new SelectItem(anamespace, anamespace));
      }
    }

    // Get role
    if (roleId != null || cloneFromRoleId != null) {
      int roleToFetch = (roleId != null ? roleId : cloneFromRoleId);
      role =
          raMasterApiProxyBean.getRole(
              raAuthenticationBean.getAuthenticationToken(), roleToFetch);
      name = role.getRoleName();
      namespace = role.getNameSpace();
      if (roleId == null) {
        role.setRoleId(
            Role
                .ROLE_ID_UNASSIGNED); // force creation of a new role if we are
                                      // cloning
      }
    } else {
      role = new Role(getDefaultNamespace(), "");
      name = "";
    }

    // Get available access rules and their values in this role
    final IdNameHashMap<CAInfo> authorizedCas =
        raMasterApiProxyBean.getAuthorizedCAInfos(
            raAuthenticationBean.getAuthenticationToken());
    for (final KeyToValueHolder<CAInfo> kv : authorizedCas.values()) {
      final CAInfo ca = kv.getValue();
      final String accessRule = StandardRules.CAACCESS.resource() + kv.getId();
      final boolean enabled =
          AccessRulesHelper.hasAccessToResource(
              role.getAccessRules(), accessRule);
      caListState.addListItem(accessRule, ca.getName(), enabled);
    }

    final IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles =
        raMasterApiProxyBean.getAuthorizedEndEntityProfiles(
            raAuthenticationBean.getAuthenticationToken(),
            AccessRulesConstants.VIEW_END_ENTITY);
    // Only allow end entity profiles with either full or no access to be edited
    for (final String accessRule : role.getAccessRules().keySet()) {
      if (accessRule.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
        final Matcher matcher = detailedProfileRulePattern.matcher(accessRule);
        if (matcher.matches()) {
          int profileId = Integer.parseInt(matcher.group(1));
          eeProfilesWithCustomPermissions.put(
              profileId, authorizedEndEntityProfiles.get(profileId).getName());
        }
      }
    }
    for (final KeyToValueHolder<EndEntityProfile> kv
        : authorizedEndEntityProfiles.values()) {
      if (!eeProfilesWithCustomPermissions.containsKey(kv.getId())) {
        final String accessRule =
            AccessRulesConstants.ENDENTITYPROFILEPREFIX + kv.getId();
        final boolean enabled =
            AccessRulesHelper.hasAccessToResource(
                role.getAccessRules(), accessRule);
        endEntityProfileListState.addListItem(
            accessRule, kv.getName(), enabled);
      }
    }
    endEntityRules.add(
        new RuleCheckboxInfo(
            AccessRulesConstants.REGULAR_APPROVEENDENTITY,
            "role_page_access_approveendentity"));
    endEntityRules.add(
        new RuleCheckboxInfo(
            AccessRulesConstants.REGULAR_CREATEENDENTITY,
            "role_page_access_createdeleteendentity")); // we let this one imply
                                                        // delete as well
    endEntityRules.add(
        new RuleCheckboxInfo(
            AccessRulesConstants.REGULAR_EDITENDENTITY,
            "role_page_access_editendentity"));
    endEntityRules.add(
        new RuleCheckboxInfo(
            AccessRulesConstants.REGULAR_REVOKEENDENTITY,
            "role_page_access_revokeendentity"));
    endEntityRules.add(
        new RuleCheckboxInfo(
            AccessRulesConstants.REGULAR_VIEWENDENTITY,
            "role_page_access_viewendentity"));
    endEntityRules.add(
        new RuleCheckboxInfo(
            AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY,
            "role_page_access_viewendentityhistory"));
  }

  /**
   * @return NS
   */
  public String getDefaultNamespace() {
    if (isLimitedToOneNamespace()
        || namespaces
            .isEmpty()) { // should never be empty, but better safe than sorry
      return "";
    } else {
      return namespaces.get(0);
    }
  }

  /**
   * @return ID
   */
  public Integer getRoleId() {
    return roleId;
  }

  /**
   * @param aroleId ID
   */
  public void setRoleId(final Integer aroleId) {
    this.roleId = aroleId;
  }

  /**
   * @return clone
   */
  public Integer getCloneFromRoleId() {
    return cloneFromRoleId;
  }

  /**
   * @param acloneFromRoleId clone
   */
  public void setCloneFromRoleId(final Integer acloneFromRoleId) {
    this.cloneFromRoleId = acloneFromRoleId;
  }

  /**
   * @return role
   */
  public Role getRole() {
    return role;
  }

  /**
   * @return name
   */
  public String getName() {
    return name;
  }

  /**
   * @param aname name
   */
  public void setName(final String aname) {
    this.name = aname;
  }

  /**
   * @return NS
   */
  public String getNamespace() {
    return namespace;
  }

  /**
   * @param anamespace NS
   */
  public void setNamespace(final String anamespace) {
    this.namespace = anamespace;
  }

  /**
   * @return NS
   */
  public String getNewNamespace() {
    return newNamespace;
  }

  /**
   * @param anewNamespace NS
   */
  public void setNewNamespace(final String anewNamespace) {
    this.newNamespace = anewNamespace;
  }

  /**
   * @return bool
   */
  public boolean isLimitedToOneNamespace() {
    return !hasAccessToEmptyNamespace && namespaces.size() == 1;
  }

  /**
   * @return bool
   */
  public boolean getCanCreateNamespaces() {
    return hasAccessToEmptyNamespace;
  }

  /**
   * @return options
   */
  public List<SelectItem> getNamespaceOptions() {
    return namespaceOptions;
  }

  /**
   * @return bool
   */
  public boolean getCanEdit() {
    return raAccessBean.isAuthorizedToEditRoleRules();
  }

  /**
   * @return perms
   */
  public boolean getHasCustomEndEntityProfilePermissions() {
    return !eeProfilesWithCustomPermissions.isEmpty();
  }

  /**
   * @return notice
   */
  public String getCustomEndEntityProfilePermissionsNotice() {
    final String profileList =
        StringUtils.join(eeProfilesWithCustomPermissions.values(), ", ");
    return raLocaleBean.getMessage(
        "role_page_custom_permissions_endentityprofiles", profileList);
  }

  /**
   * @return rules
   */
  public List<RuleCheckboxInfo> getEndEntityRules() {
    return endEntityRules;
  }

  /**
   * @return state
   */
  public AddRemoveListState<String> getCaListState() {
    return caListState;
  }

  /**
   * @return state
   */
  public AddRemoveListState<String> getEndEntityProfileListState() {
    return endEntityProfileListState;
  }

  /**
   * @return title
   */
  public String getPageTitle() {
    if (!getCanEdit()) {
      return raLocaleBean.getMessage("role_page_title_view", name);
    } else if (roleId != null) {
      return raLocaleBean.getMessage("role_page_title_edit", name);
    } else if (cloneFromRoleId != null) {
      return raLocaleBean.getMessage("role_page_title_clone", name);
    } else {
      return raLocaleBean.getMessage("role_page_title_add");
    }
  }

  /**
   * @return text
   */
  public String getSaveButtonText() {
    final String messageKey;
    if (roleId != null) {
      messageKey = "role_page_save_command";
    } else if (cloneFromRoleId != null) {
      messageKey = "role_page_clone_command";
    } else {
      messageKey = "role_page_add_command";
    }
    return raLocaleBean.getMessage(messageKey);
  }

  /**
   * @return URL
   * @throws AuthorizationDeniedException fail
   */
  public String save() throws AuthorizationDeniedException {
    // The getRole method returns a reference to an object which should not be
    // edited directly,
    // so we make a deep copy of it here, which we can edit freely. This code is
    // not performance critical,
    // so cloning through serialization is OK (and does not require a copy
    // constructor that needs to be maintained).
    final Role roleWithChanges = (Role) SerializationUtils.clone(role);
    // Check and set namespace
    if (!isLimitedToOneNamespace()) {
      final String namespaceToUse;
      if (NEW_NAMESPACE_ITEM.equals(namespace)) {
        if (StringUtils.isBlank(newNamespace)) {
          LOG.debug(
              "Empty namespace entered when 'New namespace' was selected."
                  + " Cannot save role");
          raLocaleBean.addMessageError("role_page_error_empty_namespace");
          return "";
        }
        namespaceToUse = newNamespace;
      } else {
        if (!StringUtils.isBlank(newNamespace)) {
          LOG.debug(
              "New namespace name entered when an existing namespace was"
                  + " selected. Cannot save role");
          raLocaleBean.addMessageError(
              "role_page_error_new_and_existing_namespace");
          return "";
        }
        namespaceToUse = namespace;
      }
      roleWithChanges.setNameSpace(namespaceToUse);
    } else if (role.getRoleId() == Role.ROLE_ID_UNASSIGNED) {
      // New role, and the admin is only allowed to use one namespace. Set the
      // namespace to the only allowed one
      roleWithChanges.setNameSpace(namespaces.get(0));
    }
    roleWithChanges.setRoleName(name);

    // Set access rules
    final Map<String, Boolean> accessMap = roleWithChanges.getAccessRules();
    for (final RuleCheckboxInfo checkboxInfo : endEntityRules) {
      accessMap.put(checkboxInfo.accessRule, checkboxInfo.allowed);
      // We let create imply delete, because the "make new request" page needs
      // delete access as well
      if (checkboxInfo.accessRule.equals(
          AccessRulesConstants.REGULAR_CREATEENDENTITY)) {
        accessMap.put(
            AccessRulesConstants.REGULAR_DELETEENDENTITY, checkboxInfo.allowed);
      }
    }
    accessMap.putAll(caListState.getItemStates());
    accessMap.putAll(endEntityProfileListState.getItemStates());

    try {
      role =
          raMasterApiProxyBean.saveRole(
              raAuthenticationBean.getAuthenticationToken(), roleWithChanges);
    } catch (RoleExistsException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Role named '"
                + roleWithChanges.getRoleName()
                + "' in namespace '"
                + roleWithChanges.getNameSpace()
                + "' already exists.");
      }
      if (!StringUtils.isEmpty(roleWithChanges.getNameSpace())) {
        raLocaleBean.addMessageError(
            "role_page_error_already_exists_with_namespace",
            roleWithChanges.getRoleName(),
            roleWithChanges.getNameSpace());
      } else {
        raLocaleBean.addMessageError(
            "role_page_error_already_exists", roleWithChanges.getRoleName());
      }
      return "";
    }
    roleId = role.getRoleId();
    return "roles?faces-redirect=true&includeViewParams=true";
  }

  /**
   * @return URL
   */
  public String getDeletePageTitle() {
    return raLocaleBean.getMessage("delete_role_page_title", name);
  }

  /**
   * @return confirm
   */
  public String getDeleteConfirmationText() {
    return raLocaleBean.getMessage(
        "delete_role_page_confirm", role.getAccessRules().size());
  }

  /**
   * @return URL
   * @throws AuthorizationDeniedException Fail
   */
  public String delete() throws AuthorizationDeniedException {
    if (!raMasterApiProxyBean.deleteRole(
        raAuthenticationBean.getAuthenticationToken(), role.getRoleId())) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The role '"
                + role.getRoleNameFull()
                + "' could not be deleted. Role ID: "
                + role.getRoleId());
      }
      raLocaleBean.addMessageError("delete_role_page_error_generic");
      return "";
    }
    return "roles?faces-redirect=true&includeViewParams=true";
  }

  /**
   * @return URL
   */
  public String cancel() {
    return "roles?faces-redirect=true&includeViewParams=true";
  }
}
