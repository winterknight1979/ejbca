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
import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.SerializationUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.Role;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRoleMemberTokenTypeInfo;

/**
 * Backing bean for the (Add) Role Member page.
 *
 * @version $Id: RaRoleMemberBean.java 34207 2020-01-08 13:22:50Z samuellb $
 *     TODO: Use CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@ViewScoped
public class RaRoleMemberBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RaRoleMemberBean.class);

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
  @ManagedProperty(value = "#{raRoleMembersBean}")
  private RaRoleMembersBean raRoleMembersBean;

  /**
   * @param araRoleMembersBean bean
   */
  public void setRaRoleMembersBean(final RaRoleMembersBean araRoleMembersBean) {
    this.raRoleMembersBean = araRoleMembersBean;
  }

  /** Param. */
  private List<SelectItem> availableRoles = null;
  /** Param. */
  private List<SelectItem> availableTokenTypes = null;
  /** Param. */
  private List<SelectItem> availableCAs = null;
  /** Param. */
  private Map<String, RaRoleMemberTokenTypeInfo> tokenTypeInfos;

  /** Param. */
  private Integer roleMemberId;
  /** Param. */
  private RoleMember roleMember;
  /** Param. */
  private Role role;

  /** Param. */
  private int roleId;
  /** Param. */
  private String tokenType;
  /** Param. */
  private int caId;
  /** Param. */
  private Integer matchKey;
  /** Param. */
  private String matchValue;
  /** Param. */
  private String description;

  /** Init. */
  public void initialize() {
    if (tokenType != null && tokenTypeInfos != null) {
      // Don't re-initialize, that would overwrite the fields (tokenType, etc.)
      return;
    }

    tokenTypeInfos =
        raMasterApiProxyBean.getAvailableRoleMemberTokenTypes(
            raAuthenticationBean.getAuthenticationToken());

    if (roleMemberId != null) {
      try {
        roleMember =
            raMasterApiProxyBean.getRoleMember(
                raAuthenticationBean.getAuthenticationToken(), roleMemberId);
        if (roleMember == null) {
          LOG.debug("Role member with ID " + roleMemberId + " was not found.");
          return;
        }
        roleId = roleMember.getRoleId();
        tokenType = roleMember.getTokenType();
        caId = roleMember.getTokenIssuerId();
        matchKey = roleMember.getTokenMatchKey();
        matchValue = roleMember.getTokenMatchValue();
        description = roleMember.getDescription();
        if (roleId != RoleMember.NO_ROLE) {
          role =
              raMasterApiProxyBean.getRole(
                  raAuthenticationBean.getAuthenticationToken(), roleId);
          if (role == null) {
            LOG.debug(
                "Reference to missing role with ID "
                    + roleId
                    + " in role member with ID "
                    + roleMemberId);
          }
        }
      } catch (AuthorizationDeniedException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Authorization denied to role member "
                  + roleMemberId
                  + ". "
                  + e.getMessage(),
              e);
        }
        roleMember = null;
      }
    } else {
      roleMember = new RoleMember("", RoleMember.NO_ISSUER, 0, 0, "", 0, "");
      // Default values
      if (StringUtils.isEmpty(tokenType)) {
        tokenType = "CertificateAuthenticationToken";
      }

      if (matchKey == null) {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo =
            tokenTypeInfos.get(tokenType);
        if (tokenTypeInfo != null) {
          matchKey =
              tokenTypeInfo
                  .getMatchKeysMap()
                  .get(tokenTypeInfo.getDefaultMatchKey());
        } else {
          LOG.debug("Missing information about token type " + tokenType);
          matchKey = 0;
        }
      }
    }
  }

  /**
   * @return ID
   */
  public Integer getRoleMemberId() {
    return roleMemberId;
  }

  /**
   * @param aroleMemberId member
   */
  public void setRoleMemberId(final Integer aroleMemberId) {
    this.roleMemberId = aroleMemberId;
  }

  /**
   * @return Member
   */
  public RoleMember getRoleMember() {
    return roleMember;
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
   * @return type
   */
  public String getTokenType() {
    return tokenType;
  }

  /**
   * @param atokenType Type
   */
  public void setTokenType(final String atokenType) {
    this.tokenType = atokenType;
  }

  /**
   * @return CA
   */
  public int getCaId() {
    return caId;
  }

  /**
   * @param acaId CA
   */
  public void setCaId(final int acaId) {
    this.caId = acaId;
  }

  /**
   * @return key
   */
  public int getMatchKey() {
    return matchKey;
  }

  /**
   * @param amatchKey key
   */
  public void setMatchKey(final int amatchKey) {
    this.matchKey = amatchKey;
  }

  /**
   * @return val
   */
  public String getMatchValue() {
    return matchValue;
  }

  /**
   * @param amatchValue val
   */
  public void setMatchValue(final String amatchValue) {
    this.matchValue = amatchValue;
  }

  /**
   * @return desc
   */
  public String getDescription() {
    return this.description;
  }

  /**
   * @param adescription desc
   */
  public void setDescription(final String adescription) {
    this.description = adescription.trim();
  }

  /**
   * @return List
   */
  public List<SelectItem> getAvailableRoles() {
    if (availableRoles == null) {
      availableRoles = new ArrayList<>();
      final List<Role> roles =
          new ArrayList<>(
              raMasterApiProxyBean.getAuthorizedRoles(
                  raAuthenticationBean.getAuthenticationToken()));
      Collections.sort(roles);
      boolean hasNamespaces = false;
      for (final Role arole : roles) {
        if (!StringUtils.isEmpty(arole.getNameSpace())) {
          hasNamespaces = true;
        }
      }
      for (final Role arole : roles) {
        final String name =
            hasNamespaces ? arole.getRoleNameFull() : arole.getRoleName();
        availableRoles.add(new SelectItem(arole.getRoleId(), name));
      }
    }
    return availableRoles;
  }

  /**
   * @return List
   */
  public List<SelectItem> getAvailableTokenTypes() {
    if (availableTokenTypes == null) {
      final List<String> tokenTypes = new ArrayList<>(tokenTypeInfos.keySet());
      Collections.sort(tokenTypes);
      availableTokenTypes = new ArrayList<>();
      for (final String atokenType : tokenTypes) {
        availableTokenTypes.add(
            new SelectItem(
                atokenType,
                raLocaleBean.getMessage(
                    "role_member_token_type_" + atokenType)));
      }
    }
    return availableTokenTypes;
  }

  /**
   * @return List
   */
  public List<SelectItem> getAvailableCAs() {
    if (availableCAs == null) {
      availableCAs = new ArrayList<>();
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
      for (final CAInfo caInfo : caInfos) {
        availableCAs.add(new SelectItem(caInfo.getCAId(), caInfo.getName()));
      }
    }
    return availableCAs;
  }

  /**
   * @return List
   */
  public List<SelectItem> getAvailableMatchKeys() {
    final RaRoleMemberTokenTypeInfo tokenTypeInfo =
        tokenTypeInfos.get(tokenType);
    final List<SelectItem> result = new ArrayList<>();
    if (tokenTypeInfo != null) {
      final List<String> namesSorted =
          new ArrayList<>(tokenTypeInfo.getMatchKeysMap().keySet());
      Collator coll = Collator.getInstance();
      coll.setStrength(Collator.PRIMARY);
      Collections.sort(namesSorted, coll);
      for (final String name : namesSorted) {
        if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(
                tokenType)
            && "NONE".equals(name)
            && !String.valueOf(matchKey).equals(tokenType)) {
          continue; // deprecated value
        }
        result.add(
            new SelectItem(
                tokenTypeInfo.getMatchKeysMap().get(name),
                raLocaleBean.getMessage(
                    "role_member_matchkey_" + tokenType + "_" + name)));
      }
    }
    return result;
  }

  /**
   * @return bool
   */
  public boolean isTokenTypeIssuedByCA() {
    final RaRoleMemberTokenTypeInfo tokenTypeInfo =
        tokenTypeInfos.get(tokenType);
    return tokenTypeInfo == null || tokenTypeInfo.isIssuedByCA();
  }

  /**
   * @return bool
   */
  public boolean getTokenTypeHasMatchValue() {
    final RaRoleMemberTokenTypeInfo tokenTypeInfo =
        tokenTypeInfos.get(tokenType);
    return tokenTypeInfo.getHasMatchValue();
  }

  /**
   * @return URL
   */
  public String getEditPageTitle() {
    return raLocaleBean.getMessage(
        roleMemberId != null
            ? "role_member_page_edit_title"
            : "role_member_page_add_title");
  }

  /**
   * @return URL
   */
  public String getSaveButtonText() {
    return raLocaleBean.getMessage(
        roleMemberId != null
            ? "role_member_page_save_command"
            : "role_member_page_add_command");
  }

  /** Called when the token type is changed. Does nothing */
  public void update() { }

  /**
   * @return URL
   * @throws AuthorizationDeniedException fail
   */
  public String save() throws AuthorizationDeniedException {
    final RaRoleMemberTokenTypeInfo tokenTypeInfo =
        tokenTypeInfos.get(tokenType);
    if (!tokenTypeInfo.isIssuedByCA()) {
      caId = RoleMember.NO_ISSUER;
    }

    // The getRoleMember method returns a reference to an object which should
    // not be edited directly,
    // so we make a deep copy of it here, which we can edit freely. This code is
    // not performance critical,
    // so cloning through serialization is OK (and does not require a copy
    // constructor that needs to be maintained).
    final RoleMember roleMemberWithChanges =
        (RoleMember) SerializationUtils.clone(roleMember);
    roleMemberWithChanges.setRoleId(roleId);
    roleMemberWithChanges.setTokenType(tokenType);
    roleMemberWithChanges.setTokenIssuerId(caId);
    roleMemberWithChanges.setTokenMatchKey(matchKey);
    roleMemberWithChanges.setTokenMatchOperator(
        tokenTypeInfo.getMatchOperator());
    roleMemberWithChanges.setTokenMatchValue(
        getTokenTypeHasMatchValue() ? matchValue : "");
    roleMemberWithChanges.setDescription(description);

    final RoleMember savedRoleMember =
        raMasterApiProxyBean.saveRoleMember(
            raAuthenticationBean.getAuthenticationToken(),
            roleMemberWithChanges);
    if (savedRoleMember == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The role member could not be saved. Role member ID: "
                + roleMemberId
                + ". Role ID: "
                + roleId
                + ". Match value: '"
                + matchValue
                + "'");
      }
      raLocaleBean.addMessageError("role_member_page_error_generic");
      return "";
    }
    roleMember = savedRoleMember;
    roleMemberId = roleMember.getId();

    // If the active filter does not include the newly added role member, then
    // change the filter to show it
    if (raRoleMembersBean.getCriteriaCaId() != null
        && raRoleMembersBean.getCriteriaCaId().intValue()
            != roleMember.getTokenIssuerId()) {
      raRoleMembersBean.setCriteriaCaId(
          caId != RoleMember.NO_ISSUER ? caId : null);
    }

    if (raRoleMembersBean.getCriteriaTokenType() != null
        && !raRoleMembersBean
            .getCriteriaTokenType()
            .equals(roleMember.getTokenType())) {
      raRoleMembersBean.setCriteriaTokenType(tokenType);
    }

    if (raRoleMembersBean.getCriteriaRoleId() != null
        && raRoleMembersBean.getCriteriaRoleId().intValue()
            != roleMember.getRoleId()) {
      raRoleMembersBean.setCriteriaRoleId(roleId);
    }

    return "role_members?faces-redirect=true&includeViewParams=true";
  }

  /**
   * @return URL
   */
  public String getRemovePageTitle() {
    return raLocaleBean.getMessage(
        "remove_role_member_page_title", StringUtils.defaultString(matchValue));
  }

  /**
   * @return URL
   */
  public String getRemoveConfirmationText() {
    if (role != null) {
      return raLocaleBean.getMessage(
          "remove_role_member_page_confirm_with_role", role.getRoleName());
    } else {
      return raLocaleBean.getMessage("remove_role_member_page_confirm");
    }
  }

  /**
   * @return URL
   * @throws AuthorizationDeniedException fail
   */
  public String delete() throws AuthorizationDeniedException {
    if (!raMasterApiProxyBean.deleteRoleMember(
        raAuthenticationBean.getAuthenticationToken(),
        roleMember.getRoleId(),
        roleMember.getId())) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The role member could not be deleted. Role member ID: "
                + roleMemberId
                + ". Role ID: "
                + roleId
                + ". Match value: '"
                + matchValue
                + "'");
      }
      raLocaleBean.addMessageError("remove_role_member_page_error_generic");
      return "";
    }
    return "role_members?faces-redirect=true&includeViewParams=true";
  }

  /**
   * @return URL
   */
  public String cancel() {
    return "role_members?faces-redirect=true&includeViewParams=true";
  }
}
