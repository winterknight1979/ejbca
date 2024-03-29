/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.roles;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Represents a role, and is based in the AdminGroup concept from EJBCA.
 *
 * @version $Id: AdminGroupData.java 25021 2017-01-18 01:30:19Z jeklund $
 */
@Deprecated // EJBCA 6.8.0
@Entity
@Table(name = "AdminGroupData")
public class AdminGroupData extends ProtectedData
    implements Serializable, Comparable<AdminGroupData> {

      /** Param. */
  public static final String DEFAULT_ROLE_NAME = "DEFAULT";

  private static final long serialVersionUID = -160810489638829430L;
  /** Param. */
  private Integer primaryKey;
  /** Param. */
  private Map<Integer, AccessRuleData> accessRules;
  /** Param. */
  private Map<Integer, AccessUserAspectData> accessUsers;
  /** Param. */
  private String roleName;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Null constructor. */
  public AdminGroupData() { }

  /**
   * @param aPrimaryKey PK
   * @param aRoleName Name
   */
  public AdminGroupData(final Integer aPrimaryKey, final String aRoleName) {
    this.primaryKey = aPrimaryKey;
    this.roleName = aRoleName;
    accessUsers = new HashMap<Integer, AccessUserAspectData>();
    accessRules = new HashMap<Integer, AccessRuleData>();
  }

  /**
   * @return PK
   */
  // @Id @Column
  public Integer getPrimaryKey() {
    return primaryKey;
  }

  /**
   * @param aPrimaryKey PK
   */
  public void setPrimaryKey(final Integer aPrimaryKey) {
    this.primaryKey = aPrimaryKey;
  }

  /**
   * @return name
   */
  // @Column
  public String getRoleName() {
    return roleName;
  }

  /**
   * @param aRoleName name
   */
  public void setRoleName(final String aRoleName) {
    this.roleName = aRoleName;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  /**
   * If we use lazy fetching we have to take care so that the Entity is
   * managed until we fetch the values. Set works better with eager fetching for
   * Hibernate.
 * @return map
   */
  // @OneToMany(cascade = { CascadeType.ALL }, fetch = FetchType.EAGER)
  // @JoinColumn(name = "RoleData_accessUsers")
  public Map<Integer, AccessUserAspectData> getAccessUsers() {
    return accessUsers;
  }

  /**
   * @param theAccessUsers mao
   */
  public void setAccessUsers(
      final Map<Integer, AccessUserAspectData> theAccessUsers) {
    this.accessUsers = theAccessUsers;
  }

  /**
   * If we use lazy fetching we have to take care so that the Entity is
   * managed until we fetch the values. Set works better with eager fetching for
   * Hibernate.
 * @return map
   */
  // @OneToMany(cascade = { CascadeType.ALL }, fetch = FetchType.EAGER)
  // @JoinColumn(name = "RoleData_accessRules")
  public Map<Integer, AccessRuleData> getAccessRules() {
    return accessRules;
  }

  /**
   * @param theAccessRules rules
   */
  public void setAccessRules(
          final Map<Integer, AccessRuleData> theAccessRules) {
    this.accessRules = theAccessRules;
  }

  /**
   * Utility method that makes a tree search of this Role's rules and checks for
   * a positive match.
   *
   * @param rule the rule to check
   * @return true if this Role has access to the given rule.
   */
  @Transient
  public boolean hasAccessToRule(final String rule) {
    return hasAccessToRule(rule, false);
  }

  /**
   * Utility method that makes a tree search of this Role's rules and checks for
   * a positive match.
   *
   * @param rule the rule to check
   * @param requireRecursive if rule has to be recursive (for an an exact match)
   * @return true if this Role has access to the given rule.
   */
  @Transient
  public boolean hasAccessToRule(
      final String rule, final boolean requireRecursive) {
    if (!rule.startsWith("/")) {
      throw new IllegalArgumentException("Rule must start with a \"/\"");
    }
    boolean result = false;
    for (AccessRuleData accessRuleData : accessRules.values()) {
      String currentRule = accessRuleData.getAccessRuleName();
      if (rule.equals(currentRule)) {
        if (accessRuleData
            .getInternalState()
            .equals(AccessRuleState.RULE_ACCEPT)) {
          if (requireRecursive) {
            result = accessRuleData.getRecursiveBool();
          } else {
            result = true;
          }
        } else {
          result = false;
          break;
        }
      } else if (rule.startsWith(currentRule) || currentRule.startsWith(rule)) {
        if (rule.length() > currentRule.length()
            && currentRule.length() > 1
            && rule.charAt(currentRule.length()) != '/') {
          // Not a parent rule but just one with a similar name, compare
          // /foo/bar to /foo_bar,
          // also ignoring the root "/" rule.
          continue;
        } else if (rule.length() < currentRule.length()
            && currentRule.charAt(rule.length()) != '/') {
          // This is not a subrule (i.e rule == /foo, currentRule == /foo/bar
          continue;
        } else {
          if (accessRuleData
                  .getInternalState()
                  .equals(AccessRuleState.RULE_ACCEPT)
              && accessRuleData.getRecursive()) {
            // A possible match, but there may be a contraindicator down the
            // line
            result = true;
          } else if (accessRuleData
              .getInternalState()
              .equals(AccessRuleState.RULE_DECLINE)) {
            // Definitely a non-match, break.
            result = false;
            break;
          }
        }
      }
    }
    return result;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result =
        prime * result + ((accessRules == null) ? 0 : accessRules.hashCode());
    result =
        prime * result + ((accessUsers == null) ? 0 : accessUsers.hashCode());
    result =
        prime * result + ((primaryKey == null) ? 0 : primaryKey.hashCode());
    result = prime * result + ((roleName == null) ? 0 : roleName.hashCode());
    return result;
  }

  @Override
  public boolean equals(final Object obj) { // NOPMD
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    AdminGroupData other = (AdminGroupData) obj;
    if (accessRules == null) {
      if (other.accessRules != null) {
        return false;
      }
    } else if (!accessRules.equals(other.accessRules)) {
      return false;
    }
    if (accessUsers == null) {
      if (other.accessUsers != null) {
        return false;
      }
    } else if (!accessUsers.equals(other.accessUsers)) {
      return false;
    }
    if (primaryKey == null) {
      if (other.primaryKey != null) {
        return false;
      }
    } else if (!primaryKey.equals(other.primaryKey)) {
      return false;
    }
    if (roleName == null) {
      if (other.roleName != null) {
        return false;
      }
    } else if (!roleName.equals(other.roleName)) {
      return false;
    }
    return true;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // What is important to protect here is the data that we define, id, name
    // and certificate profile data
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getPrimaryKey()).append(getRoleName());
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 1;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return String.valueOf(getPrimaryKey());
  }

  //
  // End Database integrity protection methods
  //

  @Override
  public int compareTo(final AdminGroupData o) {
    return roleName.compareToIgnoreCase(o.roleName);
  }

  @Override
  public String toString() {
    return roleName;
  }
}
