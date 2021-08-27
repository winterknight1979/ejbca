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
package org.cesecore.authorization.rules;

import java.io.Serializable;
import java.security.InvalidParameterException;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.commons.lang.builder.CompareToBuilder;
import org.cesecore.CesecoreRuntimeException;
import org.cesecore.authorization.access.AccessTreeState;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * POJO that represents an access rule.
 *
 * <p>Adapted from AccessRule version $Id: AccessRuleData.java 25514 2017-03-16
 * 15:27:56Z henriks $ in EJBCA.
 *
 * @version $Id: AccessRuleData.java 25514 2017-03-16 15:27:56Z henriks $
 */
@Deprecated // replaced with hashmap in Role (EJBCA 6.8.0)
@Entity
@Table(name = "AccessRuleData")
public class AccessRuleData extends ProtectedData
    implements Serializable, Comparable<AccessRuleData> {

  private static final long serialVersionUID = 8314055274021576487L;

  /** PK. */
  private int primaryKey;
  /** Name. */
  private String accessRuleName;
  /** State. */
  private AccessRuleState internalState;
  /** Bool. */
  private Boolean recursiveBool;
  /** Int. */
  private Integer recursiveInt;
  /** Version. */
  private int rowVersion = 0;
  /** protect. */
  private String rowProtection;

  /** Default constructor private to prohibit default instantiation. */
  @SuppressWarnings("unused")
  private AccessRuleData() { }

  /**
   * Creates a new instance of AccessRule.
   *
   * @param aPrimaryKey Primary key for this rule. Can be generated using the
   *     static method {@link AccessRuleData#generatePrimaryKey(String, String)}
   * @param anAccessRuleName The rule that this AccessRule should represent.
   * @param anInternalState The rule's state.
   * @param isRecursive True if the rule is recursive.
   */
  public AccessRuleData(
      final int aPrimaryKey,
      final String anAccessRuleName,
      final AccessRuleState anInternalState,
      final boolean isRecursive) {
    if (anAccessRuleName == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with accessruleName == null");
    } else if (anInternalState == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with internalState == null");
    }
    this.primaryKey = aPrimaryKey;
    this.accessRuleName = anAccessRuleName.trim();
    this.internalState = anInternalState;
    setRecursive(isRecursive);
  }

  /**
   * Creates a new instance of AccessRule.
   *
   * @param aRoleName The name of the Role to which this rule belongs. Used to
   *     generate primary key.
   * @param anAccessRuleName The rule that this AccessRule should represent.
   * @param anInternalState The rule's state.
   * @param isRecursive True if the rule is recursive.
   */
  public AccessRuleData(
      final String aRoleName,
      final String anAccessRuleName,
      final AccessRuleState anInternalState,
      final boolean isRecursive) {
    if (aRoleName == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with roleName == null");
    } else {
      this.primaryKey = generatePrimaryKey(aRoleName, anAccessRuleName);
    }
    if (anAccessRuleName == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with accessruleName == null");
    } else {
      this.accessRuleName = anAccessRuleName.trim();
    }
    if (anInternalState == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with internalState == null");
    } else {
      this.internalState = anInternalState;
    }
    setRecursive(isRecursive);
  }

  /**
   * @return Name
   */
  // @Column
  public String getAccessRuleName() {
    return accessRuleName;
  }

  /**
   * @param anAccessRuleName Name
   */
  public void setAccessRuleName(final String anAccessRuleName) {
    if (anAccessRuleName == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with accessruleName == null");
    }
    this.accessRuleName = anAccessRuleName.trim();
  }

  /**
   * @return state
   */
  @Transient
  public AccessRuleState getInternalState() {
    return internalState;
  }

  /**
   * @param state state
   */
  public void setInternalState(final AccessRuleState state) {
    if (state == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with state == null");
    }
    this.internalState = state;
    if (!internalState.equals(AccessRuleState.RULE_ACCEPT) && getRecursive()) {
      setRecursive(false);
    }
  }

  /**
   * Formerly known as PRIMKEY.
 * @return PK
   */
  // @Id @Column
  public int getPrimaryKey() {
    return primaryKey;
  }

  /**
   * @param aPrimaryKey PK
   */
  public void setPrimaryKey(final int aPrimaryKey) {
    this.primaryKey = aPrimaryKey;
  }

  /**
   * This is a "combined" value of recursiveBool and recursiveInt. Used because
   * some databases lacks a boolean type so booleanInt is a workaround to get
   * boolean values on such databases (Ingres).
   *
   * @return boolean
   */
  @Transient
  public boolean getRecursive() {
    final Boolean isRecB = getRecursiveBool();
    if (isRecB != null) {
      return isRecB.booleanValue();
    }
    final Integer isRecI = getRecursiveInt();
    if (isRecI != null) {
      return isRecI.intValue() == 1;
    }
    throw new CesecoreRuntimeException(
        "Could not retreive AccessRulesData.recursive from database.");
  }

  /**
   * @param recursive bool
   */
  public final void setRecursive(final boolean recursive) {
    if (internalState == AccessRuleState.RULE_ACCEPT) {
      setRecursiveBool(Boolean.valueOf(recursive));
      setRecursiveInt(recursive ? 1 : 0);
    } else {
      setRecursiveBool(false);
      setRecursiveInt(0);
    }
  }

  /**
   * Use getIsRecursive() instead of this method! Ingres: Transient Non-ingres:
   * Mapped to "isRecursive"
   *
   * @return bool
   */
  public Boolean getRecursiveBool() {
    return recursiveBool;
  }

  /**
   * Use setIsRecursive(boolean) instead of this method!
   *
   * @param aRecursiveBool boolean
   */
  public void setRecursiveBool(final Boolean aRecursiveBool) {
    if (aRecursiveBool == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with recursiveBool == null");
    }
    this.recursiveBool = aRecursiveBool;
  }

  /**
   * Use getIsRecursive() instead of this method! Ingres: Mapped to
   * "isRecursive" Non-ingres: Transient
   *
   * @return int
   */
  public Integer getRecursiveInt() {
    return recursiveInt;
  }

  /**
   * Use setIsRecursive(boolean) instead of this method!
   *
   * @param isRecursiveInt int
   */
  public void setRecursiveInt(final Integer isRecursiveInt) {
    if (isRecursiveInt == null) {
      throw new InvalidParameterException(
          "Illegal to create an access rule with isRecursiveInt == null");
    }
    this.recursiveInt = isRecursiveInt;
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
   * Formerly known as "RULE".
   * @return rule
   */
  // @Column
  public int getState() {
    return internalState.getDatabaseValue();
  }

  /**
   * @param state State
   */
  public void setState(final int state) {
    this.internalState = AccessRuleState.matchDatabaseValue(state);
  }

  /**
   * @return state
   */
  @Transient
  public AccessTreeState getTreeState() {
    AccessTreeState result = AccessTreeState.STATE_UNKNOWN;

    switch (internalState) {
      case RULE_ACCEPT:
        result =
            getRecursive()
                ? AccessTreeState.STATE_ACCEPT_RECURSIVE
                : AccessTreeState.STATE_ACCEPT;
        break;
      case RULE_DECLINE:
        result = AccessTreeState.STATE_DECLINE;
        break;
      default:
        result = AccessTreeState.STATE_UNKNOWN;
        break;
    }

    return result;
  }

  /**
   * The current pk in AdminEntityData and AccessRulesData is a mix of integer
   * pk and constraints and actually works fine. It's used like a primitive int
   * primary key in the db, but embeds logic for enforcing constraints, which
   * would otherwise have to be programatically added to the beans. If needed it
   * can easily be replaced with an int pk and programmatic logic to handle
   * constraints. From the database view the pk is just an int.
   *
   * @param roleName role
   * @param accessRuleName rule
   * @return PK
   */
  public static int generatePrimaryKey(
      final String roleName, final String accessRuleName) {
    final int roleNameHash = roleName == null ? 0 : roleName.hashCode();
    final int accessRuleHash =
        accessRuleName == null ? 0 : accessRuleName.trim().hashCode();
    return roleNameHash ^ accessRuleHash;
  }

  @Override
  public int hashCode() {
    final int prime = 47811;
    int result = 1;
    result =
        prime * result
            + ((accessRuleName == null) ? 0 : accessRuleName.hashCode());
    result =
        prime * result
            + ((internalState == null) ? 0 : internalState.getDatabaseValue());
    result = prime * result + primaryKey;
    result =
        prime * result
            + ((recursiveBool == null) ? 0 : recursiveBool.hashCode());
    result =
        prime * result + ((recursiveInt == null) ? 0 : recursiveInt.hashCode());
    return result;
  }

  @Override
  public boolean equals(final Object obj) { // NOPMD: irreducible
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    AccessRuleData other = (AccessRuleData) obj;
    if (accessRuleName == null) {
      if (other.accessRuleName != null) {
        return false;
      }
    } else if (!accessRuleName.equals(other.accessRuleName)) {
      return false;
    }
    // Comparing DB values to defend against the enums being loaded by different
    // class loaders.
    if (internalState != other.internalState) {
      //  if (internalState.getDatabaseValue() !=
      // other.internalState.getDatabaseValue()) {
      return false;
    }
    if (primaryKey != other.primaryKey) {
      return false;
    }
    // We must compare the "combined" value of recursiveBool and recursiveInt
    // here, since only one of
    // the values are used depending on different databases
    return getRecursive() == other.getRecursive();
  }

  @Override
  public String toString() {
    final StringBuilder buf = new StringBuilder();
    buf.append(getPrimaryKey())
        .append(getAccessRuleName())
        .append(getInternalState())
        .append(getRecursive());
    return buf.toString();
  }
  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    ProtectionStringBuilder build = new ProtectionStringBuilder();
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getPrimaryKey())
        .append(getAccessRuleName())
        .append(getInternalState())
        .append(getRecursive());
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
  public int compareTo(final AccessRuleData o) {
    return new CompareToBuilder()
        .append(this.accessRuleName, o.accessRuleName)
        .toComparison();
  }
}
