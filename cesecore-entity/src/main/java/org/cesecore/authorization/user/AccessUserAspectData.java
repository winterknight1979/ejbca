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

package org.cesecore.authorization.user;

import java.security.InvalidParameterException;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.commons.lang.builder.CompareToBuilder;
import org.apache.log4j.Logger;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Represents an aspect of an external user. It can be set to match one
 * administrator's <i>DN</i> or an entire organization by matching against
 * <i>O</i>.
 *
 * @version $Id: AccessUserAspectData.java 27203 2017-11-17 12:51:52Z anatom $
 * @deprecated Kept only for upgrade reasons. Use
 *     org.cesecore.roles.RoleMemberData instead
 */
@Entity
@Table(name = "AdminEntityData")
public class AccessUserAspectData extends ProtectedData
    implements AccessUserAspect, Comparable<AccessUserAspectData> {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AccessUserAspectData.class);

  private static final long serialVersionUID = 2504191317243484124L;
  /** Key. */
  private int primaryKey;
  // Kept for legacy reasons
  /** Key. */
  private int legacyPrimaryKey;
  /** Type. */
  private String tokenType;
  /** ID. */
  private Integer caId;
  /** Version. */
  private int rowVersion = 0;
  /** Protect. */
  private String rowProtection;
  /** Match. */
  private Integer matchWith;
  /** Type. */
  private AccessMatchType matchType;
  /** Value. */
  private String matchValue;

  /**
  * @param roleName role
  * @param aCaId CA
  * @param aMatchWith match
  * @param aMatchType match
  * @param aMatchValue match
  */
  public AccessUserAspectData(
      final String roleName,
      final int aCaId,
      final AccessMatchValue aMatchWith,
      final AccessMatchType aMatchType,
      final String aMatchValue) {
    this(
        roleName,
        aCaId,
        aMatchWith.getNumericValue(),
        aMatchWith.getTokenType(),
        aMatchType,
        aMatchValue);
  }

  /**
   * This constructor for internal use only.
   *
   * @param roleName role
   * @param aCcaId CA
   * @param aMatchWith match
   * @param aTokenType type
   * @param aMatchType match
   * @param aMatchValue match
   */
  public AccessUserAspectData(
      final String roleName,
      final int aCcaId,
      final int aMatchWith,
      final String aTokenType,
      final AccessMatchType aMatchType,
      final String aMatchValue) {
    if (roleName == null) {
      throw new InvalidParameterException(
          "Attempted to create an AccessUserAspectData with roleName == null");
    }
    if (aMatchType == null) {
      throw new InvalidParameterException(
          "Attempted to create an AccessUserAspectData with matchType == null");
    } else {
      this.matchType = aMatchType;
    }
    if (aMatchValue == null) {
      throw new InvalidParameterException(
          "Attempted to create an AccessUserAspectData with matchValue =="
              + " null");
    } else {
      this.matchValue = aMatchValue;
    }
    if (aTokenType == null) {
      throw new InvalidParameterException(
          "Attempted to create an AccessUserAspectData with tokenType == null");
    } else {
      this.tokenType = aTokenType;
    }

    this.matchWith = aMatchWith;
    this.caId = aCcaId;
    this.primaryKey =
        generatePrimaryKey(
            roleName, aCcaId, aMatchWith, aMatchType, aMatchValue, aTokenType);
    this.legacyPrimaryKey =
        generatePrimaryKeyOld(
                roleName, aCcaId, aMatchWith, aMatchType, aMatchValue);
  }

  /** Private to stop default instantiation. */
  @SuppressWarnings("unused")
  private AccessUserAspectData() { }

  /**
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

  @Override
  public int getMatchWith() {
    return matchWith;
  }

  @Override
  public void setMatchWith(final Integer aMatchWith) {
    if (aMatchWith == null) {
      throw new InvalidParameterException("Invalid to set matchWith == null");
    }
    this.matchWith = aMatchWith;
  }

  @Override
  public int getMatchType() {
    if (matchType == null) {
      return AccessMatchType.TYPE_NONE.getNumericValue();
    }
    return matchType.getNumericValue();
  }

  @Override
  public void setMatchType(final Integer aMatchType) {
    if (aMatchType == null) {
      throw new InvalidParameterException("Invalid to set matchType == null");
    }
    this.matchType = AccessMatchType.matchFromDatabase(aMatchType);
  }

  @Override
  public void setMatchTypeAsValue(final AccessMatchType aMatchType) {
    if (aMatchType == null) {
      throw new InvalidParameterException("Invalid to set matchType == null");
    }
    this.matchType = aMatchType;
  }

  @Override
  @Transient
  public AccessMatchType getMatchTypeAsType() {
    return matchType;
  }

  @Override
  public String getMatchValue() {
    return matchValue;
  }

  @Override
  public void setMatchValue(final String aMatchValue) {
    if (aMatchValue == null) {
      // We must allow null value in order to upgrade smoothly from very old
      // versions. See ECA-6343
      // We can log though, to say that there is something to clean out
      LOG.info(
          "Trying to set matchValue == null. Old records in the database with"
              + " matchType 2000-2004 and matchValue should be deleted during"
              + " post-upgrade but can be deleted manually as well.");
    }
    this.matchValue = aMatchValue;
  }

  @Override
  public Integer getCaId() {
    return caId;
  }

  @Override
  public void setCaId(final Integer aCaId) {
    if (aCaId == null) {
      throw new InvalidParameterException("Invalid to set caId == null");
    }
    this.caId = aCaId;
  }

  /**
   * @return version
   */
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  /**
   * @return protect
   */
  public String getRowProtection() {
    return rowProtection;
  }

  /**
   * @param aRowProtection protect
   */
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  @Override
  public String getTokenType() {
    return tokenType;
  }

  @Override
  public void setTokenType(final String aTokenType) {
    this.tokenType = aTokenType;
  }

  /**
   * Method for creating a primary key. All of the given parameters will be
   * factored into the key using their hash values, and will be aggregated and
   * multiplied with two primes (23, 31) in order to ensure that the same value
   * for different parameters are weighted differently.
   *
   * @param roleName the name of the role that this value belongs to
   * @param caId the ID of the CA that issued the user
   * @param matchWith The type to match with
   * @param matchType How to match
   * @param matchValue the value to match
   * @return a pseudo-unique primary key
   */
  public static int generatePrimaryKey(
      final String roleName,
      final int caId,
      final AccessMatchValue matchWith,
      final AccessMatchType matchType,
      final String matchValue) {
    return generatePrimaryKey(
        roleName,
        caId,
        matchWith.getNumericValue(),
        matchType,
        matchValue,
        matchWith.getTokenType());
  }

  /**
   * Method for creating a primary key. All of the given parameters will be
   * factored into the key using their hash values, and will be aggregated and
   * multiplied with two primes (23, 31) in order to ensure that the same value
   * for different parameters are weighted differently.
   *
   * @param roleName the name of the role that this value belongs to
   * @param caId the ID of the CA that issued the user
   * @param matchWith The type to match with
   * @param matchType How to match
   * @param matchValue the value to match
   * @param tokenType the token type.
   * @return a pseudo-unique primary key
   */
  public static int generatePrimaryKey(
      final String roleName,
      final int caId,
      final int matchWith,
      final AccessMatchType matchType,
      final String matchValue,
      final String tokenType) {
    final int roleNameHash = roleName == null ? 0 : roleName.hashCode();
    final int matchValueHash = matchValue == null ? 0 : matchValue.hashCode();
    if (tokenType == null) {
      throw new IllegalArgumentException(
          "Could not generate primary key for aspect with null token type.");
    }
    // Use 23 and 31 as seed and aggregate values, as they are coprime numbers.
    final int seed = 23;
    final int aggregate = 31;
    return hash(
        seed,
        aggregate,
        new int[] {
          roleNameHash,
          matchValueHash,
          caId,
          matchWith,
          matchType.getNumericValue(),
          tokenType.hashCode()
        });
  }

  /**
   * Create a combined hash value, stolen from the Great Skeet.
   *
   * @param seedValue a start value
   * @param aggregateValue an aggregate value, should be coprime to seedValue
   * @param values a list of values to add to the hash
   * @return a relatively unique number
   */
  private static int hash(
      final int seedValue, final int aggregateValue, final int[] values) {
    int hash = seedValue;
    for (int value : values) {
      hash = hash * aggregateValue + value;
    }
    return hash;
  }

  /**
   * Method for creating a primary key.
   *
   * @param roleName the name of the role that this value belongs to
   * @param caId the ID of the CA that issued the user
   * @param matchWith The type to match with
   * @param matchType How to match
   * @param matchValue the value to match
   * @return a unique primary key
   * @deprecated Replaced in 6.2.0 with generatePrimaryKey, kept only for
   *     upgrade purposes
   */
  @Deprecated
  public static int generatePrimaryKeyOld(
      final String roleName,
      final int caId,
      final int matchWith,
      final AccessMatchType matchType,
      final String matchValue) {
    final int roleNameHash = roleName == null ? 0 : roleName.hashCode();
    final int matchValueHash = matchValue == null ? 0 : matchValue.hashCode();
    return (roleNameHash & matchValueHash)
        ^ caId
        ^ matchWith
        ^ matchType.getNumericValue();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((caId == null) ? 0 : caId.hashCode());
    result = prime * result + ((matchType == null) ? 0 : matchType.hashCode());
    result =
        prime * result + ((matchValue == null) ? 0 : matchValue.hashCode());
    result = prime * result + ((matchWith == null) ? 0 : matchWith.hashCode());
    result = prime * result + primaryKey;
    return result;
  }

  @Override
  public boolean equals(final Object obj) { // NOPMD: Irreducible
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    AccessUserAspectData other = (AccessUserAspectData) obj;
    if (caId == null) {
      if (other.caId != null) {
        return false;
      }
    } else if (!caId.equals(other.caId)) {
      return false;
    }
    if (matchType != other.matchType) {
      return false;
    }
    if (matchValue == null) {
      if (other.matchValue != null) {
        return false;
      }
    } else if (!matchValue.equals(other.matchValue)) {
      return false;
    }
    if (matchWith.intValue() != other.matchWith.intValue()) {
      return false;
    }
    return primaryKey == other.primaryKey;
  }

  @Override
  public String toString() {
    return AccessMatchValueReverseLookupRegistry.INSTANCE
            .performReverseLookup(tokenType, matchWith)
            .name()
        + " matching '"
        + matchValue
        + "' as "
        + matchType.name();
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getPrimaryKey())
        .append(getMatchWith())
        .append(getMatchType())
        .append(getMatchValue())
        .append(getCaId());
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
  public int compareTo(final AccessUserAspectData o) {
    return new CompareToBuilder()
        .append(this.matchValue, o.matchValue)
        .toComparison();
  }

  /** @return the oldPrimaryKey */
  @Transient
  public int getLegacyPrimaryKey() {
    return legacyPrimaryKey;
  }
}
