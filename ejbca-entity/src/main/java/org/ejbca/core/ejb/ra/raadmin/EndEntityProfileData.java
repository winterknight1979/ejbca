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

package org.ejbca.core.ejb.ra.raadmin;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Representation of an End Entity Profile.
 *
 * @version $Id: EndEntityProfileData.java 34415 2020-01-30 12:29:30Z aminkh $
 */
@Entity
@Table(name = "EndEntityProfileData")
public class EndEntityProfileData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(EndEntityProfileData.class);

  /** Param. */
  private int id;
  /** Param. */
  private String profileName;
  /** Param. */
  private Serializable data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a end entity profile.
   *
   * @param anid ID
   * @param aprofileName Profile
   * @param endEntityProfile Entity
   */
  public EndEntityProfileData(
      final int anid,
      final String aprofileName,
      final EndEntityProfile endEntityProfile) {
    setId(anid);
    setProfileName(aprofileName);
    setProfile(endEntityProfile);
    LOG.debug("Created profile " + aprofileName);
  }

  /**
   * empty.
   */
  public EndEntityProfileData() { }

  /**
   * @return ID
   */
  // @Id @Column
  public int getId() {
    return id;
  }

  /**
   * @param anid ID
   */
  public void setId(final int anid) {
    this.id = anid;
  }

  /**
   * @return name
   */
  // @Column
  public String getProfileName() {
    return profileName;
  }

  /**
   * @param aprofileName name
   */
  public void setProfileName(final String aprofileName) {
    this.profileName = aprofileName;
  }

  /**
   * @return data
   */
  // @Column @Lob
  public Serializable getDataUnsafe() {
    return data;
  }
  /**
   * DO NOT USE! Stick with setData(HashMap data) instead.
   *
   * @param thedata Data
   */
  public void setDataUnsafe(final Serializable thedata) {
    this.data = thedata;
  }


  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String arowProtection) {
    this.rowProtection = arowProtection;
  }

  @Transient
  private LinkedHashMap<?, ?> getData() {
    final Serializable map = getDataUnsafe();
    if (map instanceof LinkedHashMap<?, ?>) {
      return (LinkedHashMap<?, ?>) map;
    } else {
      return new LinkedHashMap<>((Map<?, ?>) map);
    }
  }

  private void setData(final LinkedHashMap<?, ?> thedata) {
    setDataUnsafe(thedata);
  }

  /**
   * Method that returns the end entity profile and updates it if necessary.
   *
   * @return Profile
   */
  @Transient
  public EndEntityProfile getProfile() {
    return readAndUpgradeProfileInternal();
  }

  /**
   * Method that saves the end entity profile.
   *
   * @param profile profile
   */
  public void setProfile(final EndEntityProfile profile) {
    setData((LinkedHashMap<?, ?>) profile.saveData());
  }

  /** Method that upgrades a EndEntity Profile, if needed. */
  public void upgradeProfile() {
    readAndUpgradeProfileInternal();
  }

  /**
   * We have an internal method for this read operation with a side-effect. This
   * is because getProfile() is a read-only method, so the possible side-effect
   * of upgrade will not happen, and therefore this internal method can be
   * called from another non-read-only method, upgradeProfile().
   *
   * @return EndEntityProfile TODO: Still true with JPA?
   */
  private EndEntityProfile readAndUpgradeProfileInternal() {
    EndEntityProfile returnval = new EndEntityProfile(0);
    HashMap<?, ?> thedata = getData();
    // If EndEntityProfile-data is upgraded we want to save the new data, so we
    // must get the old version before loading the data
    // and perhaps upgrading
    float oldversion =
        ((Float) thedata.get(UpgradeableDataHashMap.VERSION)).floatValue();
    // Load the profile data, this will potentially upgrade the
    // CertificateProfile
    returnval.loadData(thedata);
    if (Float.compare(oldversion, returnval.getVersion()) != 0) {
      // Save new data versions differ
      setProfile(returnval);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Saved upgraded profile, old version="
                + oldversion
                + ", new version="
                + returnval.getVersion());
      }
    }
    return returnval;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getId()).append(getProfileName()).append(getData());
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
    return String.valueOf(getId());
  }

  //
  // End Database integrity protection methods
  //

  //
  // Search functions.
  //

  /**
   * @param entityManager EM
   * @param id ID
   * @return the found entity instance or null if the entity does not exist
   */
  public static EndEntityProfileData findById(
      final EntityManager entityManager, final int id) {
    return entityManager.find(EndEntityProfileData.class, id);
  }

  /**
   * @param entityManager EM
   * @param profileName Name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static EndEntityProfileData findByProfileName(
      final EntityManager entityManager, final String profileName) {
    Query query =
        entityManager.createQuery(
            "SELECT a FROM EndEntityProfileData a WHERE"
                + " a.profileName=:profileName");
    query.setParameter("profileName", profileName);
    return (EndEntityProfileData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<EndEntityProfileData> findAll(
      final EntityManager entityManager) {
    Query query =
        entityManager.createQuery("SELECT a FROM EndEntityProfileData a");
    return query.getResultList();
  }
}
