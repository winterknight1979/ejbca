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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * Representation of admin's preferences.
 *
 * @version $Id: AdminPreferencesData.java 34415 2020-01-30 12:29:30Z aminkh $
 */
@Entity
@Table(name = "AdminPreferencesData")
public class AdminPreferencesData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AdminPreferencesData.class);

  /** Param. */
  private String id;
  /** Param. */
  private Serializable data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of admin preferences.
   *
   * @param anid the serialnumber.
   * @param adminpreference is the AdminPreference.
   */
  public AdminPreferencesData(
      final String anid, final AdminPreference adminpreference) {
    setId(anid);
    setAdminPreference(adminpreference);
    LOG.debug("Created admin preference " + anid);
  }

  /** Empty. */
  public AdminPreferencesData() { }

  /**
   * @return ID
   */
  // @Id @Column
  public String getId() {
    return id;
  }

  /**
   * @param anid ID
   */
  public void setId(final String anid) {
    this.id = anid;
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
   * @param adata Data
   */
  public void setDataUnsafe(final Serializable adata) {
    this.data = adata;
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

  private void setData(final LinkedHashMap<?, ?> adata) {
    setDataUnsafe(adata);
  }

  /**
   * Method that returns the admin's preferences and updates it if necessary.
   *
   * @return Preferences
   */
  @Transient
  public AdminPreference getAdminPreference() {
    AdminPreference returnval = new AdminPreference();
    returnval.loadData(getData());
    return returnval;
  }
  /**
   * Method that saves the admin preference to database.
   *
   * @param adminpreference Preferences
   */
  public void setAdminPreference(final AdminPreference adminpreference) {
    setData((LinkedHashMap<?, ?>) adminpreference.saveData());
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
    build.append(getId()).append(getData());
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
    return getId();
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
  public static AdminPreferencesData findById(
      final EntityManager entityManager, final String id) {
    return entityManager.find(AdminPreferencesData.class, id);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<AdminPreferencesData> findAll(
      final EntityManager entityManager) {
    return (List<AdminPreferencesData>)
        entityManager
            .createQuery("SELECT a FROM AdminPreferencesData a")
            .getResultList();
  }
}
