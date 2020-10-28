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

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
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
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;

/**
 * Representation of a hard token profile.
 *
 * @version $Id: HardTokenProfileData.java 19902 2014-09-30 14:32:24Z anatom $
 */
@Entity
@Table(name = "HardTokenProfileData")
public class HardTokenProfileData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Log. */
  private static final Logger LOG =
      Logger.getLogger(HardTokenProfileData.class);

  /** Param. */
  private int id;
  /** Param. */
  private String name;
  /** Param. */
  private int updateCounter;
  /** Param. */
  private String data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a hard token profile.
   *
   * @param anid ID
   * @param aname Name
   * @param aprofile Profile
   */
  public HardTokenProfileData(
      final int anid, final String aname, final HardTokenProfile aprofile) {
    setId(anid);
    setName(aname);
    setUpdateCounter(0);
    if (aprofile != null) {
      setHardTokenProfile(aprofile);
    }
    LOG.debug("Created Hard Token Profile " + aname);
  }

  /** Empty. */
  public HardTokenProfileData() { }

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
   * @return count
   */
  // @Column
  public int getUpdateCounter() {
    return updateCounter;
  }

  /**
   * @param anupdateCounter count
   */
  public void setUpdateCounter(final int anupdateCounter) {
    this.updateCounter = anupdateCounter;
  }

  /**
   * @return data
   */
  // @Column @Lob
  public String getData() {
    return data;
  }

  /**
   * @param adata data
   */
  public void setData(final String adata) {
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

  /**
   * Method that saves the hard token profile data to database.
   *
   * @param hardtokenprofile Profile
   */
  @SuppressWarnings("unchecked")
  @Transient
  public void setHardTokenProfile(final HardTokenProfile hardtokenprofile) {
    // We must base64 encode string for UTF safety
    HashMap<Object, Object> a = new Base64PutHashMap();
    a.putAll((HashMap<Object, Object>) hardtokenprofile.saveData());
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    final int siz = 10000;
    try {
      if (LOG.isDebugEnabled()) {
        if (baos.size() < siz) {
          LOG.debug("Profiledata: \n" + baos.toString("UTF8"));
        } else {
          LOG.debug("Profiledata larger than 10000 bytes, not displayed.");
        }
      }
      setData(baos.toString("UTF8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
    setUpdateCounter(getUpdateCounter() + 1);
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
    build
        .append(getId())
        .append(getName())
        .append(getUpdateCounter())
        .append(getData());
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
   * @param pk PK
   * @return the found entity instance or null if the entity does not exist
   */
  public static HardTokenProfileData findByPK(
      final EntityManager entityManager, final Integer pk) {
    return entityManager.find(HardTokenProfileData.class, pk);
  }

  /**
   * @param entityManager EM
   * @param name Name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static HardTokenProfileData findByName(
      final EntityManager entityManager, final String name) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM HardTokenProfileData a WHERE a.name=:name");
    query.setParameter("name", name);
    return (HardTokenProfileData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<HardTokenProfileData> findAll(
      final EntityManager entityManager) {
    final Query query =
        entityManager.createQuery("SELECT a FROM HardTokenProfileData a");
    return query.getResultList();
  }
}
