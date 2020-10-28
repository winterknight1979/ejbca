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

package org.ejbca.core.ejb.ra.userdatasource;

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
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;

/** Representation of a user data source. */
@Entity
@Table(name = "UserDataSourceData")
public class UserDataSourceData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(UserDataSourceData.class);

  /** Param. */
  private BaseUserDataSource userdatasource = null;

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
   * Entity holding data of a userdatasource.
   *
   * @param anid ID
   * @param aname Name
   * @param auserdatasource DS
   * @throws UnsupportedEncodingException Fail
   */
  public UserDataSourceData(
      final int anid,
      final String aname,
      final BaseUserDataSource auserdatasource)
      throws UnsupportedEncodingException {
    setId(anid);
    setName(aname);
    this.setUpdateCounter(0);
    if (auserdatasource != null) {
      setUserDataSource(auserdatasource);
    }
    LOG.debug("Created User Data Source " + aname);
  }

  /** Empty. */
  public UserDataSourceData() { }

  /**
   * Primary key.
   *
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
   * Name of the user data source.
   *
   * @return Name
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
   * Counter incremented each update used to check if a user data source proxy
   * class should update its data.
   *
   * @return Counter
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
   * Data saved concerning the user data source.
   *
   * @return Data
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
   * Method that returns the cached UserDataSource.
   *
   * @return DS
   */
  @Transient
  public BaseUserDataSource getCachedUserDataSource() {
    return userdatasource;
  }

  /**
   * Method that saves the userdatasource data to database.
   *
   * @param auserdatasource DS
   */
  @SuppressWarnings("unchecked")
  public void setUserDataSource(final BaseUserDataSource auserdatasource) {
    // We must base64 encode string for UTF safety
    HashMap<Object, Object> a = new Base64PutHashMap();
    a.putAll((HashMap<Object, Object>) auserdatasource.saveData());
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Profiledata: \n" + baos.toString("UTF8"));
      }
      setData(baos.toString("UTF8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
    this.userdatasource = auserdatasource;
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
  //  Search functions.
  //

  /**
   * @param entityManager EM
   * @param id ID
   * @return the found entity instance or null if the entity does not exist
   */
  public static UserDataSourceData findById(
      final EntityManager entityManager, final int id) {
    return entityManager.find(UserDataSourceData.class, Integer.valueOf(id));
  }

  /**
   * @param entityManager EM
   * @param name name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static UserDataSourceData findByName(
      final EntityManager entityManager, final String name) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM UserDataSourceData a WHERE a.name=:name");
    query.setParameter("name", name);
    return (UserDataSourceData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<UserDataSourceData> findAll(
      final EntityManager entityManager) {
    final Query query =
        entityManager.createQuery("SELECT a FROM UserDataSourceData a");
    return query.getResultList();
  }
}
