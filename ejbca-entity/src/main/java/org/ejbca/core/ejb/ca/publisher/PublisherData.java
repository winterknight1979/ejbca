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

package org.ejbca.core.ejb.ca.publisher;

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
import org.ejbca.core.model.ca.publisher.BasePublisher;

/**
 * Representation of a publisher.
 *
 * @version $Id: PublisherData.java 25263 2017-02-14 15:51:48Z jeklund $
 */
@Entity
@Table(name = "PublisherData")
public class PublisherData extends ProtectedData implements Serializable {
  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(PublisherData.class);

  /** Param. */
  private BasePublisher publisher = null;

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
   * Entity Bean holding data of a publisher.
   *
   * @param anid ID
   * @param aname Name
   * @param apublisher Pub
   *     <p>ejb.create-method view-type="local"
   */
  public PublisherData(
      final int anid, final String aname, final BasePublisher apublisher) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Creating PublisherData '" + aname + "' (" + anid + ")");
    }
    setId(anid);
    setName(aname);
    setUpdateCounter(0);
    if (apublisher != null) {
      setPublisher(apublisher);
    }
  }

  /** Empty constructor. */
  public PublisherData() { }

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
   * @param thedata data
   */
  public void setData(final String thedata) {
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

  /**
   * Method that gets the cached publisher, if any.
   *
   * @return pub
   */
  @Transient
  public BasePublisher getCachedPublisher() {
    return publisher;
  }

  /**
   * Method that saves the publisher data to database.
   *
   * @param apublisher pub
   */
  @SuppressWarnings({"unchecked", "rawtypes"})
  public void setPublisher(final BasePublisher apublisher) {
    // We must base64 encode string for UTF safety
    HashMap a = new Base64PutHashMap();
    a.putAll((HashMap) apublisher.saveData());
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    encoder.writeObject(a);
    encoder.close();
    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Publisher data: \n" + baos.toString("UTF8"));
      }
      setData(baos.toString("UTF8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
    this.publisher = apublisher;
    setUpdateCounter(getUpdateCounter() + 1);
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  public String getProtectString(final int version) {
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
   * @param id ID
   * @return the found entity instance or null if the entity does not exist
   */
  public static PublisherData findById(
      final EntityManager entityManager, final int id) {
    return entityManager.find(PublisherData.class, id);
  }

  /**
   * @param entityManager EM
   * @param name Name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static PublisherData findByName(
      final EntityManager entityManager, final String name) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM PublisherData a WHERE a.name=:name");
    query.setParameter("name", name);
    return (PublisherData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<PublisherData> findAll(final EntityManager entityManager) {
    final Query query =
        entityManager.createQuery("SELECT a FROM PublisherData a");
    return query.getResultList();
  }
}
