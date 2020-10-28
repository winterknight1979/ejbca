/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.validation;

import java.io.Serializable;
import java.util.Collection;
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
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.validation.BlacklistEntry;

/**
 * Representation of a public key blacklist entry.
 *
 * @version $Id: BlacklistData.java 26310 2017-08-15 07:11:03Z anatom $
 */
@Entity
@Table(name = "BlacklistData")
public class BlacklistData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Class logger. */
  private static final Logger LOG = Logger.getLogger(BlacklistData.class);

  // data fields.
  /** Param. */
  private int id;
  /** Param. */
  private String type;
  /** Param. */
  private String value;
  /** Param. */
  private String data;
  /** Param. */
  private int updateCounter;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /** Creates a new instance. */
  public BlacklistData() { }

  /**
   * Creates a new instance.
   *
   * @param entry the public key blacklist domain object.
   */
  public BlacklistData(final BlacklistEntry entry) {
    setBlacklistEntry(entry);
    setUpdateCounter(0);
  }

  /**
   * Creates a new instance.
   *
   * @param entry the public key blacklist domain object.
   */
  @Transient
  public void setBlacklistEntry(final BlacklistEntry entry) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Setting BlacklistData '"
              + entry.getValue()
              + "' ("
              + entry.getID()
              + ")");
    }
    setId(entry.getID());
    setType(entry.getType());
    setValue(entry.getValue());
    setData(entry.getData());
    setUpdateCounter(getUpdateCounter() + 1);
  }

  /** @return Gets a balacklist domain object. */
  @Transient
  public BlacklistEntry getBlacklistEntry() {
    final BlacklistEntry ret =
        new BlacklistEntry(getId(), getType(), getValue(), getData());
    return ret;
  }

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
   * @return type
   */
  // @Column
  public String getType() {
    return type;
  }

  /**
   * @param atype type
   */
  public void setType(final String atype) {
    this.type = atype;
  }

  // @Column
  /**
   * See for instance {@link AlgorithmConstants#KEYALGORITHM_RSA} + length
   * 'RSA2048' and others.
   *
   * @return data
   */
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
   * @return val
   */
  // @Column
  public String getValue() {
    return value;
  }

  /**
   * @param avalue val
   */
  public void setValue(final String avalue) {
    this.value = avalue;
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
        .append(getType())
        .append(getValue())
        .append(getData())
        .append(getUpdateCounter());
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
  public static BlacklistData findById(
      final EntityManager entityManager, final int id) {
    return entityManager.find(BlacklistData.class, id);
  }

  /**
   * @param entityManager EM
   * @param type Type
   * @param value Value
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static BlacklistData findByTypeAndValue(
      final EntityManager entityManager,
      final String type,
      final String value) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM BlacklistData a WHERE a.type=:type and"
                + " a.value=:value");
    query.setParameter("type", type);
    query.setParameter("value", value);
    return (BlacklistData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<BlacklistData> findAll(final EntityManager entityManager) {
    final Query query =
        entityManager.createQuery("SELECT a FROM BlacklistData a");
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @param ids IDs
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<BlacklistData> findAllById(
      final EntityManager entityManager, final Collection<Integer> ids) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM BlacklistData a WHERE a.id IN (:ids)");
    query.setParameter("ids", ids);
    return query.getResultList();
  }
}
