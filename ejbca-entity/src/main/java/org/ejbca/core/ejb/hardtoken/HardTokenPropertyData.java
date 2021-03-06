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
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.NonUniqueResultException;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Complementary class used to assign extended properties like copyof to a hard
 * token.
 *
 * <p>Id is represented by primary key of hard token table.
 */
@Entity
@Table(name = "HardTokenPropertyData")
public class HardTokenPropertyData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Config. */
  public static final String PROPERTY_COPYOF = "copyof=";

  /** Param. */
  private HardTokenPropertyDataPK hardTokenPropertyDataPK;

  /** Param. */
  private String value;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a hard token properties.
   *
   * @param anid OD
   * @param aproperty Property
   * @param avalue Value
   */
  public HardTokenPropertyData(
      final String anid, final String aproperty, final String avalue) {
    setHardTokenPropertyDataPK(new HardTokenPropertyDataPK(anid, aproperty));
    setValue(avalue);
  }

  /** Empty. */
  public HardTokenPropertyData() { }

  /**
   * @return PK
   */
  // @EmbeddedId
  public HardTokenPropertyDataPK getHardTokenPropertyDataPK() {
    return hardTokenPropertyDataPK;
  }

  /**
   * @param thehardTokenPropertyDataPK PK
   */
  public void setHardTokenPropertyDataPK(
      final HardTokenPropertyDataPK thehardTokenPropertyDataPK) {
    this.hardTokenPropertyDataPK = thehardTokenPropertyDataPK;
  }

  /**
   * @return ID
   */
  @Transient
  public String getId() {
    return hardTokenPropertyDataPK.getId();
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
   * @return bersion
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
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getHardTokenPropertyDataPK().getId())
        .append(getHardTokenPropertyDataPK().getProperty())
        .append(getValue());
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
    return new ProtectionStringBuilder()
        .append(getHardTokenPropertyDataPK().getId())
        .append(getHardTokenPropertyDataPK())
        .toString();
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
  public static HardTokenPropertyData findByPK(
      final EntityManager entityManager, final HardTokenPropertyDataPK pk) {
    return entityManager.find(HardTokenPropertyData.class, pk);
  }

  /**
   * @param entityManager EM
   * @param id ID
   * @param property Property
   * @throws NonUniqueResultException if more than one entity with the name
   *     exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static HardTokenPropertyData findByProperty(
      final EntityManager entityManager,
      final String id,
      final String property) {
    HardTokenPropertyData ret = null;

    Query query =
        entityManager.createQuery(
            "SELECT a FROM HardTokenPropertyData a WHERE"
                + " a.hardTokenPropertyDataPK.id=:id AND"
                + " a.hardTokenPropertyDataPK.property=:property");
    query.setParameter("id", id);
    query.setParameter("property", property);
    @SuppressWarnings("unchecked")
    List<HardTokenPropertyData> resultList =
        (List<HardTokenPropertyData>) query.getResultList();

    switch (resultList.size()) {
      case 0:
        ret = null;
        break;
      case 1:
        ret = resultList.get(0);
        break;
      default:
        throw new NonUniqueResultException(
            "Several entries with the same primary key where found in the"
                + " table HardTokenPropertyData.");
    }

    return ret;
  }

  /**
   * @param entityManager EM
   * @param property Property
   * @param value Value
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<HardTokenPropertyData> findIdsByPropertyAndValue(
      final EntityManager entityManager,
      final String property,
      final String value) {
    Query query =
        entityManager.createQuery(
            "SELECT a FROM HardTokenPropertyData a WHERE"
                + " a.hardTokenPropertyDataPK.property=:property AND"
                + " a.value=:value");
    query.setParameter("property", property);
    query.setParameter("value", value);
    return query.getResultList();
  }
}
