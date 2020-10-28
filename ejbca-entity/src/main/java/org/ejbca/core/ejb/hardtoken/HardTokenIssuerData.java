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
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;

// TODO: This class might need additional merging with
// org.ejbca.core.model.hardtoken.HardTokenIssuerData,
// org.ejbca.core.model.hardtoken.HardTokenIssuer

/**
 * Representation of a hard token issuer.
 *
 * @version $Id: HardTokenIssuerData.java 34415 2020-01-30 12:29:30Z aminkh $
 */
@Entity
@Table(name = "HardTokenIssuerData")
public class HardTokenIssuerData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(HardTokenIssuerData.class);

  /** Param. */
  private int id;
  /** Param. */
  private String alias;
  /** Param. */
  private int roleId;
  /** Param. */
  private Serializable data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a hard token issuer.
   *
   * @param anid ID
   * @param analias Alias
   * @param aroleId Role
   * @param issuerdata Issuer
   */
  public HardTokenIssuerData(
      final int anid,
      final String analias,
      final int aroleId,
      final HardTokenIssuer issuerdata) {
    setId(anid);
    setAlias(analias);
    setAdminGroupId(aroleId);
    setHardTokenIssuer(issuerdata);
    LOG.debug("Created Hard Token Issuer " + analias);
  }

  /** Empty. */
  public HardTokenIssuerData() { }

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
   * @return alias
   */
  // @Column
  public String getAlias() {
    return alias;
  }

  /**
   * @param analias alias
   */
  public void setAlias(final String analias) {
    this.alias = analias;
  }

/**
 * @return ID
 */
  // @Column
  public int getAdminGroupId() {
    return roleId;
  }

  /**
   * @param adminGroupId ID
   */
  public void setAdminGroupId(final int adminGroupId) {
    this.roleId = adminGroupId;
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
   * @param thedata data
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
   * Method that returns the hard token issuer data and updates it if nessesary.
   *
   * @return issuer
   */
  @Transient
  public HardTokenIssuer getHardTokenIssuer() {
    HardTokenIssuer returnval = new HardTokenIssuer();
    returnval.loadData(getData());
    return returnval;
  }

  /**
   * Method that saves the hard token issuer data to database.
   *
   * @param hardtokenissuer issuer
   */
  public void setHardTokenIssuer(final HardTokenIssuer hardtokenissuer) {
    setData((LinkedHashMap<?, ?>) hardtokenissuer.saveData());
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
        .append(getAlias())
        .append(getAdminGroupId())
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
  public static HardTokenIssuerData findByPK(
      final EntityManager entityManager, final Integer pk) {
    return entityManager.find(HardTokenIssuerData.class, pk);
  }

  /**
   * @param entityManager EM
   * @param alias Alias
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static HardTokenIssuerData findByAlias(
      final EntityManager entityManager, final String alias) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM HardTokenIssuerData a WHERE a.alias=:alias");
    query.setParameter("alias", alias);
    return (HardTokenIssuerData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<HardTokenIssuerData> findAll(
      final EntityManager entityManager) {
    final Query query =
        entityManager.createQuery("SELECT a FROM HardTokenIssuerData a");
    return query.getResultList();
  }
}
