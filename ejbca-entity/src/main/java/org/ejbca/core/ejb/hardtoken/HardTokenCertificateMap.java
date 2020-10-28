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
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Representation of certificates placed on a token.
 *
 * @version $Id: HardTokenCertificateMap.java 19902 2014-09-30 14:32:24Z anatom
 *     $
 */
@Entity
@Table(name = "HardTokenCertificateMap")
public class HardTokenCertificateMap extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** LOG. */
  private static final Logger LOG =
      Logger.getLogger(HardTokenCertificateMap.class);

  /** Param. */
  private String certificateFingerprint;
  /** Param. */
  private String tokenSN;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a certificate to hard token relation.
   *
   * @param acertificateFingerprint FP
   * @param atokenSN SN
   */
  public HardTokenCertificateMap(
      final String acertificateFingerprint, final String atokenSN) {
    setCertificateFingerprint(acertificateFingerprint);
    setTokenSN(atokenSN);
    LOG.debug("Created HardTokenCertificateMap for token SN: " + atokenSN);
  }

  /** Empty. */
  public HardTokenCertificateMap() { }

  /**
   * @return fp
   */
  // @Id @Column
  public String getCertificateFingerprint() {
    return certificateFingerprint;
  }

  /**
   * @param acertificateFingerprint FP
   */
  public void setCertificateFingerprint(final String acertificateFingerprint) {
    this.certificateFingerprint = acertificateFingerprint;
  }

  /**
   * @return SN
   */
  // @Column
  public String getTokenSN() {
    return tokenSN;
  }

  /**
   * @param atokenSN SN
   */
  public void setTokenSN(final String atokenSN) {
    this.tokenSN = atokenSN;
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
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getCertificateFingerprint()).append(getTokenSN());
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
    return getCertificateFingerprint();
  }

  //
  // End Database integrity protection methods
  //

  //
  // Search functions.
  //

  /**
   * @param entityManager EM
   * @param certificateFingerprint FP
   * @return the found entity instance or null if the entity does not exist
   */
  public static HardTokenCertificateMap findByCertificateFingerprint(
      final EntityManager entityManager, final String certificateFingerprint) {
    return entityManager.find(
        HardTokenCertificateMap.class, certificateFingerprint);
  }

  /**
   * @param entityManager EM
   * @param tokenSN SN
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<HardTokenCertificateMap> findByTokenSN(
      final EntityManager entityManager, final String tokenSN) {
    Query query =
        entityManager.createQuery(
            "SELECT a FROM HardTokenCertificateMap a WHERE a.tokenSN=:tokenSN");
    query.setParameter("tokenSN", tokenSN);
    return query.getResultList();
  }
}
