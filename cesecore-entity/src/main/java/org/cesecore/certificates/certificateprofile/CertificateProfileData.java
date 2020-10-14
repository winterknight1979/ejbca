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
package org.cesecore.certificates.certificateprofile;

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
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.legacy.Eca7277CertificateProfileData;
import org.cesecore.util.QueryResultWrapper;

/**
 * Representation of a certificate profile (template).
 *
 * @version $Id: CertificateProfileData.java 34415 2020-01-30 12:29:30Z aminkh $
 */
@SuppressWarnings("deprecation")
@Entity
@Table(name = "CertificateProfileData")
public class CertificateProfileData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CertificateProfileData.class); // NOPMD

  /** Param. */
  private Integer id;
  /** Param. */
  private String
      certificateProfileName; // NOPMD, this is what the database column is
                              // called.
  /** Param. */
  private Serializable data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /** Needed by JPA. */
  public CertificateProfileData() { }

  /**
   * Entity holding data of a certificate profile.
   *
   * @param anId ID
   * @param profilename Name
   * @param profile Profile
   */
  public CertificateProfileData(
      final Integer anId,
      final String profilename,
      final CertificateProfile profile) {
    setId(anId);
    setCertificateProfileName(profilename);
    setCertificateProfile(profile);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created certificateprofile " + profilename + ", " + anId);
    }
  }

  /**
   * @return ID
   */
  // @Id @Column
  public Integer getId() {
    return id;
  }

  /**
   * @param anId ID
   */
  public final void setId(final Integer anId) {
    this.id = anId;
  }

  /**
   * @return Name
   */
  // @Column
  public String getCertificateProfileName() {
    return certificateProfileName;
  }

  /**
   * @param aCertificateProfileName Name
   */
  public void setCertificateProfileName(final String aCertificateProfileName) {
    this.certificateProfileName = aCertificateProfileName;
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
   * @param theData data
   */
  public void setDataUnsafe(final Serializable theData) {
    this.data = theData;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
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

  private void setData(final LinkedHashMap<?, ?> theData) {
    setDataUnsafe(theData);
  }

  /**
   * Method that returns the certificate profiles and updates it if necessary.
   *
   * @return profile
   */
  @Transient
  public CertificateProfile getCertificateProfile() {
    return readAndUpgradeProfileInternal();
  }

  /**
   * Method that saves the certificate profile to database.
   *
   * @param profile profile
   */
  public final void setCertificateProfile(final CertificateProfile profile) {
    setData((LinkedHashMap<?, ?>) profile.saveData());
  }

  /** Method that upgrades a Certificate Profile, if needed. */
  public void upgradeProfile() {
    readAndUpgradeProfileInternal();
  }

  /**
   * We have an internal method for this read operation with a side-effect. This
   * is because getCertificateProfile() is a read-only method, so the possible
   * side-effect of upgrade will not happen, and therefore this internal method
   * can be called from another non-read-only method, upgradeProfile().
   *
   * @return CertificateProfile
   *     <p>TODO: Verify read-only? apply read-only?
   */
  private CertificateProfile readAndUpgradeProfileInternal() {
    CertificateProfile returnval = null;
    returnval =
        new CertificateProfile(
            CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    final LinkedHashMap<?, ?> thedata = getData();
    // If CertificateProfile-data is upgraded we want to save the new data, so
    // we must get the old version before loading the data
    // and perhaps upgrading
    final float oldversion =
        ((Float) thedata.get(UpgradeableDataHashMap.VERSION)).floatValue();
    // Load the profile data, this will potentially upgrade the
    // CertificateProfile
    returnval.loadData(thedata);
    if (Float.compare(oldversion, returnval.getVersion()) != 0) {
      // Save new data versions differ
      setCertificateProfile(returnval);
    }
    return returnval;
  }

  //
  // Search functions.
  //

  /**
   * @param entityManager EM
   * @param id ID
   * @return the found entity instance or null if the entity does not exist
   */
  public static CertificateProfileData findById(
      final EntityManager entityManager, final Integer id) {
    return entityManager.find(CertificateProfileData.class, id);
  }

  /**
   * @param entityManager EM
   * @param certificateProfileName Name
   * @throws javax.persistence.NonUniqueResultException if more than one entity
   *     with the name exists
   * @return the found entity instance or null if the entity does not exist
   */
  public static CertificateProfileData findByProfileName(
      final EntityManager entityManager, final String certificateProfileName) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM CertificateProfileData a WHERE"
                + " a.certificateProfileName=:certificateProfileName");
    query.setParameter("certificateProfileName", certificateProfileName);
    return (CertificateProfileData) QueryResultWrapper.getSingleResult(query);
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<CertificateProfileData> findAll(
      final EntityManager entityManager) {
    final Query query =
        entityManager.createQuery("SELECT a FROM CertificateProfileData a");
    return query.getResultList();
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final int cap = 2200;
    final ProtectionStringBuilder build =
        new ProtectionStringBuilder(
            cap); // an almost empty profile gives ~2100 chars of protect
                   // string
    // What is important to protect here is the data that we define, id, name
    // and certificate profile data
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getId()).append(getCertificateProfileName()).append(getData());
    if (LOG.isDebugEnabled()) {
      // Some profiling
      if (build.length() > cap) {
        LOG.debug(
            "CertificateProfileData.getProtectString gives size: "
                + build.length());
      }
    }
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

  /**
   * Due to an issue with db protection between EJBCA 6.12 and 6.14.1 we need
   * special handling to verify protection created between those versions. If
   * the initial data verification failed, we should to "patch" the protect
   * string and verify again. If this fails we behave as usual, i.e. throw the
   * original exception if erroronverify is set, or if not set just log a
   * warning.
   *
   * <p>This code can be removed once we are sure that all installations have
   * performed post-upgrade on EJBCA version 7.x or later.
   *
   * @param possibleTamper an exception raised due to a possible database tamper
   * @throws DatabaseProtectionException possibleTamper is thrown if the
   *     exception was not caused by ECA-7277, i.e the signature did not verify
   *     over the "patched" protect string either.
   */
  @Transient
  @Override
  @Deprecated
  protected void onDataVerificationError(
      final DatabaseProtectionException possibleTamper) {
    try {
      // Try to verify again with a mocked CertificateProfileData object
      // returning a "patched"
      // protect string
      impl.verifyData(new Eca7277CertificateProfileData(this));
    } catch (final DatabaseProtectionException e) {
      // Ignore the new exception and fall back to the default behaviour
      super.onDataVerificationError(possibleTamper);
    }
  }

  @Override
  @Transient
  protected String getRowId() {
    return String.valueOf(getId());
  }
  //
  // End Database integrity protection methods
  //
}
