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

package org.ejbca.core.ejb.keyrecovery;

import java.io.Serializable;
import java.math.BigInteger;
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
import org.cesecore.util.Base64;
import org.cesecore.util.StringTools;

/**
 * Representation of a certificates key recovery data.
 *
 * @version $Id: KeyRecoveryData.java 25742 2017-04-25 10:38:47Z anatom $
 */
@Entity
@Table(name = "KeyRecoveryData")
public class KeyRecoveryData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(KeyRecoveryData.class);

  /** Param. */
  private KeyRecoveryDataPK keyRecoveryDataPK;
  /** Param. */
  private String username;
  /** Param. */
  private Boolean markedAsRecoverableBool;
  /** Param. */
  private Integer markedAsRecoverableInt;
  /** Param. */
  private String keyData;
  /** Param. */
  private int cryptoTokenId = 0;
  /** Param. */
  private String keyAlias;
  /** Param. */
  private String publicKeyId;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding key recovery data of users certificate.
   *
   * @param certificatesn of certificate the keys are belonging to.
   * @param issuerdn issuerdn of certificate the keys are belonging to.
   * @param ausername of the owner of the keys.
   * @param acryptoTokenId the id of the cryptoToken that holds the key
   *     protecting this key recovery entry
   * @param akeyAlias the alias of the key protecting this key recovery entry
   * @param apublicKeyId the keyId (same as subjectKeyId
   *      of a certificateData) of
   *     key protecting this key recovery entry
   * @param keydata the actual keydata.
   */
  public KeyRecoveryData(
      final BigInteger certificatesn,
      final String issuerdn,
      final String ausername,
      final byte[] keydata,
      final int acryptoTokenId,
      final String akeyAlias,
      final String apublicKeyId) {
    setKeyRecoveryDataPK(
        new KeyRecoveryDataPK(certificatesn.toString(16), issuerdn));
    setUsername(ausername);
    setMarkedAsRecoverable(false);
    setKeyDataFromByteArray(keydata);
    setCryptoTokenId(acryptoTokenId);
    setKeyAlias(akeyAlias);
    setPublicKeyId(apublicKeyId);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created Key Recoverydata for user " + ausername);
    }
  }

  /** Empty. */
  public KeyRecoveryData() { }

  /**
   * @return PK
   */
  public KeyRecoveryDataPK getKeyRecoveryDataPK() {
    return keyRecoveryDataPK;
  }

  /**
   * @param akeyRecoveryDataPK PK
   */
  public void setKeyRecoveryDataPK(final KeyRecoveryDataPK akeyRecoveryDataPK) {
    this.keyRecoveryDataPK = akeyRecoveryDataPK;
  }

  /**
   * @return DN
   */
  @Transient
  public String getIssuerDN() {
    return keyRecoveryDataPK.getIssuerDN();
  }

  /**
   * @return user
   */
  // @Column
  public String getUsername() {
    return username;
  }

  /**
   * @param ausername user
   */
  public void setUsername(final String ausername) {
    this.username = StringTools.stripUsername(ausername);
  }

  /**
   * @return bool
   */
  @Transient
  public boolean getMarkedAsRecoverable() {
    Boolean markB = getMarkedAsRecoverableBool();
    if (markB != null) {
      return markB.booleanValue();
    }
    Integer markI = getMarkedAsRecoverableInt();
    if (markI != null) {
      return markI.intValue() == 1;
    }
    throw new RuntimeException(
        "Could not retreive KeyRecoveryData.markedAsRecoverable from"
            + " database.");
  }

  /**
   * @param markedAsRecoverable bool
   */
  public void setMarkedAsRecoverable(final boolean markedAsRecoverable) {
    setMarkedAsRecoverableBool(Boolean.valueOf(markedAsRecoverable));
    setMarkedAsRecoverableInt(markedAsRecoverable ? 1 : 0);
  }

  /**
   * Use getMarkedAsRecoverable() instead of this method! Ingres: Transient
   * Non-ingres: Mapped to "markedAsRecoverable"
   *
   * @return bool
   */
  public Boolean getMarkedAsRecoverableBool() {
    return markedAsRecoverableBool;
  }

  /**
   * @param amarkedAsRecoverableBool bool
   */
  public void setMarkedAsRecoverableBool(
      final Boolean amarkedAsRecoverableBool) {
    this.markedAsRecoverableBool = amarkedAsRecoverableBool;
  }

  /**
   * Use getMarkedAsRecoverable() instead of this method! Ingres: Mapped to
   * "markedAsRecoverable" Non-ingres: Transient.
   *
   * @return int
   */
  public Integer getMarkedAsRecoverableInt() {
    return markedAsRecoverableInt;
  }

  /**
   * @param amarkedAsRecoverableInt mark
   */
  public void setMarkedAsRecoverableInt(final Integer amarkedAsRecoverableInt) {
    this.markedAsRecoverableInt = amarkedAsRecoverableInt;
  }

  /**
   * @return data
   */
  // @Column @Lob
  public String getKeyData() {
    return keyData;
  }

  /**
   * @param akeyData data
   */
  public void setKeyData(final String akeyData) {
    this.keyData = akeyData;
  }

  /**
   * @return ID
   */
  // @Version @Column
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }

  /**
   * @param acryptoTokenId ID
   */
  public void setCryptoTokenId(final int acryptoTokenId) {
    this.cryptoTokenId = acryptoTokenId;
  }

  /**
   * @return alias
   */
  // @Version @Column
  public String getKeyAlias() {
    return keyAlias;
  }

  /**
   * @param akeyAlias alias
   */
  public void setKeyAlias(final String akeyAlias) {
    this.keyAlias = akeyAlias;
  }

  /**
   * @return ID
   */
  // @Version @Column
  public String getPublicKeyId() {
    return publicKeyId;
  }

  /**
   * @param apublicKeyId ID
   */
  public void setPublicKeyId(final String apublicKeyId) {
    this.publicKeyId = apublicKeyId;
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
   * @return SN
   */
  @Transient
  public BigInteger getCertificateSN() {
    return new BigInteger(keyRecoveryDataPK.getCertSN(), 16);
  }
  /*public void setCertificateSN(BigInteger certificatesn) {
      keyRecoveryDataPK.setCertSN(certificatesn.toString(16));
  }*/

  /**
   * @return data
   */
  @Transient
  public byte[] getKeyDataAsByteArray() {
    return Base64.decode(this.getKeyData().getBytes());
  }

  /**
   * @param keydata data
   */
  public void setKeyDataFromByteArray(final byte[] keydata) {
    setKeyData(new String(Base64.encode(keydata)));
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
        .append(getKeyRecoveryDataPK().getIssuerDN())
        .append(getKeyRecoveryDataPK().getCertSN())
        .append(getUsername())
        .append(getMarkedAsRecoverable())
        .append(getKeyData());
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
        .append(getKeyRecoveryDataPK().getIssuerDN())
        .append(getKeyRecoveryDataPK().getCertSN())
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
  public static KeyRecoveryData findByPK(
      final EntityManager entityManager, final KeyRecoveryDataPK pk) {
    return entityManager.find(KeyRecoveryData.class, pk);
  }

  /**
   * @param entityManager EM
   * @param username User
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<KeyRecoveryData> findByUsername(
      final EntityManager entityManager, final String username) {
    Query query =
        entityManager.createQuery(
            "SELECT a FROM KeyRecoveryData a WHERE a.username=:username");
    query.setParameter("username", username);
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @param usermark User
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<KeyRecoveryData> findByUserMark(
      final EntityManager entityManager, final String usermark) {
    List<KeyRecoveryData> ret = null;
    try {
      Query query =
          entityManager.createQuery(
              "SELECT a FROM KeyRecoveryData a WHERE a.username=:usermark AND"
                  + " a.markedAsRecoverableBool=TRUE");
      query.setParameter("usermark", usermark);
      ret = query.getResultList();
    } catch (Exception e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "If database does not support boolean (like Ingres) we would"
                + " expect an Exception here. Trying to treat"
                + " markedAsRecoverable as an Integer.",
            e);
      }
      Query query =
          entityManager.createQuery(
              "SELECT a FROM KeyRecoveryData a WHERE a.username=:usermark AND"
                  + " a.markedAsRecoverableInt=1");
      query.setParameter("usermark", usermark);
      ret = query.getResultList();
    }
    return ret;
  }
}
