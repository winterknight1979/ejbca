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
import java.util.Date;
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
import org.cesecore.util.Base64;
import org.cesecore.util.StringTools;

/**
 * Representation of a hard token.
 *
 * @version $Id: HardTokenData.java 34415 2020-01-30 12:29:30Z aminkh $
 */
@Entity
@Table(name = "HardTokenData")
public class HardTokenData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(HardTokenData.class);

  /** Config. */
  public static final String ENCRYPTEDDATA = "ENCRYPTEDDATA";

  /** Param. */
  private String tokenSN;
  /** Param. */
  private String username;
  /** Param. */
  private long cTime;
  /** Param. */
  private long mTime;
  /** Param. */
  private int tokenType;
  /** Param. */
  private String significantIssuerDN;
  /** Param. */
  private Serializable data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a hard token issuer.
   *
   * @param tokensn SN
   * @param ausername User
   * @param createtime Created
   * @param modifytime Modified
   * @param tokentype Type
   * @param significantissuerdn DN
   * @param thedata Data
   */
  public HardTokenData(
      final String tokensn,
      final String ausername,
      final Date createtime,
      final Date modifytime,
      final int tokentype,
      final String significantissuerdn,
      final LinkedHashMap<?, ?> thedata) {
    setTokenSN(tokensn);
    setUsername(ausername);
    setCtime(createtime.getTime());
    setMtime(modifytime.getTime());
    setTokenType(tokentype);
    setSignificantIssuerDN(significantissuerdn);
    setData(thedata);
    LOG.debug("Created Hard Token " + tokensn);
  }

  /** Empty. */
  public HardTokenData() { }

  /**
   * @return SN
   */
  // @Id @Column
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
   * @return time
   */
  // @Column
  public long getCtime() {
    return cTime;
  }

  /**
   * @param createTime time
   */
  public void setCtime(final long createTime) {
    this.cTime = createTime;
  }

  /**
   * @return time
   */
  // @Column
  public long getMtime() {
    return mTime;
  }

  /**
   * @param modifyTime time
   */
  public void setMtime(final long modifyTime) {
    this.mTime = modifyTime;
  }

  /**
   * @return type
   */
  // @Column
  public int getTokenType() {
    return tokenType;
  }

  /**
   * @param atokenType type
   */
  public void setTokenType(final int atokenType) {
    this.tokenType = atokenType;
  }

  /**
   * @return DN
   */
  // @Column
  public String getSignificantIssuerDN() {
    return significantIssuerDN;
  }

  /**
   * @param asignificantIssuerDN DN
   */
  public void setSignificantIssuerDN(final String asignificantIssuerDN) {
    this.significantIssuerDN = asignificantIssuerDN;
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
   * @param thedata Data
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

  /**
   * @return data
   */
  @Transient
  public LinkedHashMap<?, ?> getData() {
    final Serializable map = getDataUnsafe();
    if (map instanceof LinkedHashMap<?, ?>) {
      return (LinkedHashMap<?, ?>) map;
    } else {
      return new LinkedHashMap<>((Map<?, ?>) map);
    }
  }

  /**
   * @param thedata data
   */
  public void setData(final LinkedHashMap<?, ?> thedata) {
    setDataUnsafe(thedata);
  }

  /**
   * @return time
   */
  @Transient
  public Date getCreateTime() {
    return new Date(getCtime());
  }

  /**
   * @param createtime time
   */
  public void setCreateTime(final Date createtime) {
    setCtime(createtime.getTime());
  }

  /**
   * @return time
   */
  @Transient
  public Date getModifyTime() {
    return new Date(getCtime());
  }

  /**
   * @param modifytime time
   */
  public void setModifyTime(final Date modifytime) {
    setMtime(modifytime.getTime());
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
        .append(getTokenSN())
        .append(getUsername())
        .append(getCtime())
        .append(getMtime())
        .append(getTokenType())
        .append(getSignificantIssuerDN());
    LinkedHashMap<?, ?> thedata = getData();
    // We must have special handling here if the data is encrypted because the
    // byte[] is a binary byte array
    // in this case, when doing getData().toString in this case a reference to
    // the byte array is printed, and
    // this is different for every invocation so signature verification fail.
    final String dataStr;
    if (thedata.get(ENCRYPTEDDATA) != null) {
      byte[] encdata =
          (byte[])
              thedata.get(
                  org.ejbca.core.ejb.hardtoken.HardTokenData.ENCRYPTEDDATA);
      dataStr = new String(Base64.encode(encdata, false));
    } else {
      dataStr = getData().toString();
    }
    build.append(dataStr);
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
    return String.valueOf(getTokenSN());
  }

  //
  // End Database integrity protection methods
  //

  //
  // Search functions.
  //

  /**
   * @param entityManager EM
   * @param tokenSN SN
   * @return the found entity instance or null if the entity does not exist
   */
  public static HardTokenData findByTokenSN(
      final EntityManager entityManager, final String tokenSN) {
    return entityManager.find(HardTokenData.class, tokenSN);
  }

  /**
   * @param entityManager EM
   * @param username User
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<HardTokenData> findByUsername(
      final EntityManager entityManager, final String username) {
    Query query =
        entityManager.createQuery(
            "SELECT a FROM HardTokenData a WHERE a.username=:username");
    query.setParameter("username", username);
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @param searchPattern Pattern
   * @param maxResults Max results
   * @return return a List&lt;String&gt; of all usernames where the
   *     searchPattern matches the token serial number.
   */
  @SuppressWarnings("unchecked")
  public static List<String> findUsernamesByHardTokenSerialNumber(
      final EntityManager entityManager,
      final String searchPattern,
      final int maxResults) {
    Query query =
        entityManager.createNativeQuery(
            "SELECT DISTINCT a.username FROM HardTokenData a WHERE tokenSN"
                + " LIKE :search");
    // To use parameterized values in LIKE queries we must put the % in the
    // parameter
    final String parameter = "%" + searchPattern + "%";
    query.setParameter("search", parameter);
    query.setMaxResults(maxResults);
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<String> findAllTokenSN(final EntityManager entityManager) {
    return entityManager
        .createQuery("SELECT a.tokenSN FROM HardTokenData a")
        .getResultList();
  }
}
