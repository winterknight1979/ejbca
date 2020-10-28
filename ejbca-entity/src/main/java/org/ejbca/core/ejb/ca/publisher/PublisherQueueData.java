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

import java.beans.XMLEncoder;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.GUIDGenerator;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.ValueExtractor;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Entity Bean representing publisher failure data. Data is stored here when
 * publishing to a publisher fails. Using this data publishing can be tried
 * again. This data bean should not duplicate data completely, but holds this:
 *
 * <p>- Information needed for scheduling of republishing, such as publish
 * dates, retry counter and last failure message. - Information which is
 * volatile on other places in the database, and we need to publish this data as
 * it was at the time of publishing. In this case it is UserData, which can
 * change because every user can have several certificates with different DN,
 * the password is re-set when a certificate is issued etc. - Foreign keys to
 * information which is not volatile. In this case this is keys to
 * CertificateData and CRLData. For CertificateData we always want to publish
 * the latest information, even if it changed since we failed to publish. This
 * is so there should be no chance that a revocation is overwritten with a good
 * status if the publish events would happen out of order.
 *
 * @version $Id: PublisherQueueData.java 34163 2020-01-02 15:00:17Z samuellb $
 */
@Entity
@Table(name = "PublisherQueueData")
public class PublisherQueueData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(PublisherQueueData.class);

  /** Param. */
  private String pk;
  /** Param. */
  private long timeCreated;
  /** Param. */
  private long lastUpdate;
  /** Param. */
  private int publishStatus;
  /** Param. */
  private int tryCounter;
  /** Param. */
  private int publishType;
  /** Param. */
  private String fingerprint;
  /** Param. */
  private int publisherId;
  /** Param. */
  private String volatileData;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * @param apublisherId ID
   * @param apublishType is one of PublisherConst.PUBLISH_TYPE_CERT or CRL
   * @param afingerprint FP
   * @param aqueueData Data
   * @param apublishStatus Status
   */
  public PublisherQueueData(
      final int apublisherId,
      final int apublishType,
      final String afingerprint,
      final PublisherQueueVolatileInformation aqueueData,
      final int apublishStatus) {
    String apk = GUIDGenerator.generateGUID(this);
    setPk(apk);
    setTimeCreated(System.currentTimeMillis());
    setLastUpdate(0);
    setPublishStatus(apublishStatus);
    setTryCounter(0);
    setPublishType(apublishType);
    setFingerprint(afingerprint);
    setPublisherId(apublisherId);
    setPublisherQueueVolatileData(aqueueData);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created Publisher queue data " + apk);
    }
  }

  /** Empty.
   */
  public PublisherQueueData() { }

  /**
   * @return key
   */
  // @Id @Column
  public String getPk() {
    return pk;
  }

  /**
   * @param apk key
   */
  public void setPk(final String apk) {
    this.pk = apk;
  }

  /**
   * @return time
   */
  // @Column
  public long getTimeCreated() {
    return timeCreated;
  }

  /**
   * @param atimeCreated time
   */
  public void setTimeCreated(final long atimeCreated) {
    this.timeCreated = atimeCreated;
  }

  /**
   * @return update
   */
  // @Column
  public long getLastUpdate() {
    return lastUpdate;
  }

  /**
   * @param alastUpdate update
   */
  public void setLastUpdate(final long alastUpdate) {
    this.lastUpdate = alastUpdate;
  }

  /**
   * PublishStatus is one of
   * org.ejbca.core.model.ca.publisher.PublisherConst.STATUS_PENDING, FAILED or
   * SUCCESS.
   *
   * @return Status
   */
  // @Column
  public int getPublishStatus() {
    return publishStatus;
  }

  /**
   * @param apublishStatus status
   */
  public void setPublishStatus(final int apublishStatus) {
    this.publishStatus = apublishStatus;
  }

  /**
   * @return count
   */
  // @Column
  public int getTryCounter() {
    return tryCounter;
  }

  /**
   * @param atryCounter count
   */
  public void setTryCounter(final int atryCounter) {
    this.tryCounter = atryCounter;
  }

  /**
   * PublishType is one of
   * org.ejbca.core.model.ca.publisher.PublisherConst.PUBLISH_TYPE_CERT or CRL.
   *
   * @return Type
   */
  // @Column
  public int getPublishType() {
    return publishType;
  }

  /**
   * @param apublishType type
   */
  public void setPublishType(final int apublishType) {
    this.publishType = apublishType;
  }

  /**
   * Foreign key to certificate of CRL.
   *
   * @return FP
   */
  // @Column
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @param afingerprint FP
   */
  public void setFingerprint(final String afingerprint) {
    this.fingerprint = afingerprint;
  }


  /**
   * @return ID
   */
  // @Column
  public int getPublisherId() {
    return publisherId;
  }

  /**
   * @param apublisherId ID
   */
  public void setPublisherId(final int apublisherId) {
    this.publisherId = apublisherId;
  }

  /**
   * @return data
   */
  // @Column @Lob
  public String getVolatileData() {
    return volatileData;
  }

  /**
   * @param thevolatileData data
   */
  public void setVolatileData(final String thevolatileData) {
    this.volatileData = thevolatileData;
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
   * Method that returns the PublisherQueueVolatileData data and updates it if
   * necessary.
   *
   * @return VolatileData is optional in publisher queue data
   */
  @Transient
  public PublisherQueueVolatileInformation getPublisherQueueVolatileData() {
    PublisherQueueVolatileInformation ret = null;
    String vd = getVolatileData();
    if ((vd != null) && (vd.length() > 0)) {
      final byte[] databytes = vd.getBytes(StandardCharsets.UTF_8);
      final HashMap<?, ?> h;
      try (SecureXMLDecoder decoder =
          new SecureXMLDecoder(new java.io.ByteArrayInputStream(databytes))) {
        h = (HashMap<?, ?>) decoder.readObject();
      } catch (IOException e) {
        final String msg =
            "Failed to parse PublisherQueueVolatileInformation map in"
                + " database: "
                + e.getMessage();
        if (LOG.isDebugEnabled()) {
          LOG.debug(msg + ". Data:\n" + vd);
        }
        throw new IllegalStateException(msg, e);
      }
      // Handle Base64 encoded string values
      HashMap<?, ?> data = new Base64GetHashMap(h);
      ret = new PublisherQueueVolatileInformation();
      ret.loadData(data);
      if (ret.isUpgraded()) {
        setPublisherQueueVolatileData(ret);
      }
    }
    return ret;
  }

  /**
   * Method that saves the PublisherQueueData data to database.
   *
   * @param qd is optional in publisher queue data
   */
  @SuppressWarnings("unchecked")
  public void setPublisherQueueVolatileData(
      final PublisherQueueVolatileInformation qd) {
    if (qd != null) {
      // We must base64 encode string for UTF safety
      HashMap<Object, Object> a = new Base64PutHashMap();
      a.putAll((HashMap<Object, Object>) qd.saveData());

      // typical size of XML is something like 250-400 chars
      final int siz = 400;
      java.io.ByteArrayOutputStream baos =
          new java.io.ByteArrayOutputStream(siz);
      try (XMLEncoder encoder = new XMLEncoder(baos)) {
        encoder.writeObject(a);
      }

      try {
        if (LOG.isDebugEnabled()) {
          LOG.debug("PublisherQueueVolatileData: \n" + baos.toString("UTF8"));
        }
        setVolatileData(baos.toString("UTF8"));
      } catch (UnsupportedEncodingException e) {
        throw new RuntimeException(e);
      }
    }
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
        .append(getPk())
        .append(getTimeCreated())
        .append(getLastUpdate())
        .append(getPublishStatus());
    build
        .append(getTryCounter())
        .append(getPublishType())
        .append(getFingerprint())
        .append(getPublisherId())
        .append(getVolatileData());
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
    return getPk();
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
  public static PublisherQueueData findByPk(
      final EntityManager entityManager, final String pk) {
    return entityManager.find(PublisherQueueData.class, pk);
  }

  /**
   * @param entityManager EM
   * @param fingerprint PK
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<PublisherQueueData> findDataByFingerprint(
      final EntityManager entityManager, final String fingerprint) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM PublisherQueueData a WHERE"
                + " a.fingerprint=:fingerprint");
    query.setParameter("fingerprint", fingerprint);
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @param publisherId ID
   * @param publishStatus Status
   * @param maxRows If set &gt; 0, limits the number of rows fetched.
   * @return return the query results as a List.
   */
  @SuppressWarnings("unchecked")
  public static List<PublisherQueueData> findDataByPublisherIdAndStatus(
      final EntityManager entityManager,
      final int publisherId,
      final int publishStatus,
      final int maxRows) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM PublisherQueueData a WHERE"
                + " a.publisherId=:publisherId AND"
                + " a.publishStatus=:publishStatus");
    query.setParameter("publisherId", publisherId);
    query.setParameter("publishStatus", publishStatus);
    if (maxRows > 0) {
      query.setMaxResults(maxRows);
    }
    return query.getResultList();
  }

  /**
   * @param entityManager EM
   * @param publisherId ID
   * @return return the count.
   */
  public static long findCountOfPendingEntriesForPublisher(
      final EntityManager entityManager, final int publisherId) {
    Query query =
        entityManager.createQuery(
            "SELECT COUNT(a) FROM PublisherQueueData a WHERE"
                + " a.publisherId=:publisherId AND publishStatus="
                + PublisherConst.STATUS_PENDING);
    query.setParameter("publisherId", publisherId);
    return ((Long) query.getSingleResult())
        .longValue(); // Always returns a result
  }

  /**
   * @param entityManager EM
   * @param publisherId ID
   * @param lowerBounds Bound
   * @param upperBounds Bound
   * @return the count of pending entries for a publisher in the specified
   *     intervals.
   */
  @SuppressWarnings("unchecked")
  public static List<Integer> findCountOfPendingEntriesForPublisher(
      final EntityManager entityManager,
      final int publisherId,
      final int[] lowerBounds,
      final int[] upperBounds) {
    final long msPerS = 1000L;
    if (lowerBounds.length == 0) {
      throw new IllegalArgumentException(
          "lowerBounds and upperBounds are mandatory parameters");
    }

    final StringBuilder sql = new StringBuilder();
    long now = System.currentTimeMillis();

    sql.append("select c from (");

    for (int i = 0; i < lowerBounds.length; i++) {
      sql.append(
          "SELECT "
              + i
              + " as ordering, COUNT(*) as c FROM PublisherQueueData where"
              + " publisherId=");
      sql.append(publisherId);
      sql.append(" AND publishStatus=");
      sql.append(PublisherConst.STATUS_PENDING);
      if (lowerBounds[i] > 0) {
        sql.append(" AND timeCreated < ");
        sql.append(now - msPerS * lowerBounds[i]);
      }
      if (upperBounds[i] > 0) {
        sql.append(" AND timeCreated > ");
        sql.append(now - msPerS * upperBounds[i]);
      }
      if (i < lowerBounds.length - 1) {
        sql.append(" UNION ALL ");
      }
    }
    sql.append(") tmp ORDER BY tmp.ordering");

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "findCountOfPendingEntriesForPublisher executing SQL: "
              + sql.toString());
    }
    final Query query = entityManager.createNativeQuery(sql.toString());
    List<?> resultList = query.getResultList();
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "findCountOfPendingEntriesForPublisher result: "
              + resultList.toString());
    }
    List<Integer> returnList;
    // Derby returns Integers, MySQL returns BigIntegers, Oracle returns
    // BigDecimal
    if (resultList.size() == 0) {
      returnList = new ArrayList<Integer>();
    } else if (resultList.get(0) instanceof Integer) {
      returnList =
          (List<Integer>)
              resultList; // This means we can return it in it's current format
    } else {
      returnList = new ArrayList<Integer>();
      for (Object o : resultList) {
        returnList.add(ValueExtractor.extractIntValue(o));
      }
    }
    return returnList;
  }
}
