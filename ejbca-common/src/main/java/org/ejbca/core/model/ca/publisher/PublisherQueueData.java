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

package org.ejbca.core.model.ca.publisher;

import java.io.Serializable;
import java.util.Date;

/**
 * Value object holding the data contained in a PublisherQueueData record in the
 * database.
 *
 * @version $Id: PublisherQueueData.java 22117 2015-10-29 10:53:42Z mikekushner
 *     $
 */
public class PublisherQueueData implements Serializable {

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = 101L;

  // private fields.
  /** Key. */
  private String pk;
  /** Time. */
  private Date timeCreated;
  /** Date. */
  private Date lastUpdate;
  /** PublisherQueueData.STATUS_SUCCESS etc. */
  private int publishStatus;
  /** Count. */
  private int tryCounter;
  /** PublisherQueueData.PUBLISH_TYPE_CERT etc. */
  private int publishType;

  /** FP. */
  private String fingerprint;
  /** ID. */
  private int publisherId;
  /** Data. */
  private PublisherQueueVolatileInformation volatileData;

  // Public constants

  // Public methods.

  /**
   * @param aPk PK
   * @param theTimeCreated Time
   * @param theLastUpdate Date
   * @param aPublishStatus Status
   * @param theTryCounter Count
   * @param aPublishType Type
   * @param aFingerprint FP
   * @param aPublisherId ID
   * @param theVolatileData Data
   */
  public PublisherQueueData(
      final String aPk,
      final Date theTimeCreated,
      final Date theLastUpdate,
      final int aPublishStatus,
      final int theTryCounter,
      final int aPublishType,
      final String aFingerprint,
      final int aPublisherId,
      final PublisherQueueVolatileInformation theVolatileData) {
    super();
    this.pk = aPk;
    this.timeCreated = theTimeCreated;
    this.lastUpdate = theLastUpdate;
    this.publishStatus = aPublishStatus;
    this.tryCounter = theTryCounter;
    this.publishType = aPublishType;
    this.fingerprint = aFingerprint;
    this.publisherId = aPublisherId;
    this.volatileData = theVolatileData;
  }

  /**
   * @return type
   */
  public int getPublishType() {
    return publishType;
  }

  /**
   * @param aPublishType type
   */
  public void setPublishType(final int aPublishType) {
    this.publishType = aPublishType;
  }

  /**
   * @return key
   */
  public String getPk() {
    return pk;
  }

  /**
   * @param aPk key
   */
  public void setPk(final String aPk) {
    this.pk = aPk;
  }

  /**
   * @return time
   */
  public Date getTimeCreated() {
    return timeCreated;
  }

  /**
   * @param theTimeCreated time
   */
  public void setTimeCreated(final Date theTimeCreated) {
    this.timeCreated = theTimeCreated;
  }

  /**
   * @return date
   */
  public Date getLastUpdate() {
    return lastUpdate;
  }

  /**
   * @param theLastUpdate date
   */
  public void setLastUpdate(final Date theLastUpdate) {
    this.lastUpdate = theLastUpdate;
  }

  /**
   * @return status
   */
  public int getPublishStatus() {
    return publishStatus;
  }

  /**
   * @param aPublishStatus Status
   */
  public void setPublishStatus(final int aPublishStatus) {
    this.publishStatus = aPublishStatus;
  }

  /**
   * @return count
   */
  public int getTryCounter() {
    return tryCounter;
  }

  /**
   * @param theTryCounter count
   */
  public void setTryCounter(final int theTryCounter) {
    this.tryCounter = theTryCounter;
  }

  /**
   * @return FP
   */
  public String getFingerprint() {
    return fingerprint;
  }

  /**
   * @param aFingerprint FP
   */
  public void setFingerprint(final String aFingerprint) {
    this.fingerprint = aFingerprint;
  }

  /**
   * @return ID
   */
  public int getPublisherId() {
    return publisherId;
  }

  /**
   * @param aPublisherId ID
   */
  public void setPublisherId(final int aPublisherId) {
    this.publisherId = aPublisherId;
  }

  /**
   * @return data
   */
  public PublisherQueueVolatileInformation getVolatileData() {
    return volatileData;
  }

  /**
   * @param theVolatileData data
   */
  public void setVolatileData(
      final PublisherQueueVolatileInformation theVolatileData) {
    this.volatileData = theVolatileData;
  }
}
