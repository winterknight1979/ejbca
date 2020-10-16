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
  private String pk;
  private Date timeCreated;
  private Date lastUpdate;
  /** PublisherQueueData.STATUS_SUCCESS etc */
  private int publishStatus;

  private int tryCounter;
  /** PublisherQueueData.PUBLISH_TYPE_CERT etc */
  private int publishType;

  private String fingerprint;
  private int publisherId;
  private PublisherQueueVolatileInformation volatileData;

  // Public constants

  // Public methods.

  public PublisherQueueData(
      final String pk,
      final Date timeCreated,
      final Date lastUpdate,
      final int publishStatus,
      final int tryCounter,
      final int publishType,
      final String fingerprint,
      final int publisherId,
      final PublisherQueueVolatileInformation volatileData) {
    super();
    this.pk = pk;
    this.timeCreated = timeCreated;
    this.lastUpdate = lastUpdate;
    this.publishStatus = publishStatus;
    this.tryCounter = tryCounter;
    this.publishType = publishType;
    this.fingerprint = fingerprint;
    this.publisherId = publisherId;
    this.volatileData = volatileData;
  }

  public int getPublishType() {
    return publishType;
  }

  public void setPublishType(final int publishType) {
    this.publishType = publishType;
  }

  public String getPk() {
    return pk;
  }

  public void setPk(final String pk) {
    this.pk = pk;
  }

  public Date getTimeCreated() {
    return timeCreated;
  }

  public void setTimeCreated(final Date timeCreated) {
    this.timeCreated = timeCreated;
  }

  public Date getLastUpdate() {
    return lastUpdate;
  }

  public void setLastUpdate(final Date lastUpdate) {
    this.lastUpdate = lastUpdate;
  }

  public int getPublishStatus() {
    return publishStatus;
  }

  public void setPublishStatus(final int publishStatus) {
    this.publishStatus = publishStatus;
  }

  public int getTryCounter() {
    return tryCounter;
  }

  public void setTryCounter(final int tryCounter) {
    this.tryCounter = tryCounter;
  }

  public String getFingerprint() {
    return fingerprint;
  }

  public void setFingerprint(final String fingerprint) {
    this.fingerprint = fingerprint;
  }

  public int getPublisherId() {
    return publisherId;
  }

  public void setPublisherId(final int publisherId) {
    this.publisherId = publisherId;
  }

  public PublisherQueueVolatileInformation getVolatileData() {
    return volatileData;
  }

  public void setVolatileData(
      final PublisherQueueVolatileInformation volatileData) {
    this.volatileData = volatileData;
  }
}
