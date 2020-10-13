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
package org.cesecore.time;

import java.io.Serializable;
import java.util.Date;

/**
 * This class encapsulates a Date object that represents a trusted time. It also
 * provides information related to thhe trusted time source: accuracy and
 * stratum
 *
 * @version $Id: TrustedTime.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public class TrustedTime implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Delta. */
  private static final Integer DELTA = 1;
  /** Source. */
  private String source;
  /** Accuracy. */
  private Double accuracy;
  /** Stratum. */
  private Integer stratum;
  /** Last update. */
  private Long previousUpdate; // seconds
  /** Nest update. */
  private Long nextUpdate; // seconds
  /** Sync. */
  private boolean sync = false;

  /** Default constructor. */
  public TrustedTime() { }

  /**
   * @return stratum
   */
  public Integer getStratum() {
    return stratum;
  }

  /**
   * @param aStratum stratum
   */
  public void setStratum(final Integer aStratum) {
    this.stratum = aStratum;
  }

  /**
   * @return last update
   */
  public Long getPreviousUpdate() {
    return this.previousUpdate;
  }

  /**
   * @return Nest update
   */
  public Long getNextUpdate() {
    return this.nextUpdate;
  }

  /**
   * @param when When
   * @param poll Poll
   */
  public void setNextUpdate(final Integer when, final Integer poll) {
    final long msPerSec = 1000L;
    Long lnextUpdate = Long.valueOf(((poll - when) + DELTA) * msPerSec);
    if (lnextUpdate.longValue() <= 0) {
      lnextUpdate = Long.valueOf(1);
    }

    if (this.nextUpdate != null) {
      this.previousUpdate = this.nextUpdate;
    }

    this.nextUpdate = lnextUpdate;
  }

  /**
   * @return sync
   */
  public boolean isSync() {
    return this.sync;
  }

  /**
   * @param aSync sync
   */
  public void setSync(final boolean aSync) {
    this.sync = aSync;
  }

  /**
   * @return time
   */
  public Date getTime() {
    return new Date();
  }

  /**
   * @return source
   */
  public String getSource() {
    return this.source;
  }

  /**
   * @param aSource source
   */
  public void setSource(final String aSource) {
    this.source = aSource;
  }

  /**
   * @return Accuracy
   */
  public Double getAccuracy() {
    return accuracy;
  }

  /**
   * @param anAccuracy Accuracy
   */
  public void setAccuracy(final Double anAccuracy) {
    this.accuracy = anAccuracy;
  }

  /**
   * @param anAccuracy accuracy
   */
  public TrustedTime(final Double anAccuracy) {
    this.accuracy = anAccuracy;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder();
    sb.append(this.accuracy)
        .append(";")
        .append(this.stratum)
        .append(";")
        .append(this.previousUpdate)
        .append(";")
        .append(this.nextUpdate)
        .append(";")
        .append(this.sync)
        .append(this.source);
    return sb.toString();
  }
}
