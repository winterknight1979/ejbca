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
package org.ejbca.core.ejb;

import java.io.Serializable;

/**
 * Aggregated statistics about an EJB method invocation.
 *
 * @version $Id: ProfilingStat.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class ProfilingStat implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Name. */
  private final String fullmethodName;
  /** Durations. */
  private final long duration;
  /** Invoke. */
  private final long invocations;
  /** Average. */
  private final long average;

  /**
   * @param afullmethodName Name
   * @param aduration duration
   * @param ainvocations invoke
   */
  public ProfilingStat(
      final String afullmethodName,
      final long aduration,
      final long ainvocations) {
    this.fullmethodName = afullmethodName;
    this.duration = aduration;
    this.invocations = ainvocations;
    this.average = aduration / ainvocations;
  }

  /**
   * @return Name
   */
  public String getFullmethodName() {
    return fullmethodName;
  }

  /**
   * @return us
   */
  public long getDurationMicroSeconds() {
    return duration;
  }

  /**
   * @return ms
   */
  public long getDurationMilliSeconds() {
    return duration / msPerS;
  }

  /**
   * @return invocations.
   */
  public long getInvocations() {
    return invocations;
  }

  /**
   * @return us
   */
  public long getAverageMicroSeconds() {
    return average;
  }

  /**
   * @return MS
   */
  public long getAverageMilliSeconds() {
    return average / msPerS;
  }

  /** Mils. */
  private final int msPerS = 1000;
}
