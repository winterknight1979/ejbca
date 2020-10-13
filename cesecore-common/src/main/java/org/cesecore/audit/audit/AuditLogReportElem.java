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
package org.cesecore.audit.audit;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * A sub-element of a AuditLogValidationReport representing an error or warning.
 *
 * @version $Id: AuditLogReportElem.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public class AuditLogReportElem implements Serializable {

  private static final long serialVersionUID = -7018231147212983227L;

  /** First. */
  private Long first;
  /** Second. */
  private Long second;
  /** Reasons. */
  private final List<String> reasons = new ArrayList<String>();

  /** Constructor. */
  public AuditLogReportElem() { }

  /**
   * Constructor.
   *
   * @param firstElem First element
   * @param secondElem Second element
   * @param reasonsList Reasons
   */
  public AuditLogReportElem(
      final Long firstElem,
      final Long secondElem,
      final List<String> reasonsList) {
    this.first = firstElem;
    this.second = secondElem;
    this.reasons.addAll(reasonsList);
  }

  /**
   * Constructor.
   *
   * @param firstElem First element
   * @param secondElem Second element
   * @param reason Reason
   */
  public AuditLogReportElem(
      final Long firstElem, final Long secondElem, final String reason) {
    this.first = firstElem;
    this.second = secondElem;
    this.reasons.add(reason);
  }

  /**
   * Gets the first for this instance.
   *
   * @return The first.
   */
  public Long getFirst() {
    return this.first;
  }
  /**
   * Sets the first for this instance.
   *
   * @param newFirst The first.
   */
  public void setFirst(final Long newFirst) {
    this.first = newFirst;
  }
  /**
   * Gets the second for this instance.
   *
   * @return The second.
   */
  public Long getSecond() {
    return this.second;
  }
  /**
   * Sets the second for this instance.
   *
   * @param newSecond The second.
   */
  public void setSecond(final Long newSecond) {
    this.second = newSecond;
  }
  /**
   * Gets the reasons for this instance.
   *
   * @return The reasons.
   */
  public List<String> getReasons() {
    return this.reasons;
  }
  /**
   * Sets the reasons for this instance.
   *
   * @param reason The reasons.
   */
  public void setReason(final String reason) {
    this.reasons.add(reason);
  }
}
