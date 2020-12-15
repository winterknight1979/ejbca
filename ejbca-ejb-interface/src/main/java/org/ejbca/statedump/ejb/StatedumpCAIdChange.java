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
package org.ejbca.statedump.ejb;

/**
 * Represents a change of CA Subject DN (and CA Id also, which is computed from
 * the Subject DN).
 *
 * @version $Id: StatedumpCAIdChange.java 22675 2016-01-29 16:07:49Z samuellb $
 */
public final class StatedumpCAIdChange {

      /** Param. */
  private final int fromId;
  /** Param. */
  private final int toId;
  /** Param. */
  private final String toSubjectDN;

  /**
   * @param afromId ID
   * @param atoId ID
   * @param atoSubjectDN DN
   */
  public StatedumpCAIdChange(
      final int afromId, final int atoId, final String atoSubjectDN) {
    this.fromId = afromId;
    this.toId = atoId;
    this.toSubjectDN = atoSubjectDN;
  }

  /**
   * @return ID
   */
  public int getFromId() {
    return fromId;
  }

  /**
   * @return ID
   */
  public int getToId() {
    return toId;
  }

  /**
   * @return DN
   */
  public String getToSubjectDN() {
    return toSubjectDN;
  }
}
