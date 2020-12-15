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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.List;
import org.ejbca.core.model.approval.profile.ApprovalPartition;

/**
 * Contains a list of partitions in a step that are visible to a given admin.
 * Could be removed as part of ECA-5294, since the filtering would be done on
 * the RA side.
 *
 * @version $Id: RaApprovalStepInfo.java 24113 2016-08-04 13:10:03Z samuellb $
 */
public final class RaApprovalStepInfo implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final int stepId;
  /** Param. */
  private final List<ApprovalPartition> partitions;

  /**
   * @param astepId ID
   * @param thepartitions Partitions
   */
  public RaApprovalStepInfo(
      final int astepId, final List<ApprovalPartition> thepartitions) {
    this.stepId = astepId;
    this.partitions = thepartitions;
  }

  /**
   * @return Step
   */
  public int getStepId() {
    return stepId;
  }

  /**
   * @return Partitions
   */
  public List<ApprovalPartition> getPartitions() {
    return partitions;
  }
}
