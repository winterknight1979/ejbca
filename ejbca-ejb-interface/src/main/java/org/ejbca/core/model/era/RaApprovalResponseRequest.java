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
import org.ejbca.core.model.approval.ApprovalRequest;

/**
 * Used for approving requests from RaManageRequestBean.
 *
 * @version $Id: RaApprovalResponseRequest.java 24256 2016-08-31 07:00:25Z
 *     samuellb $
 */
public class RaApprovalResponseRequest implements Serializable {

  public enum Action {
      /** Const. */
    SAVE,
      /** Const. */
    APPROVE,
      /** Const. */
    REJECT;
  }

  private static final long serialVersionUID = 1L;
  /** id of approval. */
  private final int id;

  /** Param. */
  private final int stepIdentifier;
  /** Param. */
  private final int partitionIdentifier;
  /** Param. */
  private final ApprovalRequest approvalRequest;
  /** Param. */
  private final String comment;
  /** Param. */
  private final Action action;

  /**
   * @param anid ID
   * @param astepIdentifier Step
   * @param apartitionIdentifier Partition
   * @param anapprovalRequest Request
   * @param acomment Comment
   * @param anaction Action
   */
  public RaApprovalResponseRequest(
      final int anid,
      final int astepIdentifier,
      final int apartitionIdentifier,
      final ApprovalRequest anapprovalRequest,
      final String acomment,
      final Action anaction) {
    this.id = anid;
    this.stepIdentifier = astepIdentifier;
    this.partitionIdentifier = apartitionIdentifier;
    this.approvalRequest = anapprovalRequest;
    this.comment = acomment;
    this.action = anaction;
  }

  /**
   * @return ID
   */
  public int getId() {
    return id;
  }

  /**
   * @return Step
   */
  public int getStepIdentifier() {
    return stepIdentifier;
  }

  /**
   * @return Request
   */
  public ApprovalRequest getApprovalRequest() {
    return approvalRequest;
  }

  /**
   * @return Comment
   */
  public String getComment() {
    return comment;
  }

  /**
   * @return Action
   */
  public Action getAction() {
    return action;
  }

  /**
   * @return ID
   */
  public int getPartitionIdentifier() {
    return partitionIdentifier;
  }
}
