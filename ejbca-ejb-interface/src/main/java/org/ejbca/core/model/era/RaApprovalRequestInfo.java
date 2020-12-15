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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.TimeAndAdmin;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Information for an approval request, as seen by an admin.
 *
 * @version $Id: RaApprovalRequestInfo.java 27821 2018-01-10 09:29:00Z henriks $
 */
public class RaApprovalRequestInfo implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(RaApprovalRequestInfo.class);

  // Request information from ApprovalDataVO
  /** Param. */
  private final int id;
  /** Param. */
  private final String
      caName; // to avoid unnecessary lookups. only the id is present in
              // ApprovalDataVO
  /** Param. */
  private final String requesterSubjectDN;
  /** Param. */
  private final int status;
  /** Param. */
  private final ApprovalDataVO approvalData;
  /** Param. */
  private final ApprovalProfile approvalProfile;
  /** Param. */
  private final long maxExtensionTime;
  /** Param. */
  private final String endEntityProfileName;
  /** Param. */
  private final EndEntityProfile endEntityProfile;
  /** Param. */
  private final String certificateProfileName;

  /** Request data, as text. Not editable .*/
  private final List<ApprovalDataText> requestData;
  /** Editable request data for end entity requests. */
  private final RaEditableRequestData editableData;

  /** Param. */
  private final boolean requestedByMe;
  /** Param. */
  private final boolean lastEditedByMe;
  /** Param. */
  private boolean approvedByMe;
  /** Param. */
  private final boolean editable;
  /** Param. */
  private boolean isVisibleByMe;
  /** Param. */
  private final List<TimeAndAdmin> editedByAdmins;

  // Current approval step
  /** Param. */
  private ApprovalStep nextApprovalStep;
  /** Param. */
  private ApprovalPartition nextApprovalStepPartition;
  /** Param. */
  private int currentStepOrdinal;
  /** Param. */
  private final Collection<String> nextStepAllowedRoles;

  // Previous approval steps that are visible to the admin
  /** Param. */
  private final List<RaApprovalStepInfo> previousApprovalSteps;

  /** Param. */
  private final Map<Integer, Integer> stepToOrdinalMap;

  private static class StepPartitionId {
      /** Param. */
    private final int stepId;
    /** Param. */
    private final int partitionId;

    /**
     * @param astepId Step
     * @param apartitionId Partition
     */
    StepPartitionId(final int astepId, final int apartitionId) {
      this.stepId = astepId;
      this.partitionId = apartitionId;
    }

    @Override
    public boolean equals(final Object other) {
      if (other instanceof StepPartitionId) {
        final StepPartitionId o = (StepPartitionId) other;
        return o.stepId == stepId && o.partitionId == partitionId;
      }
      return false;
    }

    @Override
    public int hashCode() {
      return stepId ^ (partitionId << 16);
    }
  }

  /**
   * @param anauthenticationToken Token
   * @param acaName Name
   * @param anendEntityProfileName Profile
   * @param anendEntityProfile Profile
   * @param acertificateProfileName Name
   * @param anapproval Approval
   * @param therequestData Data
   * @param theeditableData Data
   */
  public RaApprovalRequestInfo(
      final AuthenticationToken anauthenticationToken,
      final String acaName,
      final String anendEntityProfileName,
      final EndEntityProfile anendEntityProfile,
      final String acertificateProfileName,
      final ApprovalDataVO anapproval,
      final List<ApprovalDataText> therequestData,
      final RaEditableRequestData theeditableData) {
    id = anapproval.getId();
    this.caName = acaName;
    final Certificate requesterCert =
        anapproval.getApprovalRequest().getRequestAdminCert();
    requesterSubjectDN =
        requesterCert != null ? CertTools.getSubjectDN(requesterCert) : null;
    status = anapproval.getStatus();
    this.approvalData = anapproval;
    this.requestData = therequestData;
    this.endEntityProfile = anendEntityProfile;
    this.endEntityProfileName = anendEntityProfileName;
    this.certificateProfileName = acertificateProfileName;
    this.editableData = theeditableData;
    this.approvalProfile = anapproval.getApprovalProfile();
    this.maxExtensionTime = anapproval.getApprovalProfile()
            .getMaxExtensionTime();

    final AuthenticationToken requestAdmin =
        anapproval.getApprovalRequest().getRequestAdmin();
    requestedByMe =
        requestAdmin != null && requestAdmin.equals(anauthenticationToken);
    lastEditedByMe =
        anapproval.getApprovalRequest().isEditedByMe(anauthenticationToken);
    editedByAdmins = anapproval.getApprovalRequest().getEditedByAdmins();

    // Check which partitions have been approved, and if approved by self
    approvedByMe = false;
    final Set<StepPartitionId> approvedSet = new HashSet<>();
    final Set<StepPartitionId> approvedByMeSet = new HashSet<>();
    for (final Approval prevApproval : anapproval.getApprovals()) {
      final StepPartitionId spId =
          new StepPartitionId(
              prevApproval.getStepId(), prevApproval.getPartitionId());
      approvedSet.add(spId);
      if (anauthenticationToken.equals(prevApproval.getAdmin())) {
        approvedByMe = true;
        approvedByMeSet.add(spId);
      }
    }

    // Can only edit approvals in waiting state that haven't been approved by
    // any admin yet
    editable =
        (status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL
            && anapproval.getApprovals().isEmpty());

    // Next steps
    final ApprovalStep nextStep;
    try {
      nextStep = approvalProfile.getStepBeingEvaluated(
              anapproval.getApprovals());
    } catch (AuthenticationFailedException e) {
      throw new IllegalStateException(e);
    }

    nextApprovalStep = null;
    nextApprovalStepPartition = null;
    if (nextStep != null
        && status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL
        && (!lastEditedByMe
            || anapproval.getApprovalProfile().getAllowSelfEdit())) {
      final Map<Integer, ApprovalPartition> partitions =
          nextStep.getPartitions();
      for (ApprovalPartition partition : partitions.values()) {
        try {
          if (approvalProfile.canApprovePartition(
              anauthenticationToken, partition)) {
            nextApprovalStep = nextStep;
            nextApprovalStepPartition = partition;
            break;
          } else if (approvalProfile.canViewPartition(
              anauthenticationToken, partition)) {
            isVisibleByMe = true;
          }
        } catch (AuthenticationFailedException e) {
          // If this admin cannot approve this partition, check the next
          // partition
        }
      }
    }
    try {
      currentStepOrdinal =
          approvalProfile.getOrdinalOfStepBeingEvaluated(
              anapproval.getApprovals());
    } catch (AuthenticationFailedException e) {
      // Should never happen
      LOG.debug("Exception occurred while getting current step", e);
      currentStepOrdinal = -1;
    }

    // Determine which admins can approve the next step (ECA-5123)
    nextStepAllowedRoles = new HashSet<>();
    if (nextStep != null) {
      for (final ApprovalPartition partition
          : nextStep.getPartitions().values()) {
        nextStepAllowedRoles.addAll(
            approvalProfile.getAllowedRoleNames(partition));
      }
    }

    // Build a list of all approval steps that we are allowed to see (used in
    // the RA GUI to display the previous steps/partitions)
    stepToOrdinalMap = new HashMap<>();
    previousApprovalSteps = new ArrayList<>();
    ApprovalStep step = approvalProfile.getFirstStep();
    int stepOrdinal = 1;
    while (step != null) {
      final int stepId = step.getStepIdentifier();
      stepToOrdinalMap.put(stepId, stepOrdinal);

      final List<ApprovalPartition> partitions = new ArrayList<>();
      for (final ApprovalPartition partition : step.getPartitions().values()) {
        try {
          final StepPartitionId spId =
              new StepPartitionId(stepId, partition.getPartitionIdentifier());
          if (approvedByMeSet.contains(spId)
              || (approvalProfile.canViewPartition(
                      anauthenticationToken, partition)
                  && approvedSet.contains(spId))) {
            partitions.add(partition);
          }
        } catch (AuthenticationFailedException e) {
          // Just ignore
        }
      }
      if (!partitions.isEmpty()) {
        previousApprovalSteps.add(new RaApprovalStepInfo(stepId, partitions));
      }

      final Integer nextStepId = step.getNextStep();
      if (nextStepId == null) {
        break;
      }
      step = approvalProfile.getStep(nextStepId);
      stepOrdinal++;
    }
  }

  /**
   * @return ID
   */
  public int getId() {
    return id;
  }

  /**
   * @return CA
   */
  public String getCaName() {
    return caName;
  }

  /**
   * @return Status
   */
  public int getStatus() {
    return status;
  }

  /**
   * @return DN
   */
  public String getRequesterSubjectDN() {
    return requesterSubjectDN;
  }

  /**
   * @return Data
   */
  public ApprovalDataVO getApprovalData() {
    return approvalData;
  }

  /**
   * @return Request
   */
  public ApprovalRequest getApprovalRequest() {
    return approvalData.getApprovalRequest();
  }

  /**
   * @return Profile
   */
  public EndEntityProfile getEndEntityProfile() {
    return endEntityProfile;
  }

  /**
   * @return Name
   */
  public String getEndEntityProfileName() {
    return endEntityProfileName;
  }

  /**
   * @return Name
   */
  public String getCertificateProfileName() {
    return certificateProfileName;
  }

  /**
   * @return Data
   */
  public List<ApprovalDataText> getRequestData() {
    return requestData;
  }

  /**
   * @return Data
   */
  public RaEditableRequestData getEditableData() {
    return editableData.clone();
  }

  /**
   * @return Profile
   */
  public ApprovalProfile getApprovalProfile() {
    return approvalProfile;
  }

  /**
   * @return long
   * @since EJBCA 6.7.0. If the response comes from an earlier version, it will
   *     return 0 (=extension of requests not allowed)
   */
  public long getMaxExtensionTime() {
    return maxExtensionTime;
  }

  /**
   * @return Step
   */
  public ApprovalStep getNextApprovalStep() {
    return nextApprovalStep;
  }

  /**
   * @return Partition
   */
  public ApprovalPartition getNextApprovalStepPartition() {
    return nextApprovalStepPartition;
  }

  /**
   * @return Steps
   */
  public List<RaApprovalStepInfo> getPreviousApprovalSteps() {
    return previousApprovalSteps;
  }

  /**
   * @return Map
   */
  public Map<Integer, Integer> getStepIdToOrdinalMap() {
    return stepToOrdinalMap;
  }

  /**
   * @return Count
   */
  public int getStepCount() {
    return stepToOrdinalMap.size();
  }

  /**
   * @return Step
   */
  public int getCurrentStepOrdinal() {
    return currentStepOrdinal;
  }

  /**
   * @return Roles
   */
  public Collection<String> getNextStepAllowedRoles() {
    return nextStepAllowedRoles;
  }

  /**
   * @return Bool
   */
  public boolean isVisibleToMe() {
    return isVisibleByMe;
  }

  /**
   * Is waiting for the given admin to do something.
   *
   * @param admin admin
   * @return fail
   */
  public boolean isWaitingForMe(final AuthenticationToken admin) {
    if (requestedByMe) {
      // There are approval types that do not get executed automatically on
      // approval.
      // These go into APPROVED (instead of EXECUTED) state and need to executed
      // again by the requester
      return status == ApprovalDataVO.STATUS_APPROVED;
    } else if (approvedByMe) {
      return false; // Already approved by me, so not "waiting for me"
    } else {
      if (status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
        try {
          if (approvalProfile.canApprovePartition(
              admin, nextApprovalStepPartition)) {
            return true;
          }
        } catch (AuthenticationFailedException e) {
        }
      }
    }
    return false;
  }

  /**
   * Is waiting for someone else to do something.
   *
   * @param admin admin
   * @return fail
   */
  public boolean isPending(final AuthenticationToken admin) {
    return !isWaitingForMe(admin) && !isProcessed();
  }

  /**
   * @param now Date
   * @return Bool
   */
  public boolean isExpired(final Date now) {
    return approvalData.getExpireDate().before(now) && !isProcessed();
  }

  /**
   * @return Bool
   */
  public boolean isProcessed() {
    return status != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL
        && status != ApprovalDataVO.STATUS_APPROVED
        && status != ApprovalDataVO.STATUS_EXPIRED
        && status != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
  }

  /**
   * @param now Date
   * @return Bool
   */
  public boolean isWaitingForFirstApproval(final Date now) {
    return !isProcessed()
        && !isExpired(now)
        && approvalData.getApprovals().isEmpty();
  }

  /**
   * @param now Date
   * @return Bool
   */
  public boolean isInProgress(final Date now) {
    return !isProcessed()
        && !isExpired(now)
        && !approvalData.getApprovals().isEmpty();
  }

  /**
   * @return bool
   */
  public boolean isRequestedByMe() {
    return requestedByMe;
  }

  /**
   * @return bool
   */
  public boolean isApprovedByMe() {
    return approvedByMe;
  }

  /**
   * @return bool
   */
  public boolean isEditedByMe() {
    return lastEditedByMe;
  }

  /**
   * @return Bool
   */
  public boolean isEditable() {
    return editable;
  }

  /**
   * @return Admins
   */
  public List<TimeAndAdmin> getEditedByAdmin() {
    return editedByAdmins;
  }
}
