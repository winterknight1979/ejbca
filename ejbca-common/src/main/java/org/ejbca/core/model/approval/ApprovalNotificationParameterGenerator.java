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
package org.ejbca.core.model.approval;

import org.ejbca.core.model.approval.profile.ApprovalPartitionWorkflowState;
import org.ejbca.util.NotificationParamGen;


/**
 * Parameters for notification of partition owners in the approval request work flow.
 * 
 * ${approvalRequest.ID}            The approval request identifier.
 * ${approvalRequest.STEP_ID}       The approval step that this notification concerns.
 * ${approvalRequest.PARTITION_ID}  The approval partition in the step that this notification concerns.
 * ${approvalRequest.PARTITION_NAME} The approval partition in the step that this notification concerns.
 * ${approvalRequest.TYPE}          The type of approval request.
 * ${approvalRequest.WORKFLOWSTATE} The work flow state from the perspective of the one(s) responsible for handling the partition.
 * ${approvalRequest.REQUESTOR}     The human readable version of the authentication token that was used to create the request.
 * ${approvalRequest.APPROVALADMIN} The human readable version of the authentication token that was used to last approved the request, if any.
 * 
 * @see ApprovalPartitionWorkflowState
 * @version $Id: ApprovalNotificationParameterGenerator.java 24431 2016-09-28 12:10:34Z anatom $
 */
public class ApprovalNotificationParameterGenerator extends NotificationParamGen {

    /**
     * 
     * @param approvalRequestID approval request ID, is the ID of the ApprovalData
     * @param approvalStepId
     * @param approvalPartitionId
     * @param approvalPartitionName
     * @param approvalType one of the ApprovalDataVO.APPROVALTYPENAMES
     * @param workflowState "APPROVAL_WFSTATE_" + approvalPartitionWorkflowState.name(), where approvalPartitionWorkflowState.name() typically is "approved", "rejected"
     * @param requestor AuthenticationToken.toString() of the admin who created the approval request
     * @param lastApprovedBy AuthenticationToken.toString() of the admin who last approved the request, or empty string/null if none
     */
    public ApprovalNotificationParameterGenerator(final int approvalRequestID, final int approvalStepId, final int approvalPartitionId,
            final String approvalPartitionName, final String approvalType, final String workflowState, final String requestor, final String lastApprovedBy) {
        paramPut("approvalRequest.ID", approvalRequestID);
        paramPut("approvalRequest.STEP_ID", approvalStepId);
        paramPut("approvalRequest.PARTITION_ID", approvalPartitionId);
        paramPut("approvalRequest.PARTITION_NAME", approvalPartitionName);
        paramPut("approvalRequest.TYPE", approvalType);
        paramPut("approvalRequest.WORKFLOWSTATE", workflowState);
        paramPut("approvalRequest.REQUESTOR", requestor);
        paramPut("approvalRequest.APPROVALADMIN", lastApprovedBy);
    }

}
