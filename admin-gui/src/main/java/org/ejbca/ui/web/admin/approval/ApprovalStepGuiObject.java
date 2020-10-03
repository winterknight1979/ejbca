/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;

/**
 * A display POJO for approval sequences.
 * 
 * @version $Id: ApprovalStepGuiObject.java 27768 2018-01-08 12:48:47Z mikekushner $
 *
 */
public class ApprovalStepGuiObject {
    private final Integer identifier;
    private final int stepNumber;
    private final List<ApprovalPartitionProfileGuiObject> partitionGuiObjects;
    private final Integer nextStep;
    private final Integer previousStep;

    /**
     * 
     * @param approvalStep the approval step we want to display
     * @param approvalProfileIdentifier the identifier for the approval profile type, which will be used for localization further down the line
     * @param ordinal the ordinal of the approval step, i.e. the list number
     * @param partitionProperties a Map between partition identifiers and lists of DynamicUiProperties, i.e the values to be displayed. Is extracted out in the MBean 
     *          in order to be able to fill certain placeholders with values from the database. 
     */
    public ApprovalStepGuiObject(ApprovalStep approvalStep, String approvalProfileIdentifier, int ordinal,
            Map<Integer, List<DynamicUiProperty<? extends Serializable>>> partitionProperties) {
        this.identifier = approvalStep.getStepIdentifier();
        this.stepNumber = ordinal;
        this.partitionGuiObjects = new ArrayList<>();
        for (Integer partitionId : partitionProperties.keySet()) {
            String partitionName = "";
            DynamicUiProperty<? extends Serializable> nameProperty = approvalStep.getPartition(partitionId).getProperty(PartitionedApprovalProfile.PROPERTY_NAME);
            if(nameProperty != null) {
                partitionName = nameProperty.getValueAsString();
            }
            partitionGuiObjects.add(new ApprovalPartitionProfileGuiObject(approvalProfileIdentifier, partitionId, partitionName, partitionProperties.get(partitionId)));
        }
        this.nextStep = approvalStep.getNextStep();
        this.previousStep = approvalStep.getPreviousStep();
    }

    public Integer getIdentifier() {
        return identifier;
    }

    /**
     * @return the ordinal of this sequence
     */
    public int getStepNumber() {
        return stepNumber;
    }
    
    public List<ApprovalPartitionProfileGuiObject> getPartitionGuiObjects() {
        return partitionGuiObjects;
    }
    
    public boolean isFinalStep() {
        return nextStep == null;
    }
    
    public Integer getNextStep() {
        return nextStep;
    }
    
    public Integer getPreviousStep() {
        return previousStep;
    }
    
    public int getNumberOfPartitions() {
        return partitionGuiObjects.size();
    }
    
}
