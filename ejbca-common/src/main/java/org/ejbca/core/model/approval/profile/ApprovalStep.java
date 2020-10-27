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
package org.ejbca.core.model.approval.profile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleInformation;
import org.cesecore.util.Base64;
import org.cesecore.util.LookAheadObjectInputStream;
import org.cesecore.util.ProfileID;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.DynamicUiPropertyCallback;
import org.cesecore.util.ui.DynamicUiPropertyValidator;
import org.cesecore.util.ui.MultiLineString;
import org.cesecore.util.ui.RadioButton;

/**
 * This class represents an approval step, to sum of which is a collective
 * series of events, in serial order, which must occur for an approval to pass.
 * Once the final step passes, the approval automatically passes.
 *
 * <p>Steps are stored in the ApprovalProfile without order, but instead track
 * their own order in the form of a doubly linked list.
 *
 * @version $Id: ApprovalStep.java 34227 2020-01-09 14:20:59Z henriks $
 */
@SuppressWarnings("deprecation")
public class ApprovalStep implements Serializable {

  private static final long serialVersionUID = 1L;
  /** ID. */
  private final int id;
  /** Step. */
  private Integer nextStep = null;
  /** Step. */
  private Integer previousStep = null;

  /**
   * Partotions.
   */
  private final LinkedHashMap<Integer, ApprovalPartition> partitions;

  /**
   * @param anid ID
   */
  public ApprovalStep(final int anid) {
    this.id = anid;
    // Use LinkedHashMap to keep insertion order.
    partitions = new LinkedHashMap<>();
  }

  /**
   * Copy constructor for ApprovalStep objects.
   *
   * @param original the step to copy
   */
  public ApprovalStep(final ApprovalStep original) {
    this.id = original.getStepIdentifier();
    this.nextStep = original.getNextStep();
    this.previousStep = original.getPreviousStep();
    // Use LinkedHashMap to keep insertion order.
    partitions = new LinkedHashMap<>();
    for (ApprovalPartition partition : original.getPartitions().values()) {
      partitions.put(partition.getPartitionIdentifier(), partition);
    }
  }

  /**
   * Create an approval step from a base64 encoded string representing a
   * serialized {@link ApprovalStep}.
   *
   * @param encodedStep a serialized approval step encoded as a string.
   */
  public ApprovalStep(final String encodedStep) {
    final byte[] bytes = Base64.decode(encodedStep.getBytes());
    try (LookAheadObjectInputStream ois =
        new LookAheadObjectInputStream(new ByteArrayInputStream(bytes))) {
      ois.setEnabledMaxObjects(false);
      ois.setAcceptedClasses(
          Arrays.asList(
              ApprovalStep.class,
              ApprovalPartition.class,
              LinkedHashMap.class,
              HashMap.class,
              DynamicUiProperty.class,
              DynamicUiPropertyCallback.class,
              Enum.class,
              ArrayList.class,
              DynamicUiPropertyValidator.class,
              RoleInformation.class,
              HashSet.class,
              AccessUserAspectData.class,
              AccessMatchType.class,
              RoleData.class,
              RadioButton.class,
              MultiLineString.class));
      ois.setEnabledInterfaceImplementations(true, "org.cesecore.util.ui");
      final ApprovalStep step = (ApprovalStep) ois.readObject();
      this.id = step.getStepIdentifier();
      this.nextStep = step.getNextStep();
      this.previousStep = step.getPreviousStep();
      this.partitions = step.getPartitions();
    } catch (IOException | ClassNotFoundException e) {
      throw new IllegalArgumentException(
          "Could not decode encoded ApprovalStep", e);
    }
  }

  /**
   * @return Encoded
   */
  public String getEncoded() {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      final ObjectOutputStream oos = new ObjectOutputStream(baos);
      oos.writeObject(this);
      oos.close();
    } catch (IOException e) {
      throw new IllegalStateException("Could not encode ApprovalStep", e);
    }
    byte[] byteArray = baos.toByteArray();
    return new String(Base64.encode(byteArray, false));
  }

  /** @return the identifier of this step. */
  public int getStepIdentifier() {
    return id;
  }

  /**Partitions.
   * @return Partitions
   */
  public LinkedHashMap<Integer, ApprovalPartition> getPartitions() {
    return partitions;
  }

  /**
   * @param partitionIdentifier the identifier of the partition in question
   * @return the sought partition, or null if no such partitions exists
   */
  public ApprovalPartition getPartition(final int partitionIdentifier) {
    return partitions.get(partitionIdentifier);
  }

  /**
   * @return the next step after this one. May be null if this is the last step.
   */
  public Integer getNextStep() {
    return nextStep;
  }

  /**
   * @param theNextStep Step
   */
  public void setNextStep(final Integer theNextStep) {
    this.nextStep = theNextStep;
  }

  /**
   * @return Step
   */
  public Integer getPreviousStep() {
    return previousStep;
  }

  /**
   * @param thePreviousStep Step
   */
  public void setPreviousStep(final Integer thePreviousStep) {
    this.previousStep = thePreviousStep;
  }

  /**
   * Sets a property to a particular partition. If that partition does not
   * exist, it's created.
   *
   * @param partitionId the id of the partition
   * @param property the property to set
   */
  public void setPropertyToPartition(
      final Integer partitionId,
      final DynamicUiProperty<? extends Serializable> property) {
    if (!partitions.containsKey(partitionId)) {
      partitions.put(partitionId, new ApprovalPartition(partitionId));
    }
    partitions.get(partitionId).addProperty(property);
  }

  /**
   * Removes the property from the given partition.
   *
   * @param partitionId the identifier of the partition
   * @param propertyName the name of the property
   */
  public void removePropertyFromPartition(
      final int partitionId, final String propertyName) {
    ApprovalPartition approvalPartition = partitions.get(partitionId);
    if (approvalPartition != null) {
      approvalPartition.removeProperty(propertyName);
    }
  }

  /**
   * @return Partition
   */
  public ApprovalPartition addPartition() {
    Integer identifier;
    do {
      identifier = ProfileID.getRandomIdNumber();
    } while (partitions.containsKey(identifier));
    ApprovalPartition newPartition = new ApprovalPartition(identifier);
    partitions.put(identifier, newPartition);
    return newPartition;
  }

  /**
   * Adds a partition. This method is package specific to avoid outside use.
   * Using this method directly will not lead to values in this step being
   * serialized.
   *
   * @param partition a partition
   */
  void addPartition(final ApprovalPartition partition) {
    partitions.put(partition.getPartitionIdentifier(), partition);
  }

  /**
   * This method is package specific to avoid outside use. Using this method
   * directly will not lead to values in this step being serialized.
   *
   * @param partitionIdentifier the ID of a partition
   */
  void removePartition(final int partitionIdentifier) {
    partitions.remove(partitionIdentifier);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + id;
    return result;
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    ApprovalStep other = (ApprovalStep) obj;
    if (id != other.id) {
      return false;
    }
    return true;
  }

  /**
   * Get a list of all partitions which must be approved before the step passes.
   *
   * @return a list of all partitions in this step
   */
  public List<ApprovalPartition> getPartitionList() {
    return new ArrayList<ApprovalPartition>(partitions.values());
  }
}
