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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Reads in the implementations of the ApprovalProfile interface. Mainly used by
 * GUI and CLI to list the available types of approvals.
 *
 * @version $Id: ApprovalProfilesFactory.java 24946 2016-12-21 15:17:53Z
 *     mikekushner $
 */
public enum ApprovalProfilesFactory {
  /** Singleton. */
    INSTANCE;

    /**
     * Map. */
  private final Map<String, ApprovalProfile> identifierToImplementationMap =
      new HashMap<>();

  /**
   * Factory. */
  ApprovalProfilesFactory() {
    ServiceLoader<ApprovalProfile> svcloader =
        ServiceLoader.load(ApprovalProfile.class);
    for (ApprovalProfile type : svcloader) {
      type.initialize();
      identifierToImplementationMap.put(
          type.getApprovalProfileTypeIdentifier(), type);
    }
  }

  /**
   * @return Profile
   */
  public Collection<ApprovalProfile> getAllImplementations() {
    return identifierToImplementationMap.values();
  }

  /**
   * @param identifier ID
   * @return Profile
   */
  public ApprovalProfile getArcheType(final String identifier) {
    return identifierToImplementationMap.get(identifier).clone();
  }
}
