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

/**
 * Editable data in an approval request (e.g. Subject DN in Add End Entity
 * requests). Sent by the CA in e.g. {@link
 * org.ejbca.core.model.era.RaMasterApi#getApprovalRequest} and returned to the
 * CA in {@link org.ejbca.core.model.era.RaMasterApi#editApprovalRequest}
 *
 * @version $Id: RaApprovalEditRequest.java 23552 2016-05-27 13:42:36Z samuellb
 *     $
 */
public final class RaApprovalEditRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final int approvalId;
  /** Param. */
  private final RaEditableRequestData editableData;

  /**
   * @param anapprovalId ID
   * @param theeditableData Data
   */
  public RaApprovalEditRequest(
      final int anapprovalId, final RaEditableRequestData theeditableData) {
    this.approvalId = anapprovalId;
    this.editableData = theeditableData;
  }

  /**
   * @return ID
   */
  public int getId() {
    return approvalId;
  }

  /**
   * @return Data
   */
  public RaEditableRequestData getEditableData() {
    return editableData;
  }
}
