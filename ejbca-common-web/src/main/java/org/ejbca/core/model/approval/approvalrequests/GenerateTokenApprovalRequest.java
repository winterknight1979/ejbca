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
package org.ejbca.core.model.approval.approvalrequests;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.List;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Special Approval Request created when an administrator wants to generate a
 * token through the Web Service interface.
 *
 * <p>It is a two step approval request were the first step is a view hard token
 * PUK data and the second is the actual hard token generation
 *
 * @version $Id: GenerateTokenApprovalRequest.java 23981 2016-07-22 12:21:55Z
 *     anatom $
 */
public class GenerateTokenApprovalRequest extends ApprovalRequest {

  private static final long serialVersionUID = -1L;

  /** Param. */
  public static final int STEP_0_VIEWHARDTOKENDATA = 0;
  /** Param. */
  public static final int STEP_1_GENERATETOKEN = 1;

  /** Param. */
  private static final int LATEST_VERSION = 1;

  /** Param. */
  private String dn;
  /** Param. */
  private String username;
  /** Param. */
  private String tokenTypeLabel;

  /** Constructor used in externalization only. */
  public GenerateTokenApprovalRequest()  { }

  /**
   * @param ausername User
   * @param userDN DN
   * @param atokenTypeLabel Type
   * @param requestAdmin Admin
   * @param requestSignature Sig
   * @param cAId CA
   * @param endEntityProfileId Entity
   * @param approvalProfile Approval
   */
  public GenerateTokenApprovalRequest(
      final String ausername,
      final String userDN,
      final String atokenTypeLabel,
      final AuthenticationToken requestAdmin,
      final String requestSignature,
      final int cAId,
      final int endEntityProfileId,
      final ApprovalProfile approvalProfile) {
    // This is a 2 step approval, whatever that means...
    super(
        requestAdmin,
        requestSignature,
        REQUESTTYPE_SIMPLE,
        cAId,
        endEntityProfileId,
        2,
        approvalProfile);
    this.username = ausername;
    this.dn = userDN;
    this.tokenTypeLabel = atokenTypeLabel;
  }

  @Override
  public void execute() throws ApprovalRequestExecutionException {
    // This is a non-executable approval
  }

  /**
   * Approval Id is generated of This approval type (i.e
   * AddEndEntityApprovalRequest) and UserName.
   */
  @Override
  public int generateApprovalId() {
    return new String(
            getApprovalType()
                + ";"
                + username
                + ";"
                + CertTools.getFingerprintAsString(getRequestAdminCert())
                + ";"
                + getApprovalProfile().getProfileName())
        .hashCode();
  }

  @Override
  public int getApprovalType() {
    return ApprovalDataVO.APPROVALTYPE_GENERATETOKEN;
  }

  @Override
  public List<ApprovalDataText> getNewRequestDataAsText(
      final AuthenticationToken admin) {
    ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
    retval.add(new ApprovalDataText("USERNAME", username, true, false));
    retval.add(new ApprovalDataText("SUBJECTDN", dn, true, false));
    retval.add(new ApprovalDataText("LABEL", tokenTypeLabel, true, true));
    return retval;
  }

  @Override
  public List<ApprovalDataText> getOldRequestDataAsText(
      final AuthenticationToken admin) {
    return null;
  }

  @Override
  public boolean isExecutable() {
    return false;
  }

  @Override
  public void writeExternal(final ObjectOutput out) throws IOException {
    super.writeExternal(out);
    out.writeInt(LATEST_VERSION);
    out.writeObject(username);
    out.writeObject(dn);
    out.writeObject(tokenTypeLabel);
  }

  @Override
  public void readExternal(final ObjectInput in)
      throws IOException, ClassNotFoundException {
    super.readExternal(in);
    int version = in.readInt();
    if (version == 1) {
      username = (String) in.readObject();
      dn = (String) in.readObject();
      tokenTypeLabel = (String) in.readObject();
    }
  }

  /** @return the subject dn used in the request */
  public String getDN() {
    return dn;
  }
}
