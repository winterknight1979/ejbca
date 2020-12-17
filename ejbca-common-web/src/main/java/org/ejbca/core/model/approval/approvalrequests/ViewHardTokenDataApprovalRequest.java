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
 * Approval Request created when an administrator wants to view hard token data.
 *
 * @version $Id: ViewHardTokenDataApprovalRequest.java 23853 2016-07-10
 *     12:09:36Z mikekushner $
 */
public class ViewHardTokenDataApprovalRequest extends ApprovalRequest {

  private static final long serialVersionUID = -1L;
  // private static final Logger log =
  // Logger.getLogger(ViewHardTokenDataApprovalRequest.class);
  /** Param. */
  private static final int LATEST_VERSION = 1;

  /** Param. */
  private String dn;
  /** Param. */
  private String username;
  /** Param. */
  private String tokensn;
  /** Param. */
  private boolean viewpuk;

  /** Constructor used in externalization only. */
  public ViewHardTokenDataApprovalRequest() { }

  /**
   * @param ausername User
   * @param userDN DN
   * @param atokensn SN
   * @param viewPUK PUK
   * @param requestAdmin Admin
   * @param requestSignature Sig
   * @param numOfReqApprovals Approvals
   * @param cAId CA
   * @param endEntityProfileId Profile
   * @param approvalProfile Profile
   */
  public ViewHardTokenDataApprovalRequest(
      final String ausername,
      final String userDN,
      final String atokensn,
      final boolean viewPUK,
      final AuthenticationToken requestAdmin,
      final String requestSignature,
      final int numOfReqApprovals,
      final int cAId,
      final int endEntityProfileId,
      final ApprovalProfile approvalProfile) {
    super(
        requestAdmin,
        requestSignature,
        REQUESTTYPE_SIMPLE,
        cAId,
        endEntityProfileId,
        approvalProfile);
    this.username = ausername;
    this.dn = userDN;
    this.tokensn = atokensn;
    this.viewpuk = viewPUK;
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
                + tokensn
                + ";"
                + CertTools.getFingerprintAsString(getRequestAdminCert())
                + ";"
                + getApprovalProfile().getProfileName())
        .hashCode();
  }

  @Override
  public int getApprovalType() {
    return ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA;
  }

  @Override
  public List<ApprovalDataText> getNewRequestDataAsText(
      final AuthenticationToken admin) {
    ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
    retval.add(new ApprovalDataText("USERNAME", username, true, false));
    retval.add(new ApprovalDataText("SUBJECTDN", dn, true, false));
    retval.add(new ApprovalDataText("HARDTOKENSN", tokensn, true, false));
    if (viewpuk) {
      retval.add(
          new ApprovalDataText("VIEWPUKENDENTITYRULE", "YES", true, true));
    } else {
      retval.add(
          new ApprovalDataText("VIEWPUKENDENTITYRULE", "NO", true, true));
    }
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
    out.writeObject(tokensn);
    out.writeBoolean(viewpuk);
  }

  @Override
  public void readExternal(final ObjectInput in)
      throws IOException, ClassNotFoundException {
    super.readExternal(in);
    int version = in.readInt();
    if (version == 1) {
      username = (String) in.readObject();
      dn = (String) in.readObject();
      tokensn = (String) in.readObject();
      viewpuk = in.readBoolean();
    }
  }
}
