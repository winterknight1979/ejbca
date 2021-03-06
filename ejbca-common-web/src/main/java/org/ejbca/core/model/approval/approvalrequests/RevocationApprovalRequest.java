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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ra.AlreadyRevokedException;

/**
 * @version $Id: RevocationApprovalRequest.java 29136 2018-06-07 11:11:07Z
 *     andresjakobs $
 */
public class RevocationApprovalRequest extends ApprovalRequest {

  private static final long serialVersionUID = -1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(RevocationApprovalRequest.class);
  /** Param. */
  private static final int LATEST_VERSION = 1;

  /** Param. */
  private int approvalType = -1;
  /** Param. */
  private String username = null;
  /** Param. */
  private BigInteger certificateSerialNumber = null;
  /** Param. */
  private String issuerDN = null;
  /** Param. */
  private int reason = -2;

  /** Constructor used in externalization only. */
  public RevocationApprovalRequest() { }

  /**
   * Construct an ApprovalRequest for the revocation of a certificate.
   *
   * @param acertificateSerialNumber SN
   * @param anissuerDN DN
   * @param ausername Name
   * @param areason reason
   * @param requestAdmin Admin
   * @param cAId CA
   * @param endEntityProfileId Entity
   * @param approvalProfile Approval
   */
  public RevocationApprovalRequest(
      final BigInteger acertificateSerialNumber,
      final String anissuerDN,
      final String ausername,
      final int areason,
      final AuthenticationToken requestAdmin,
      final int cAId,
      final int endEntityProfileId,
      final ApprovalProfile approvalProfile) {
    super(
        requestAdmin,
        null,
        REQUESTTYPE_SIMPLE,
        cAId,
        endEntityProfileId,
        approvalProfile);
    this.approvalType = ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE;
    this.username = ausername;
    this.reason = areason;
    this.certificateSerialNumber = acertificateSerialNumber;
    this.issuerDN = anissuerDN;
  }

  /**
   * Constructs an ApprovalRequest for the revocation and optional removal of an
   * end entity.
   *
   * @param deleteAfterRevoke bool
   * @param ausername Name
   * @param areason reason
   * @param requestAdmin Admin
   * @param cAId CA
   * @param endEntityProfileId Entity
   * @param approvalProfile Approval
   */
  public RevocationApprovalRequest(
      final boolean deleteAfterRevoke,
      final String ausername,
      final int areason,
      final AuthenticationToken requestAdmin,
      final int cAId,
      final int endEntityProfileId,
      final ApprovalProfile approvalProfile) {
    super(
        requestAdmin,
        null,
        REQUESTTYPE_SIMPLE,
        cAId,
        endEntityProfileId,
        approvalProfile);
    if (deleteAfterRevoke) {
      this.approvalType = ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY;
    } else {
      this.approvalType = ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY;
    }
    this.username = ausername;
    this.reason = areason;
    this.certificateSerialNumber = null;
    this.issuerDN = null;
  }

  /**
   * A main function of the ApprovalRequest, the execute() method is run when
   * all required approvals have been made.
   *
   * <p>execute should perform the action or nothing if the requesting admin is
   * supposed to try this action again.
   */
  @Override
  public void execute() throws ApprovalRequestExecutionException {
    throw new RuntimeException(
        "This execution requires additional bean references.");
  }

  /**
   * @param endEntityManagementSession Session
   * @param approvalRequestID ID
   * @param lastApprovalAdmin Admin
   * @throws ApprovalRequestExecutionException FAil
   */
  public void execute(
      final EndEntityManagementSession endEntityManagementSession,
      final int approvalRequestID,
      final AuthenticationToken lastApprovalAdmin)
      throws ApprovalRequestExecutionException {
    LOG.debug(
        "Executing "
            + ApprovalDataVO.APPROVALTYPENAMES[approvalType]
            + " ("
            + approvalType
            + ").");
    try {
      switch (approvalType) {
        case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY:
          endEntityManagementSession.revokeUserAfterApproval(
              getRequestAdmin(),
              username,
              reason,
              approvalRequestID,
              lastApprovalAdmin);
          break;
        case ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY:
          // Since the end entity will be deleted from the database, there is no
          // point to store the approval request ID in its extendedInformation
          endEntityManagementSession.revokeAndDeleteUser(
              getRequestAdmin(), username, reason);
          break;
        case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE:
          endEntityManagementSession.revokeCertAfterApproval(
              getRequestAdmin(),
              certificateSerialNumber,
              issuerDN,
              reason,
              approvalRequestID,
              lastApprovalAdmin);
          break;
        default:
          LOG.error("Unknown approval type " + approvalType);
          break;
      }
    } catch (AuthorizationDeniedException e) {
      throw new ApprovalRequestExecutionException(
          "Authorization Denied :" + e.getMessage(), e);
    } catch (ApprovalException e) {
      throw new EJBException("This should never happen", e);
    } catch (WaitingForApprovalException e) {
      throw new EJBException("This should never happen", e);
    } catch (AlreadyRevokedException e) {
      throw new ApprovalRequestExecutionException(
          "End entity " + username + " was already revoked at execution time.");
    } catch (NoSuchEndEntityException e) {
      throw new ApprovalRequestExecutionException("Could not find object.", e);
    } catch (CouldNotRemoveEndEntityException e) {
      throw new ApprovalRequestExecutionException(
          "Could not remove object.", e);
    }
  }

  /**
   * Method that should generate an approval id for this type of approval, the
   * same request i.e the same admin want's to do the same thing twice should
   * result in the same approvalId.
   */
  @Override
  public int generateApprovalId() {
    return generateApprovalId(
        getApprovalType(),
        username,
        reason,
        certificateSerialNumber,
        issuerDN,
        getApprovalProfile().getProfileName());
  }

  /**
   * @param approvalType Type
   * @param username User
   * @param reason Reason
   * @param certificateSerialNumber SN
   * @param issuerDN DN
   * @param approvalProfileName Profile
   * @return ID
   */
  public static int generateApprovalId(
      final int approvalType,
      final String username,
      final int reason,
      final BigInteger certificateSerialNumber,
      final String issuerDN,
      final String approvalProfileName) {
    String idString = approvalType + ";" + username + ";" + reason + ";";
    if (certificateSerialNumber != null && issuerDN != null) {
      idString += certificateSerialNumber + ";" + issuerDN + ";";
    }
    idString += ";" + approvalProfileName;
    return idString.hashCode();
  }

  @Override
  public int getApprovalType() {
    return approvalType;
  }

  /**
   * This method should return the request data in text representation. This
   * text is presented for the approving administrator in order for him to make
   * a decision about the request.
   *
   * <p>Should return a List of ApprovalDataText, one for each row
   */
  @Override
  public List<ApprovalDataText> getNewRequestDataAsText(
      final AuthenticationToken admin) {
    ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
    if (username != null) {
      retval.add(new ApprovalDataText("USERNAME", username, true, false));
    }
    if (reason == RevokedCertInfo.NOT_REVOKED) {
      retval.add(new ApprovalDataText("REASON", "UNREVOKE", true, true));
    } else {
      retval.add(
          new ApprovalDataText(
              "REASON", SecConst.REASONTEXTS[reason], true, true));
    }
    if (certificateSerialNumber != null && issuerDN != null) {
      retval.add(
          new ApprovalDataText(
              "CERTSERIALNUMBER",
              certificateSerialNumber.toString(16),
              true,
              false));
      retval.add(new ApprovalDataText("ISSUERDN", issuerDN, true, false));
    }
    return retval;
  }

  /**
   * This method should return the original request data in text representation.
   * Should only be implemented by TYPE_COMPARING ApprovalRequests. TYPE_SIMPLE
   * requests should return null;
   *
   * <p>This text is presented for the approving administrator for him to
   * compare of what will be done.
   *
   * <p>Should return a Collection of ApprovalDataText, one for each row
   */
  @Override
  public List<ApprovalDataText> getOldRequestDataAsText(
      final AuthenticationToken admin) {
    return null;
  }

  /**
   * Should return true if the request if of the type that should be executed by
   * the last approver.
   *
   * <p>False if the request admin should do a polling action to try again.
   */
  @Override
  public boolean isExecutable() {
    return true;
  }

  @Override
  public void writeExternal(final ObjectOutput out) throws IOException {
    super.writeExternal(out);
    out.writeInt(LATEST_VERSION);
    out.writeObject(username);
    out.writeInt(reason);
    out.writeInt(approvalType);
    out.writeObject(certificateSerialNumber);
    out.writeObject(issuerDN);
  }

  @Override
  public void readExternal(final ObjectInput in)
      throws IOException, ClassNotFoundException {
    super.readExternal(in);
    int version = in.readInt();
    if (version == 1) {
      username = (String) in.readObject();
      reason = in.readInt();
      approvalType = in.readInt();
      certificateSerialNumber = (BigInteger) in.readObject();
      issuerDN = (String) in.readObject();
    }
  }

  /**
   * @return User
   */
  public String getUsername() {
    return username;
  }
}
