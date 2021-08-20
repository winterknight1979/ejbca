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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Approval Request created when an administrator wants to recovery a end
 * entities keyset.
 *
 * @version $Id: KeyRecoveryApprovalRequest.java 26106 2017-06-30 13:39:10Z
 *     henriks $
 */
public class KeyRecoveryApprovalRequest extends ApprovalRequest {

  private static final long serialVersionUID = -1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(KeyRecoveryApprovalRequest.class);
  /** Param. */
  private static final int LATEST_VERSION = 1;

  /** Param. */
  private String username;
  /** Param. */
  private Certificate cert;

  /** Param. */
  private boolean recoverNewestCert = false;

  /** Constructor used in externalization only. */
  public KeyRecoveryApprovalRequest() { }

  /**
   * @param acert Cert
   * @param ausername User
   * @param dorecoverNewestCert Bool
   * @param requestAdmin Admin
   * @param requestSignature Sig
   * @param cAId CA
   * @param endEntityProfileId Entity
   * @param approvalProfile Profile
   */
  public KeyRecoveryApprovalRequest(
      final Certificate acert,
      final String ausername,
      final boolean dorecoverNewestCert,
      final AuthenticationToken requestAdmin,
      final String requestSignature,
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
    this.cert = acert;
    this.recoverNewestCert = dorecoverNewestCert;
  }

  @Override
  public void execute() throws ApprovalRequestExecutionException {
    throw new RuntimeException(
        "This execution requires additional bean references.");
  }

  /**
   * @param endEntityManagementSession Session
   * @throws ApprovalRequestExecutionException Fail
   */
  public void execute(
      final EndEntityManagementSession endEntityManagementSession)
      throws ApprovalRequestExecutionException {
    LOG.debug("Executing mark for recovery for user:" + username);
    try {
      if (recoverNewestCert) {
        endEntityManagementSession.prepareForKeyRecovery(
            getRequestAdmin(), username, getEndEntityProfileId(), null);
      } else {
        endEntityManagementSession.prepareForKeyRecovery(
            getRequestAdmin(), username, getEndEntityProfileId(), cert);
      }
    } catch (AuthorizationDeniedException e) {
      throw new ApprovalRequestExecutionException(
          "Authorization Denied :" + e.getMessage(), e);
    } catch (ApprovalException e) {
      throw new EJBException("This should never happen", e);
    } catch (WaitingForApprovalException e) {
      throw new EJBException("This should never happen", e);
    } catch (CADoesntExistsException e) {
      throw new EJBException("This should never happen", e);
    }
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
                + getApprovalProfile().getProfileName())
        .hashCode();
  }

  @Override
  public int getApprovalType() {
    return ApprovalDataVO.APPROVALTYPE_KEYRECOVERY;
  }

  /**
   * @return user
   */
  public String getUsername() {
    return username;
  }

  @Override
  public List<ApprovalDataText> getNewRequestDataAsText(
      final AuthenticationToken admin) {
    ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
    retval.add(new ApprovalDataText("USERNAME", username, true, false));
    retval.add(
        new ApprovalDataText(
            "CERTSERIALNUMBER",
            CertTools.getSerialNumberAsString(cert),
            true,
            false));
    retval.add(
        new ApprovalDataText(
            "SUBJECTDN", CertTools.getSubjectDN(cert).toString(), true, false));
    retval.add(
        new ApprovalDataText(
            "ISSUERDN", CertTools.getIssuerDN(cert).toString(), true, false));
    return retval;
  }

  @Override
  public List<ApprovalDataText> getOldRequestDataAsText(
      final AuthenticationToken admin) {
    return null;
  }

  @Override
  public boolean isExecutable() {
    return true;
  }

  @Override
  public void writeExternal(final ObjectOutput out) throws IOException {
    super.writeExternal(out);
    out.writeInt(LATEST_VERSION);
    out.writeObject(username);
    out.writeBoolean(recoverNewestCert);
    try {
      String certString =
              new String(Base64Util.encode(cert.getEncoded()), "UTF8");
      out.writeObject(certString);
    } catch (CertificateEncodingException e) {
      LOG.debug("Error serializing certificate", e);
      throw new IOException(e.getMessage());
    }
  }

  @Override
  public void readExternal(final ObjectInput in)
      throws IOException, ClassNotFoundException {
    super.readExternal(in);
    int version = in.readInt();
    if (version == 1) {
      username = (String) in.readObject();
      recoverNewestCert = in.readBoolean();
      String certString = (String) in.readObject();
      try {
        cert =
          CertTools.getCertfromByteArray(
             Base64Util.decode(certString.getBytes("UTF8")), Certificate.class);
      } catch (CertificateException e) {
        LOG.debug("Error deserializing certificate", e);
        throw new IOException(e.getMessage());
      }
    }
  }
}
