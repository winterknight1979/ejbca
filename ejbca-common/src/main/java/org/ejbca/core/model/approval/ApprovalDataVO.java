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

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Value Object containing all the information about an approval such as
 * approvalid, approvaltype, endentityprofileid, caid, reqadmincertissuerdn,
 * reqadmincertsn, status, approvals (Collection), requestdata, requestdate,
 * expiredate, remainingapprovals.
 *
 * @version $Id: ApprovalDataVO.java 27422 2017-12-05 14:05:42Z bastianf $
 */
public class ApprovalDataVO implements Serializable {

  private static final long serialVersionUID = -2L;

  // Status constants
  /** Config. */
  public static final int STATUS_WAITINGFORAPPROVAL = -1;
  /** Config. */
  public static final int STATUS_APPROVED = 0;
  /** Config. */
  public static final int STATUS_REJECTED = -2;
  /** Config. */
  public static final int STATUS_EXPIRED = -3;
  /** Config. */
  public static final int STATUS_EXPIREDANDNOTIFIED =
      -4; // Used to mark that the requester has been notified that the request
          // has expired.
  /** Config. */
  public static final int STATUS_EXECUTED = -5;
  /** Config. */
  public static final int STATUS_EXECUTIONFAILED = -6;
  /** Config. */
  public static final int STATUS_EXECUTIONDENIED = -7;

  // Approval types
  /** Config. */
  public static final int APPROVALTYPE_DUMMY = 0;
  /** Config. */
  public static final int APPROVALTYPE_VIEWHARDTOKENDATA = 1;
  /** Config. */
  public static final int APPROVALTYPE_ADDENDENTITY = 2;
  /** Config. */
  public static final int APPROVALTYPE_EDITENDENTITY = 3;
  /** Config. */
  public static final int APPROVALTYPE_CHANGESTATUSENDENTITY = 4;
  /** Config. */
  public static final int APPROVALTYPE_KEYRECOVERY = 5;
  /** Config. */
  public static final int APPROVALTYPE_GENERATETOKEN = 6;
  /** Config. */
  public static final int APPROVALTYPE_REVOKEENDENTITY = 7;
  /** Config. */
  public static final int APPROVALTYPE_REVOKEANDDELETEENDENTITY = 8;
  /** Config. */
  public static final int APPROVALTYPE_REVOKECERTIFICATE = 9;
  /** Config. */
  public static final int APPROVALTYPE_ACTIVATECATOKEN = 10;

  /** IMPORTANT REMEMBER TO SET THE RESOURCES IN BOTH INTERNAL AND ADMINWEB
   LANGUAGE FILES. */
  public static final String[] APPROVALTYPENAMES = {
    "APDUMMY",
    "APVIEWHARDTOKENDATA",
    "APADDENDENTITY",
    "APEDITENDENTITY",
    "APCHANGESTATUSENDENTITY",
    "APKEYRECOVERY",
    "APGENERATETOKEN",
    "APREVOKEENDENTITY",
    "APREVOKEDELETEENDENTITY",
    "APREVOKECERTIFICATE",
    "APPROVEACTIVATECA"
  };

  /** Used to indicate that the approval is applicable to any ca. */
  public static final int ANY_CA = SecConst.ALLCAS;

  /**
   * Used to indicate that the approval is applicable to any end entity profile.
   */
  public static final int ANY_ENDENTITYPROFILE =
      EndEntityConstants.NO_END_ENTITY_PROFILE;

  /** ID. */
  private int id = 0;
  /** ID. */
  private int approvalId = 0;
  /** Type. */
  private int approvalType = 0;
  /**
   * Note: It's known that this field has a typo in it, but renaming it would
   * break serialization and thus compromise EJBCA's 100% uptime requirements.
   * For that reason, leave it be.
   */
  private int endEntityProfileiId = 0;
  /** CA. */
  private int cAId = 0;
  /** DN. */
  private String reqadmincertissuerdn = null;
  /** SN. */
  private String reqadmincertsn = null;
  /** Status. */
  private int status = 0;
  /** Approvals. */
  private Collection<Approval> approvals = null;
  /** Req. */
  private ApprovalRequest approvalRequest = null;
  /** Date. */
  private Date requestDate = null;
  /** Date. */
  private Date expireDate = null;

  /**
   * @param abid unique row id
   * @param anapprovalId Constructed from action data as actiontype, admin,
   *     username etc. It should result in the same approvalid if the admin
   *     tries to request the same action twice.
   * @param anapprovalType Type of action that should be approved, should be one
   *     of ApprovalDataVO.APPROVALTYPE_ constants ex:
   *     ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA
   * @param anendEntityProfileiId For RA specific approval requests should the
   *     related end entity profile id be specified for non ra request should
   *     this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE
   * @param acAId For CA specific approval requests should the related ca id be
   *     specified for non ca request should this field be set to
   *     ApprovalDataVO.ANY_CA
   * @param areqadmincertissuerdn The issuerdn of the administrator certificate
   *     that generated the request.
   * @param areqadmincertsn The serialnumber of the administrator certificate
   *     that generated the request. String in Hex
   * @param astatus Should be one of ApprovalDataVO.STATUS_ constants
   * @param theapprovals Collection of created Approvals (never null)
   * @param anapprovalRequest The ApprovalRequest
   * @param therequestDate Date the request for approval were added
   * @param theexpireDate Date the request for action or the
   *     approval action will
   *     expire, Long.MAX_VALUE means that the request/approval never expires
   */
  public ApprovalDataVO(
      final int abid,
      final int anapprovalId,
      final int anapprovalType,
      final int anendEntityProfileiId,
      final int acAId,
      final String areqadmincertissuerdn,
      final String areqadmincertsn,
      final int astatus,
      final Collection<Approval> theapprovals,
      final ApprovalRequest anapprovalRequest,
      final Date therequestDate,
      final Date theexpireDate) {
    super();
    this.id = abid;
    this.approvalId = anapprovalId;
    this.approvalType = anapprovalType;
    this.endEntityProfileiId = anendEntityProfileiId;
    this.cAId = acAId;
    this.reqadmincertissuerdn = areqadmincertissuerdn;
    this.reqadmincertsn = areqadmincertsn;
    this.status = astatus;
    this.approvals = theapprovals;
    this.approvalRequest = anapprovalRequest;
    this.requestDate = therequestDate;
    this.expireDate = theexpireDate;
  }
  /**
   * Constructed from action data as actiontype, admin, username etc. It should
   * result in the same approvalid if the admin tries to request the same action
   * twice.
   *
   * @return Returns the approvalId.
   */
  public int getApprovalId() {
    return approvalId;
  }
  /**
   * The ApprovalRequest.
   *
   * @return Returns the approvalRequest.
   */
  public ApprovalRequest getApprovalRequest() {
    return approvalRequest;
  }

/**
 * @param anApprovalRequest req
 */
  public void setApprovalRequest(final ApprovalRequest anApprovalRequest) {
    this.approvalRequest = anApprovalRequest;
  }

  /**
   * Collection of created Approvals (never null).
   *
   * @return Returns the approvals.
   */
  public Collection<Approval> getApprovals() {
    return approvals;
  }

  /**
   * Type of action that should be approved, should be one of
   * ApprovalDataVO.APPROVALTYPE_ constants ex:
   * ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA.
   *
   * @return Returns the approvalType.
   */
  public int getApprovalType() {
    return approvalType;
  }

  /**
   * For CA specific approval requests should the related ca id be specified for
   * non ca request should this field be set to ApprovalDataVO.ANY_CA.
   *
   * @return Returns the cAId.
   */
  public int getCAId() {
    return cAId;
  }

  /**
   * For RA specific approval requests should the related end entity profile id
   * be specified for non ra request should this field be set to
   * ApprovalDataVO.ANY_ENDENTITYPROFILE.
   *
   * @return Returns the endEntityProfileId.
   */
  public int getEndEntityProfileId() {
    return endEntityProfileiId;
  }

  /**
   * Date the request for action or the approvel action will expire,
   * Long.MAX_VALUE means that the request/approval never expires.
   *
   * @return Returns the expireDate.
   */
  public Date getExpireDate() {
    return expireDate;
  }

  /** @return Returns the id. */
  public int getId() {
    return id;
  }

  /**
   * @return profile
   */
  public ApprovalProfile getApprovalProfile() {
    return approvalRequest.getApprovalProfile();
  }

  /**
   * @return num
   */
  public int getRemainingApprovals() {
    if (status == STATUS_REJECTED) {
      return 0;
    } else {
      if (getApprovalProfile() != null) {
        return getApprovalProfile().getRemainingApprovals(getApprovals());
      } else {
        return -1;
      }
    }
  }

  /**
   * The issuerdn of the administrator certificate that generated the request.
   *
   * @return Returns the reqadmincertissuerdn.
   */
  public String getReqadmincertissuerdn() {
    return reqadmincertissuerdn;
  }

  /**
   * The serialnumber of the administrator certificate that generated the
   * request. String in Hex
   *
   * @return Returns the reqadmincertsn.
   */
  public String getReqadmincertsn() {
    return reqadmincertsn;
  }

  /**
   * Date the request for approval were added.
   *
   * @return Returns the requestDate.
   */
  public Date getRequestDate() {
    return requestDate;
  }

  /**
   * Should be one of ApprovalDataVO.STATUS_ constants.
   *
   * @return Returns the status.
   */
  public int getStatus() {
    return status;
  }
}
