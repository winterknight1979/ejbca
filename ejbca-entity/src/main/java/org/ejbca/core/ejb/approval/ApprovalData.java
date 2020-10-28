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

package org.ejbca.core.ejb.approval;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;

/**
 * Representation of approval request data used to control request and their
 * approvals.
 *
 * @version $Id: ApprovalData.java 24238 2016-08-29 11:32:18Z aveen4711 $
 */
@Entity
@Table(name = "ApprovalData")
public class ApprovalData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  private static final Logger log = Logger.getLogger(ApprovalData.class);

  private int id; // the unique id stored in the database
  private int approvalId; // a hash of the request
  private int approvalType;
  private int endEntityProfileId;
  private int cAId;
  private String reqAdminCertIssuerDn;
  private String reqAdminCertSn;
  private int status;
  private String approvalData; // list of approvals
  private String requestData;
  private long requestDate;
  private long expireDate;
  private int remainingApprovals;
  private int rowVersion = 0;
  private String rowProtection;

  /**
   * Entity holding data of a approval data.
   *
   * <p>The constructor is responsible for populating all non-nullable fields!
   *
   * @param id ID
   */
  public ApprovalData(final int id) {
    setId(id);
    setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
    setRequestdate(System.currentTimeMillis());
    log.debug("Created approval with id " + id);
  }

  public ApprovalData() {
    // used from test code (also required by JPA!)
  }

  /**
   * unique row id
   *
   * @return ID
   */
  // @Id @Column
  public int getId() {
    return id;
  }

  /**
   * unique row id
   *
   * @param id ID
   */
  public final void setId(final int id) {
    this.id = id;
  }

  /**
   * Constructed from action data as actiontype, admin, username etc. It should
   * result in the same approvalid if the admin tries to request the same action
   * twice.
   *
   * @return ID
   */
  // @Column
  public int getApprovalid() {
    return approvalId;
  }
  /**
   * Constructed from action data as actiontype, admin, username etc. It should
   * result in the same approvalid if the admin tries to request the same action
   * twice.
   *
   * @param approvalId ID
   */
  public void setApprovalid(final int approvalId) {
    this.approvalId = approvalId;
  }

  /**
   * Type of action that should be approved, should be one of
   * ApprovalDataVO.APPROVALTYPE_ constants ex:
   * ApprovalDataVO.APPROVALTYPE_ADDUSER
   *
   * @return Type
   */
  // @Column
  public int getApprovaltype() {
    return approvalType;
  }
  /**
   * Type of action that should be approved, should be one of
   * ApprovalDataVO.APPROVALTYPE_ constants ex:
   * ApprovalDataVO.APPROVALTYPE_ADDUSER
   *
   * @param approvalType Type
   */
  public void setApprovaltype(final int approvalType) {
    this.approvalType = approvalType;
  }

  /**
   * For RA specific approval requests should the related end entity profile id
   * be specified for non ra request should this field be set to
   * ApprovalDataVO.ANY_ENDENTITYPROFILE
   *
   * @return ID
   */
  // @Column
  public int getEndentityprofileid() {
    return endEntityProfileId;
  }
  /**
   * For RA specific approval requests should the related end entity profile id
   * be specified for non ra request should this field be set to
   * ApprovalDataVO.ANY_ENDENTITYPROFILE s
   *
   * @param endEntityProfileId ID
   */
  public void setEndentityprofileid(final int endEntityProfileId) {
    this.endEntityProfileId = endEntityProfileId;
  }

  /**
   * For CA specific approval requests should the related ca id be specified for
   * non ca request should this field be set to ApprovalDataVO.ANY_CA
   *
   * @return ID
   */
  // @Column
  public int getCaid() {
    return cAId;
  }
  /**
   * For CA specific approval requests should the related ca id be specified for
   * non ca request should this field be set to ApprovalDataVO.ANY_CA
   *
   * @param cAId ID
   */
  public void setCaid(final int cAId) {
    this.cAId = cAId;
  }

  /**
   * The issuerdn of the administrator certificate that generated the request.
   *
   * @return DN
   */
  // @Column
  public String getReqadmincertissuerdn() {
    return reqAdminCertIssuerDn;
  }
  /**
   * The issuerdn of the administrator certificate that generated the request.
   *
   * @param reqAdminCertIssuerDn DN
   */
  public void setReqadmincertissuerdn(final String reqAdminCertIssuerDn) {
    this.reqAdminCertIssuerDn = reqAdminCertIssuerDn;
  }

  /**
   * The serialnumber of the administrator certificate that generated the
   * request. String in Hex.
   *
   * @return SN
   */
  // @Column
  public String getReqadmincertsn() {
    return reqAdminCertSn;
  }
  /**
   * The serialnumber of the administrator certificate that generated the
   * request. String in Hex.
   *
   * @param reqAdminCertSn SN
   */
  public void setReqadmincertsn(final String reqAdminCertSn) {
    this.reqAdminCertSn = reqAdminCertSn;
  }

  /**
   * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED,
   * STATUS_REJECTED, STATUS_EXPIRED
   *
   * @return Status
   */
  // @Column
  public int getStatus() {
    return status;
  }
  /**
   * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED,
   * STATUS_REJECTED, STATUS_EXPIRED
   *
   * @param status Status
   */
  public void setStatus(final int status) {
    this.status = status;
  }

  /**
   * String representation of data of approvals made by one or more
   * administrators
   *
   * @return Data
   */
  // @Column @Lob
  public String getApprovaldata() {
    return approvalData;
  }

  /**
   * String representation of data of approvals made by one or more
   * administrators
   *
   * @param approvalData Data
   */
  public void setApprovaldata(final String approvalData) {
    this.approvalData = approvalData;
  }

  /**
   * Data containing information about the request displayed for the approval
   * administrator.
   *
   * @return Data
   */
  // @Column @Lob
  public String getRequestdata() {
    return requestData;
  }

  /**
   * Data containing information about the request displayed for the approval
   * administrator.
   *
   * @param requestData Data
   */
  public void setRequestdata(final String requestData) {
    this.requestData = requestData;
  }

  /**
   * Date the request for approval were added
   *
   * @return Date
   */
  // @Column
  public long getRequestdate() {
    return requestDate;
  }
  /**
   * Date the request for approval were added
   *
   * @param requestDate Date
   */
  public void setRequestdate(final long requestDate) {
    this.requestDate = requestDate;
  }

  /**
   * Date the request for action or the approval action will expire,
   * Long.MAX_VALUE means that the request/approval never expires
   *
   * @return Date
   */
  // @Column
  public long getExpiredate() {
    return expireDate;
  }
  /**
   * Date the request for action or the approval action will expire,
   * Long.MAX_VALUE means that the request/approval never expires
   *
   * @param expireDate Date
   */
  public void setExpiredate(final long expireDate) {
    this.expireDate = expireDate;
  }

  /**
   * Indicates the number of approvals that remains in order to execute the
   * action
   *
   * @return approvals
   * @deprecated in 6.6.0, the type of approval handled is now part of the
   *     approval profile
   */
  // @Column
  @Deprecated
  public int getRemainingapprovals() {
    // TODO remove this method when support for Ejbca 6.5.x is dropped
    return remainingApprovals;
  }
  /**
   * Indicates the number of approvals that remains in order to execute the
   * action
   *
   * @param remainingApprovals approvals
   */
  @Deprecated
  public void setRemainingapprovals(final int remainingApprovals) {
    this.remainingApprovals = remainingApprovals;
  }

  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  public void setRowVersion(final int rowVersion) {
    this.rowVersion = rowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String rowProtection) {
    this.rowProtection = rowProtection;
  }

  @Transient
  public Date getRequestDate() {
    return new Date(getRequestdate());
  }

  @Transient
  public Date getExpireDate() {
    return new Date(getExpiredate());
  }

  /**
   * Method used to set the expire date of the request
   *
   * @param expireDate date
   */
  public void setExpireDate(final Date expireDate) {
    setExpiredate(expireDate.getTime());
  }

  /**
   * Method that checks if the request or approval have expired The status is
   * set to expired if it is
   *
   * @return true of the request or approval have expired
   */
  public boolean hasRequestOrApprovalExpired() {
    final Date currentDate = new Date();
    boolean retval = false;
    if (currentDate.after(getExpireDate())) {
      if (getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL
          || getStatus() == ApprovalDataVO.STATUS_APPROVED
          || getStatus() == ApprovalDataVO.STATUS_REJECTED) {
        setStatus(ApprovalDataVO.STATUS_EXPIRED);
      }
      retval = true;
    }
    return retval;
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getId())
        .append(getApprovalid())
        .append(getApprovaltype())
        .append(getEndentityprofileid())
        .append(getCaid())
        .append(getReqadmincertissuerdn());
    build
        .append(getReqadmincertsn())
        .append(getStatus())
        .append(getApprovaldata())
        .append(getRequestdata())
        .append(getRequestdate())
        .append(getExpiredate())
        .append(getRemainingapprovals());
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 2;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return String.valueOf(getId());
  }

  //
  // End Database integrity protection methods
  //

  /** @return a value object representation of this entity bean */
  @Transient
  public ApprovalDataVO getApprovalDataVO() {
    hasRequestOrApprovalExpired();
    ApprovalDataVO result =
        new ApprovalDataVO(
            getId(),
            getApprovalid(),
            getApprovaltype(),
            getEndentityprofileid(),
            getCaid(),
            getReqadmincertissuerdn(),
            getReqadmincertsn(),
            getStatus(),
            getApprovals(),
            getApprovalRequest(),
            getRequestDate(),
            getExpireDate());
    return result;
  }

  @Transient
  public ApprovalRequest getApprovalRequest() {
    ApprovalRequest retval = null;
    try {
      ObjectInputStream ois =
          new ObjectInputStream(
              new ByteArrayInputStream(
                  Base64.decode(getRequestdata().getBytes())));
      retval = (ApprovalRequest) ois.readObject();
    } catch (IOException e) {
      log.error("Error building approval request.", e);
      throw new IllegalStateException(e);
    } catch (ClassNotFoundException e) {
      log.error("Error building approval request.", e);
      throw new IllegalStateException(e);
    }
    return retval;
  }

  @Transient
  public List<Approval> getApprovals() {
    List<Approval> retval = new ArrayList<Approval>();
    try {
      ObjectInputStream ois =
          new ObjectInputStream(
              new ByteArrayInputStream(
                  Base64.decode(getApprovaldata().getBytes())));
      int size = ois.readInt();
      for (int i = 0; i < size; i++) {
        Approval next = (Approval) ois.readObject();
        retval.add(next);
      }
    } catch (IOException e) {
      log.error("Error building approvals.", e);
      throw new IllegalStateException(e);
    } catch (ClassNotFoundException e) {
      log.error("Error building approvals.", e);
      throw new IllegalStateException(e);
    }
    return retval;
  }
}
