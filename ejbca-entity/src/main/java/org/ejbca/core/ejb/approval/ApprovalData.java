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
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(ApprovalData.class);

  /** Param. */
  private int id; // the unique id stored in the database
  /** Param. */
  private int approvalId; // a hash of the request
  /** Param. */
  private int approvalType;
  /** Param. */
  private int endEntityProfileId;
  /** Param. */
  private int cAId;
  /** Param. */
  private String reqAdminCertIssuerDn;
  /** Param. */
  private String reqAdminCertSn;
  /** Param. */
  private int status;
  /** Param. */
  private String approvalData; // list of approvals
  /** Param. */
  private String requestData;
  /** Param. */
  private long requestDate;
  /** Param. */
  private long expireDate;
  /** Param. */
  private int remainingApprovals;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of a approval data.
   *
   * <p>The constructor is responsible for populating all non-nullable fields!
   *
   * @param anId ID
   */
  public ApprovalData(final int anId) {
    setId(anId);
    setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
    setRequestdate(System.currentTimeMillis());
    LOG.debug("Created approval with id " + anId);
  }

  /** Null constructor. */
  public ApprovalData() {
    // used from test code (also required by JPA!)
  }

  /**
   * unique row id.
   *
   * @return ID
   */
  // @Id @Column
  public int getId() {
    return id;
  }

  /**
   * unique row id.
   *
   * @param anid ID
   */
  public final void setId(final int anid) {
    this.id = anid;
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
   * @param anapprovalId ID
   */
  public void setApprovalid(final int anapprovalId) {
    this.approvalId = anapprovalId;
  }

  /**
   * Type of action that should be approved, should be one of
   * ApprovalDataVO.APPROVALTYPE_ constants ex:
   * ApprovalDataVO.APPROVALTYPE_ADDUSER.
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
   * ApprovalDataVO.APPROVALTYPE_ADDUSER.
   *
   * @param anapprovalType Type
   */
  public void setApprovaltype(final int anapprovalType) {
    this.approvalType = anapprovalType;
  }

  /**
   * For RA specific approval requests should the related end entity profile id
   * be specified for non ra request should this field be set to
   * ApprovalDataVO.ANY_ENDENTITYPROFILE.
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
   * ApprovalDataVO.ANY_ENDENTITYPROFILE s.
   *
   * @param anendEntityProfileId ID
   */
  public void setEndentityprofileid(final int anendEntityProfileId) {
    this.endEntityProfileId = anendEntityProfileId;
  }

  /**
   * For CA specific approval requests should the related ca id be specified for
   * non ca request should this field be set to ApprovalDataVO.ANY_CA.
   *
   * @return ID
   */
  // @Column
  public int getCaid() {
    return cAId;
  }
  /**
   * For CA specific approval requests should the related ca id be specified for
   * non ca request should this field be set to ApprovalDataVO.ANY_CA.
   *
   * @param acAId ID
   */
  public void setCaid(final int acAId) {
    this.cAId = acAId;
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
   * @param areqAdminCertIssuerDn DN
   */
  public void setReqadmincertissuerdn(final String areqAdminCertIssuerDn) {
    this.reqAdminCertIssuerDn = areqAdminCertIssuerDn;
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
   * @param areqAdminCertSn SN
   */
  public void setReqadmincertsn(final String areqAdminCertSn) {
    this.reqAdminCertSn = areqAdminCertSn;
  }

  /**
   * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED,
   * STATUS_REJECTED, STATUS_EXPIRED.
   *
   * @return Status
   */
  // @Column
  public int getStatus() {
    return status;
  }
  /**
   * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED,
   * STATUS_REJECTED, STATUS_EXPIRED.
   *
   * @param astatus Status
   */
  public void setStatus(final int astatus) {
    this.status = astatus;
  }

  /**
   * String representation of data of approvals made by one or more
   * administrators.
   *
   * @return Data
   */
  // @Column @Lob
  public String getApprovaldata() {
    return approvalData;
  }

  /**
   * String representation of data of approvals made by one or more
   * administrators.
   *
   * @param theapprovalData Data
   */
  public void setApprovaldata(final String theapprovalData) {
    this.approvalData = theapprovalData;
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
   * @param therequestData Data
   */
  public void setRequestdata(final String therequestData) {
    this.requestData = therequestData;
  }

  /**
   * Date the request for approval were added.
   *
   * @return Date
   */
  // @Column
  public long getRequestdate() {
    return requestDate;
  }
  /**
   * Date the request for approval were added.
   *
   * @param arequestDate Date
   */
  public void setRequestdate(final long arequestDate) {
    this.requestDate = arequestDate;
  }

  /**
   * Date the request for action or the approval action will expire,
   * Long.MAX_VALUE means that the request/approval never expires.
   *
   * @return Date
   */
  // @Column
  public long getExpiredate() {
    return expireDate;
  }
  /**
   * Date the request for action or the approval action will expire,
   * Long.MAX_VALUE means that the request/approval never expires.
   *
   * @param anexpireDate Date
   */
  public void setExpiredate(final long anexpireDate) {
    this.expireDate = anexpireDate;
  }

  /**
   * Indicates the number of approvals that remains in order to execute the
   * action.
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
   * action.
   *
   * @param theremainingApprovals approvals
   */
  @Deprecated
  public void setRemainingapprovals(final int theremainingApprovals) {
    this.remainingApprovals = theremainingApprovals;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String arowProtection) {
    this.rowProtection = arowProtection;
  }

  /**
   * @return request date
   */
  @Transient
  public Date getRequestDate() {
    return new Date(getRequestdate());
  }

  /**
   * @return expiry date
   */
  @Transient
  public Date getExpireDate() {
    return new Date(getExpiredate());
  }

  /**
   * Method used to set the expire date of the request.
   *
   * @param anexpireDate date
   */
  public void setExpireDate(final Date anexpireDate) {
    setExpiredate(anexpireDate.getTime());
  }

  /**
   * Method that checks if the request or approval have expired The status is
   * set to expired if it is.
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

  /**
   * @return request
   */
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
      LOG.error("Error building approval request.", e);
      throw new IllegalStateException(e);
    } catch (ClassNotFoundException e) {
      LOG.error("Error building approval request.", e);
      throw new IllegalStateException(e);
    }
    return retval;
  }

  /**
   * @return approvals
   */
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
      LOG.error("Error building approvals.", e);
      throw new IllegalStateException(e);
    } catch (ClassNotFoundException e) {
      LOG.error("Error building approvals.", e);
      throw new IllegalStateException(e);
    }
    return retval;
  }
}
