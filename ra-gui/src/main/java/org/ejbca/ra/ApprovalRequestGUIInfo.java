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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import javax.faces.model.SelectItem;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDateUtil;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.TimeAndAdmin;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalStepInfo;
import org.ejbca.core.model.era.RaEditableRequestData;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Keeps localized information about an approval request.
 *
 * @version $Id: ApprovalRequestGUIInfo.java 28562 2018-03-27 14:07:49Z undulf $
 */
public class ApprovalRequestGUIInfo implements Serializable {

  private static final long serialVersionUID = 1L;
  /**
   * Logger.
   */
  private static final Logger LOG =
      Logger.getLogger(ApprovalRequestGUIInfo.class);

  public static final class ApprovalGuiObject {
      /** Param. */
    private final Approval approval;

    /**
     * @param aznapproval app
     */
    public ApprovalGuiObject(final Approval aznapproval) {
      this.approval = aznapproval;
    }

    /**
     * @return Date
     */
    public String getApprovalDate() {
      return ValidityDateUtil.formatAsISO8601(
          approval.getApprovalDate(), ValidityDateUtil.TIMEZONE_SERVER);
    }

    /**
     * @return Admin
     */
    public String getApprovalAdmin() {
      return approval.getAdmin().toString();
    }

    /**
     * @return Action
     */
    public String getAdminAction() {
      if (approval.isApproved()) {
        return "APPROVED";
      }
      return "REJECTED";
    }

    /**
     * @return Comment
     */
    public String getComment() {
      return approval.getComment();
    }
  }

  /** A display POJO for approval partitions. */
  public static final class ApprovalPartitionProfileGuiObject
      implements Serializable {
    private static final long serialVersionUID = 1L;

    /** Param. */
    private List<DynamicUiProperty<? extends Serializable>>
        profilePropertyList = null;

    /** Param. */
    private final int partitionId;
    /** Param. */
    private final int stepId;
    /** Param. */
    private final List<Approval> approvals;

    /**
     * @param astepId ID
     * @param apartitionId ID
     * @param propertyValues List
     * @param theapprovals List
     */
    public ApprovalPartitionProfileGuiObject(
        final int astepId,
        final int apartitionId,
        final List<DynamicUiProperty<? extends Serializable>> propertyValues,
        final List<Approval> theapprovals) {
      // Pass property values as a parameter because it may need some outside
      // poking
      setProfilePropertyList(propertyValues);
      this.stepId = astepId;
      this.partitionId = apartitionId;
      this.approvals = theapprovals;
    }

    /**
     * @return list
     */
    public List<DynamicUiProperty<? extends Serializable>>
        getProfilePropertyList() {
      return profilePropertyList;
    }

    /**
     * @param aprofilePropertyList list
     */
    public void setProfilePropertyList(
        final List<DynamicUiProperty<? extends Serializable>>
            aprofilePropertyList) {
      this.profilePropertyList = aprofilePropertyList;
    }

    /**
     * @return ID
     */
    public int getPartitionId() {
      return partitionId;
    }

    /**
     * @return ID
     */
    public int getStepId() {
      return stepId;
    }

    /**
     * @param property Property
     * @return the current multi-valued property's possible values as JSF
     *     friendly SelectItems.
     */
    public List<SelectItem /*<String,String>*/> getPropertyPossibleValues(
        final DynamicUiProperty<? extends Serializable> property) {
      final List<SelectItem> propertyPossibleValues = new ArrayList<>();
      if (profilePropertyList != null) {
        if (property != null && property.getPossibleValues() != null) {
          for (final Serializable possibleValue
              : property.getPossibleValues()) {
            propertyPossibleValues.add(
                new SelectItem(
                    property.getAsEncodedValue(
                        property.getType().cast(possibleValue)),
                    possibleValue.toString()));
          }
        }
      }
      return propertyPossibleValues;
    }

    /**
     * @return list
     */
    public List<Approval> getApprovals() {
      return this.approvals;
    }
  }

  public static final class StepOption implements Serializable {
    private static final long serialVersionUID = 1L;
    /** Param. */
    private final String name;
    /** Param. */
    private Object value;


    /**
     * @param aname name
     */
    public StepOption(final String aname) {
      this.name = aname;
    }

    /**
     * @return name
     */
    public String getName() {
      return name;
    }

    /**
     * @return val
     */
    public Object getValue() {
      return value;
    }

    /**
     * @param avalue val
     */
    public void setValue(final Object avalue) {
      this.value = avalue;
    }
  }

  /** Represents a step that has been approved. */
  public static final class Step implements Serializable {
    private static final long serialVersionUID = 1L;
    /** Param. */
    private final int stepId;
    /** Param. */
    private final Integer stepOrdinal;
    /** Param. */
    private final String headingText;
    /** Param. */
    private final List<ApprovalPartition> partitions;

    /**
     * @param stepInfo info
     * @param request req
     * @param raLocaleBean bean
     */
    public Step(
        final RaApprovalStepInfo stepInfo,
        final RaApprovalRequestInfo request,
        final RaLocaleBean raLocaleBean) {
      stepId = stepInfo.getStepId();
      final Map<Integer, Integer> stepToOrdinal =
          request.getStepIdToOrdinalMap();
      stepOrdinal = stepToOrdinal.get(stepId);
      headingText =
          raLocaleBean.getMessage("view_request_page_step", stepOrdinal);
      partitions = stepInfo.getPartitions();
    }

    /**
     * @return step
     */
    public int getStepId() {
      return stepId;
    }

    /**
     * @return step
     */
    public int getStepOrdinal() {
      if (stepOrdinal == null) {
        return 0;
      }
      return stepOrdinal;
    }

    /**
     * @return text
     */
    public String getHeadingText() {
      return headingText;
    }

    /**
     * @return list
     */
    public List<ApprovalPartition> getPartitions() {
      return partitions;
    }
  }

  public static final class RequestDataRow implements Serializable {
        /** Param. */
    private static final long serialVersionUID = 1L;
    /** Param. */
    private final ApprovalDataText approvalDataText;
    /** Param. */
    private final RaLocaleBean raLocaleBean;
    /** Param. */
    private final boolean editingSupported;
    /** Param. */
    private Object
        editValue; // TODO the column maps to a translation id. does it also map
                   // to something in the *ApprovalRequest data hashmap?

    /**

     * @param araLocaleBean bean
     * @param aapprovalDataText text
     * @param aneditingSupported bool
     * @param aneditValue val
     */
    public RequestDataRow(
        final RaLocaleBean araLocaleBean,
        final ApprovalDataText aapprovalDataText,
        final boolean aneditingSupported,
        final Object aneditValue) {
      this.approvalDataText = aapprovalDataText;
      this.raLocaleBean = araLocaleBean;
      this.editingSupported = aneditingSupported;
      this.editValue = aneditValue;
    }

    /**
     * @return Key
     */
    public String getKey() {
      return approvalDataText.getHeader();
    }

    /**
     * @return String
     */
    public String getHeader() {
      if (approvalDataText.isHeaderTranslateable()) {
        return raLocaleBean.getMessage(
            "view_request_page_data_header_" + approvalDataText.getHeader());
      } else {
        return approvalDataText.getHeader();
      }
    }

    /**
     * @return String
     */
    public String getData() {
      if (approvalDataText.isDataTranslatable()) {
        return raLocaleBean.getMessage(
            "view_request_page_data_value_" + approvalDataText.getData());
      } else {
        return approvalDataText.getData();
      }
    }

    /**
     * @return bool
     */
    public boolean isEditingSupported() {
      return editingSupported;
    }

    /**
     *
     * @return val
     */
    public Object getEditValue() {
      return editValue;
    }

    /**
     * @param aneditValue val
     */
    public void setEditValue(final Object aneditValue) {
      this.editValue = aneditValue;
    }
  }

  /** This field is package-internal so RaManageRequest(s)Bean can use it
  / internally. This class is specific to these beans. */
  final RaApprovalRequestInfo request;
  /** Param. */
  private final ApprovalDataVO approvalData;

  /** Param. */
  private final String requestDate;
  /** Param. */
  private final String requestExpireDate;
  /** Param. */
  private final String caName;
  /** Param. */
  private final String type;
  /** Param. */
  private final String requesterName;
  /** Param. */
  private final String displayName;
  /** Param. */
  private final String detail;
  /** Param. */
  private final String status;

  /** Param. */
  private final RaEndEntityDetails endEntityDetails;
  /** Param. */
  private final List<RequestDataRow> requestData;

  /** Param. */
  private final List<Step> previousSteps;

  /** Param. */
  private final List<String> editLogEntries;

  // Whether the current admin can approve this request
  /** Param. */
  private boolean canApprove;
  /** Param. */
  private boolean canEdit;
  /** Param. */
  private boolean canView;
  /** Param. */
  private final boolean authorizedToRequestType;

  /**
   *
   * @param arequest req
   * @param raLocaleBean bean
   * @param raAccessBean bean
   */
  public ApprovalRequestGUIInfo(
      final RaApprovalRequestInfo arequest,
      final RaLocaleBean raLocaleBean,
      final RaAccessBean raAccessBean) {
    this.request = arequest;
    approvalData = arequest.getApprovalData();

    // Determine what parts of the approval request are editable
    final EndEntityInformation endEntityInformation =
        getEndEntityInformation(); // editable
    boolean hasEditableData = (endEntityInformation != null);
    requestData = new ArrayList<>();
    if (arequest.getRequestData() != null && endEntityInformation == null) {
      final RaEditableRequestData editData = arequest.getEditableData();
      for (final ApprovalDataText dataText : arequest.getRequestData()) {
        boolean editingSupported = true;
        final Object editValue;
        switch (dataText.getHeader()) {
          case "SUBJECTDN":
            editValue = editData.getSubjectDN();
            break;
          case "SUBJECTALTNAME":
            editValue = editData.getSubjectAltName();
            break;
          case "SUBJECTDIRATTRIBUTES":
            if ("NOVALUE".equals(dataText.getData())) {
                continue;
            }
            editValue = editData.getSubjectDirAttrs();
            break;
          case "EMAIL":
            editValue = editData.getEmail();
            break;
            // Suppress some "no" or "none" values
          case "HARDTOKENISSUERALIAS":
          case "KEYRECOVERABLE":
          case "SENDNOTIFICATION":
            if ("NOVALUE".equals(dataText.getData())
                || "NO".equals(dataText.getData())) {
                continue;
            }
            // NOPMD: Fall through
          default:
            editingSupported = false;
            editValue = null;
        }
        if (editingSupported) {
          hasEditableData = true;
        }
        requestData.add(
            new RequestDataRow(
                raLocaleBean, dataText, editingSupported, editValue));
      }
    }

    requestDate =
        ValidityDateUtil.formatAsISO8601ServerTZ(
            approvalData.getRequestDate().getTime(), TimeZone.getDefault());
    requestExpireDate =
        ValidityDateUtil.formatAsISO8601ServerTZ(
            approvalData.getExpireDate().getTime(), TimeZone.getDefault());
    // These must be added last, so the "Extend" button appears under the
    // Expiration Date field.
    requestData.add(
        new RequestDataRow(
            raLocaleBean,
            new ApprovalDataText("REQUESTDATE", getRequestDate(), true, false),
            false,
            null));
    requestData.add(
        new RequestDataRow(
            raLocaleBean,
            new ApprovalDataText(
                "REQUESTEXPIRATIONDATE", getRequestExpireDate(), true, false),
            false,
            null));

    if (approvalData.getCAId() == ApprovalDataVO.ANY_CA) {
      caName = raLocaleBean.getMessage("manage_requests_no_ca");
    } else if (arequest.getCaName() == null) {
      caName = "Missing CA id " + approvalData.getCAId();
    } else {
      caName = arequest.getCaName();
    }

    if (endEntityInformation != null) {
      final EndEntityProfile endEntityProfile = arequest.getEndEntityProfile();
      final RaEndEntityDetails.Callbacks callbacks =
          new RaEndEntityDetails.Callbacks() {
            @Override
            public RaLocaleBean getRaLocaleBean() {
              return raLocaleBean;
            }

            @Override
            public EndEntityProfile getEndEntityProfile(final int eepId) {
              return endEntityProfile;
            }
          };
      endEntityDetails =
          new RaEndEntityDetails(
              getEndEntityInformation(),
              callbacks,
              arequest.getCertificateProfileName(),
              arequest.getEndEntityProfileName(),
              caName);
    } else {
      endEntityDetails = null;
    }

    final String reqSubjDN = arequest.getRequesterSubjectDN();
    if (reqSubjDN != null) {
      requesterName = getCNOrFallback(reqSubjDN, reqSubjDN);
    } else {
      requesterName = "";
    }

    switch (approvalData.getApprovalType()) {
      case ApprovalDataVO.APPROVALTYPE_ACTIVATECATOKEN:
        type =
            raLocaleBean.getMessage("manage_requests_type_activate_ca_token");
        break;
      case ApprovalDataVO.APPROVALTYPE_ADDENDENTITY:
        type = raLocaleBean.getMessage("manage_requests_type_add_end_entity");
        break;
      case ApprovalDataVO.APPROVALTYPE_CHANGESTATUSENDENTITY:
        type =
            raLocaleBean.getMessage(
                "manage_requests_type_change_status_end_entity");
        break;
      case ApprovalDataVO.APPROVALTYPE_EDITENDENTITY:
        type = raLocaleBean.getMessage("manage_requests_type_edit_end_entity");
        break;
      case ApprovalDataVO.APPROVALTYPE_KEYRECOVERY:
        type = raLocaleBean.getMessage("manage_requests_type_key_recovery");
        break;
      case ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY:
        type =
            raLocaleBean.getMessage(
                "manage_requests_type_revoke_and_delete_end_entity");
        break;
      case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE:
        type =
            raLocaleBean.getMessage("manage_requests_type_revoke_certificate");
        break;
      case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY:
        type =
            raLocaleBean.getMessage("manage_requests_type_revoke_end_entity");
        break;
      default:
        LOG.info(
            "Invalid/unsupported type of approval request: "
                + approvalData.getApprovalType());
        type = "???";
    }

    // Get username and subject DN if the request has this information
    String username = null;
    String subjectDN = null;
    if (endEntityInformation != null) {
      username = endEntityInformation.getUsername();
      subjectDN = endEntityInformation.getDN();
    }
    displayName = getCNOrFallback(subjectDN, username);
    detail = subjectDN;

    switch (arequest.getStatus()) {
      case ApprovalDataVO.STATUS_APPROVED:
        status = raLocaleBean.getMessage("manage_requests_status_approved");
        break;
      case ApprovalDataVO.STATUS_EXECUTED:
        status = raLocaleBean.getMessage("manage_requests_status_executed");
        break;
      case ApprovalDataVO.STATUS_EXECUTIONDENIED:
        status =
            raLocaleBean.getMessage("manage_requests_status_execution_denied");
        break;
      case ApprovalDataVO.STATUS_EXECUTIONFAILED:
        status =
            raLocaleBean.getMessage("manage_requests_status_execution_failed");
        break;
      case ApprovalDataVO.STATUS_EXPIRED:
        status = raLocaleBean.getMessage("manage_requests_status_expired");
        break;
      case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
        status =
            raLocaleBean.getMessage(
                "manage_requests_status_expired_and_notified");
        break;
      case ApprovalDataVO.STATUS_REJECTED:
        status = raLocaleBean.getMessage("manage_requests_status_rejected");
        break;
      case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
        status =
            raLocaleBean.getMessage(
                "manage_requests_status_waiting_for_approval");
        break;
      default:
        LOG.info("Invalid status of approval request: " + arequest.getStatus());
        status = "???";
    }

    editLogEntries = new ArrayList<>();
    for (final TimeAndAdmin entry : arequest.getEditedByAdmin()) {
      final String editDate =
       ValidityDateUtil.formatAsISO8601(entry.getDate(), TimeZone.getDefault());
      final String adminName;
      if (entry.getAdmin() instanceof X509CertificateAuthenticationToken) {
        final String adminDN =
            CertTools.getSubjectDN(
                ((X509CertificateAuthenticationToken) entry.getAdmin())
                    .getCertificate());
        adminName = getCNOrFallback(adminDN, adminDN);
      } else {
        adminName = entry.getAdmin().toString();
      }
      editLogEntries.add(
          raLocaleBean.getMessage(
              "view_request_page_edit_log_entry", editDate, adminName));
    }

    if (endEntityInformation != null
        || approvalData.getApprovalType()
            == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE
        || approvalData.getApprovalType()
            == ApprovalDataVO.APPROVALTYPE_KEYRECOVERY) {
      authorizedToRequestType =
          raAccessBean.isAuthorizedToApproveEndEntityRequests();
    } else {
      authorizedToRequestType = raAccessBean.isAuthorizedToApproveCARequests();
    }

    final ApprovalStep nextApprovalStep = arequest.getNextApprovalStep();
    // We can approve our own edits if allowed by approval profile
    boolean allowSelfEdit =
        arequest.getApprovalRequest().getApprovalProfile().getAllowSelfEdit();
    canApprove =
        nextApprovalStep != null
            && (!arequest.isEditedByMe() || allowSelfEdit)
            && !arequest.isApprovedByMe()
            && !arequest.isRequestedByMe()
            && authorizedToRequestType;
    // Can only edit our own requests, or requests that we could approve
    // irrespective of who made or edited them.
    canEdit =
        authorizedToRequestType
            && arequest.isEditable()
            && hasEditableData
            && (nextApprovalStep != null || isRequestedByMe());
    canView = arequest.isVisibleToMe();

    previousSteps = new ArrayList<>();
    for (final RaApprovalStepInfo stepInfo
       : arequest.getPreviousApprovalSteps()) {
      previousSteps.add(new Step(stepInfo, arequest, raLocaleBean));
    }
  }

  private String getCNOrFallback(
      final String subjectDN, final String fallback) {
    final String cn = CertTools.getPartFromDN(subjectDN, "CN");
    if (cn != null) {
      return cn;
    } else if (fallback != null) {
      return fallback;
    } else {
      return "";
    }
  }

  /**
   * @return ID
   */
  public String getId() {
    return String.valueOf(request.getId());
  }


  /**
   * @return Date
   */
  public String getRequestDate() {
    return requestDate;
  }

  /**
   * @return Date
   */
  public String getRequestExpireDate() {
    return requestExpireDate;
  }

  /**
   * @return CA
   */
  public String getCa() {
    return caName;
  }

  /**
   * @return type
   */
  public String getType() {
    return type;
  }

  /**
   * @return name
   */
  public String getRequesterName() {
    return requesterName;
  }

  /**
   * @return name
   */
  public String getDisplayName() {
    return displayName;
  }

  /**
   * @return detail
   */
  public String getDetail() {
    return detail;
  }

  /**
   * @return status
   */
  public String getStatus() {
    return status;
  }

  /**
   * @return info
   */
  public EndEntityInformation getEndEntityInformation() {
    final ApprovalRequest approvalRequest = request.getApprovalRequest();
    if (approvalRequest instanceof AddEndEntityApprovalRequest) {
      return ((AddEndEntityApprovalRequest) approvalRequest)
          .getEndEntityInformation();
    } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
      return ((EditEndEntityApprovalRequest) approvalRequest)
          .getNewEndEntityInformation();
    } else {
      return null;
    }
  }
  /**
   * @return bool
   */
  public RaEndEntityDetails getEndEntityDetails() {
    return endEntityDetails;
  }
  /**
   * @return bool
   */
  public List<RequestDataRow> getRequestData() {
    return requestData;
  }
  /**
   * @return bool
   */
  public List<String> getEditLogEntries() {
    return editLogEntries;
  }
  /**
   * @return bool
   */
  public List<Step> getPreviousSteps() {
    return previousSteps;
  }
  /**
   * @return bool
   */
  public int getStepCount() {
    return request.getStepCount();
  }
  /**
   * @return bool
   */
  public int getCurrentStepOrdinal() {
    return request.getCurrentStepOrdinal();
  }
  /**
   * @return bool
   */
  public boolean isCanApprove() {
    return canApprove;
  }
  /**
   * @return bool
   */
  public boolean isCanEdit() {
    return canEdit;
  }
  /**
   * @return bool
   */
  public boolean isCanView() {
    return canView;
  }
  /**
   * @return bool
   */
  public boolean isEditedByMe() {
    return request.isEditedByMe();
  }
  /**
   * @return bool
   */
  public boolean isRequestedByMe() {
    return request.isRequestedByMe();
  }
  /**
   * @return bool
   */
  public boolean isApprovedByMe() {
    return request.isApprovedByMe();
  }
  /**
   * @param admin bool
   * @return bool
   */
  public boolean isPending(final AuthenticationToken admin) {
    return request.isPending(admin);
  }
  /**
   * @return bool
   */
  public boolean isPendingExecution() {
    return request.getStatus()
        == ApprovalDataVO.STATUS_APPROVED; /* = approved but not executed */
  }
  /**
   * @return bool
   */
  public boolean isExecuted() {
    return request.getStatus() == ApprovalDataVO.STATUS_EXECUTED;
  }
  /**
   * @return bool
   */
  public boolean isSuccessful() {
    return isExecuted() || isPendingExecution();
  }
  /**
   * @return bool
   */
  public boolean isUnsuccessful() {
    return !isWaitingForApproval() && !isSuccessful();
  }
  /**
   * @return bool
   */
  public boolean isExecutionFailed() {
    return request.getStatus() == ApprovalDataVO.STATUS_EXECUTIONFAILED;
  }
  /**
   * @param admin token
   * @return bool
   */
  public boolean isWaitingForMe(final AuthenticationToken admin) {
    return request.isWaitingForMe(admin);
  }
  /**
   * @return bool
   */
  public boolean isWaitingForApproval() {
    return request.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
  }
  /**
   * @return bool
   */
  public boolean isExpired() {
    return request.getStatus() == ApprovalDataVO.STATUS_EXPIRED
        || request.getStatus() == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
  }
  /**
   * @return bool
   */
  public boolean hasNextApprovalStep() {
    return request.getNextApprovalStep() != null;
  }
  /**
   * @return bool
   */
  public boolean isAuthorizedToApprovalType() {
    return authorizedToRequestType;
  }

  /**
   * @return bool
   */
  public boolean getCanExtend() {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Checking if extension of request expiration is possible: Authorized="
              + isAuthorizedToApprovalType()
              + ", expired="
              + isExpired()
              + ", max extension time="
              + request.getMaxExtensionTime());
    }
    return isAuthorizedToApprovalType()
        && isExpired()
        && request.getMaxExtensionTime() != 0;
  }
}
