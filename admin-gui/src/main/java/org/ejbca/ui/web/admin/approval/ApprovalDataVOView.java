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

package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.ejb.EJBException;
import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.LinkView;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class representing the view of one ApprovalDataVO data.
 *
 * @version $Id: ApprovalDataVOView.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class ApprovalDataVOView implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(ApprovalDataVOView.class);
  /** Param. */
  private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
  /** Param. */
  private ApprovalDataVO data;

  // Table of the translation constants in languagefile.xx.properties
  /** Param. */
  private static final String CERTSERIALNUMBER = "CERTSERIALNUMBER";
  /** Param. */
  private static final String ISSUERDN = "ISSUERDN";
  /** Param. */
  private static final String USERNAME = "USERNAME";

  /**
   * @param thedata Data
   */
  public ApprovalDataVOView(final ApprovalDataVO thedata) {
    this.data = thedata;
  }


  /** Default. */
  public ApprovalDataVOView() { }

  /**
   * @return Date
   */
  public ApprovalRequest getApprovalRequest() {
    return data.getApprovalRequest();
  }

  /**
   * @return Date
   */
  public String getRequestDate() {
    return fastDateFormat(data.getRequestDate());
  }

  /**
   * @return Date
   */
  public String getExpireDate() {
    return fastDateFormat(data.getExpireDate());
  }

  private String fastDateFormat(final Date date) {
    return EjbcaJSFHelper.getBean().getEjbcaWebBean().formatAsISO8601(date);
  }

  /**
   * @return name
   */
  public String getCaName() {
    EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();
    if (data.getCAId() == ApprovalDataVO.ANY_CA) {
      return helpBean.getEjbcaWebBean().getText("ANYCA", true);
    }
    try {
      CAInfo caInfo =
          ejbLocalHelper
              .getCaSession()
              .getCAInfo(helpBean.getAdmin(), data.getCAId());
      if (caInfo != null) {
        return caInfo.getName();
      } else {
        LOG.error("Can not get CA with id: " + data.getCAId());
      }
    } catch (AuthorizationDeniedException e) {
      LOG.error("Can not get CA with id: " + data.getCAId(), e);
    }
    return "Error";
  }

  /**
   * @return Name
   */
  public String getEndEntityProfileName() {
    EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();
    if (data.getEndEntityProfileId() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
      return helpBean.getEjbcaWebBean().getText("ANYENDENTITYPROFILE", true);
    }
    return ejbLocalHelper
        .getEndEntityProfileSession()
        .getEndEntityProfileName(data.getEndEntityProfileId());
  }

  /**
   * @return Approvals
   */
  public String getRemainingApprovals() {
    return "" + data.getRemainingApprovals();
  }

  /**
   * @return Profile
   */
  public ApprovalProfile getApprovalProfile() {
    return data.getApprovalProfile();
  }

  /**
   * @return name
   */
  public String getApproveActionName() {
    return EjbcaJSFHelper.getBean()
        .getEjbcaWebBean()
        .getText(
            ApprovalDataVO.APPROVALTYPENAMES[
                data.getApprovalRequest().getApprovalType()],
            true);
  }

  /**
   * @return Name
   */
  public String getRequestAdminName() {
    String retval;
    final Certificate cert = data.getApprovalRequest().getRequestAdminCert();
    final AuthenticationToken reqAdmin =
        data.getApprovalRequest().getRequestAdmin();
    if (cert != null) {
      String dn = CertTools.getSubjectDN(cert);
      String o = CertTools.getPartFromDN(dn, "O");
      if (o == null) {
        o = "";
      } else {
        o = ", " + o;
      }
      retval = CertTools.getPartFromDN(dn, "CN") + o;
    } else {
      retval =
          EjbcaJSFHelper.getBean()
              .getEjbcaWebBean()
              .getText("CLITOOL", true); // Assume CLI if not match
      if (reqAdmin != null) {
        for (Principal principal : reqAdmin.getPrincipals()) {
          if (principal
              instanceof
              PublicAccessAuthenticationToken.PublicAccessPrincipal) {
            // Unauthenticated users accessing the RA
            retval =
                EjbcaJSFHelper.getBean()
                    .getEjbcaWebBean()
                    .getText("RAWEB", true);
            break;
          } else if (principal instanceof PublicWebPrincipal) {
            // Mostly self-registration in the Public Web
            final String ipAddress =
                ((PublicWebPrincipal) principal).getClientIPAddress();
            retval =
                EjbcaJSFHelper.getBean()
                        .getEjbcaWebBean()
                        .getText("PUBLICWEB", true)
                    + ": "
                    + ipAddress;
            break;
          } else if (principal instanceof WebPrincipal) {
            // Other things, such as CMP, etc. We probably shouldn't ever get
            // here, unless something is miss-configured.
            retval =
                principal.getName(); // e.g. "NameOfServlet: 198.51.100.123"
            break;
          }
        }
      }
    }
    LOG.debug("getRequestAdminName " + retval);
    return retval;
  }

  /**
   * @return Status
   */
  public String getStatus() {
    FacesContext context = FacesContext.getCurrentInstance();
    Application app = context.getApplication();
    ApproveActionManagedBean value =
        app.evaluateExpressionGet(
            context,
            "#{approvalActionManagedBean}",
            ApproveActionManagedBean.class);
    return value.getStatusText().get(Integer.valueOf(data.getStatus()));
  }

  /**
   * @return Data
   */
  public ApprovalDataVO getApproveActionDataVO() {
    return data;
  }

  /**
   * @return ID
   */
  public int getApprovalId() {
    return data.getApprovalId();
  }

  /**
   * Constructs JavaScript that opens up a new window and opens up actionview
   * there.
   *
   * @return JS
   */
  public String getApproveActionWindowLink() {
    String link =
        EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
            + EjbcaJSFHelper.getBean()
                .getEjbcaWebBean()
                .getGlobalConfiguration()
                .getAdminWebPath()
            + "approval/approveaction.jsf?uniqueId="
            + data.getId();
    return "window.open('"
        + link
        + "', 'ViewApproveAction',"
        + " 'width=1000,height=800,scrollbars=yes,"
        + "toolbar=no,resizable=yes').focus()";
  }

  /**
   * @return bool
   */
  public boolean getShowViewRequestorCertLink() {
    // Return true if there is a certificate
    return (data.getApprovalRequest().getRequestAdminCert() != null);
  }

  /**
   * @return link
   */
  public String getViewRequestorCertLink() {
    String retval = "";
    if (data.getApprovalRequest().getRequestAdminCert() != null) {
      String link;
      try {
        link =
            EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                + EjbcaJSFHelper.getBean()
                    .getEjbcaWebBean()
                    .getGlobalConfiguration()
                    .getAdminWebPath()
                + "viewcertificate.jsp?certsernoparameter="
                + java.net.URLEncoder.encode(
                    data.getReqadmincertsn()
                        + ","
                        + data.getReqadmincertissuerdn(),
                    "UTF-8");
      } catch (UnsupportedEncodingException e) {
        throw new EJBException(e);
      }
      retval = "viewcert('" + link + "')";
    }
    return retval;
  }

  /**
   * Detect all certificate and user links from approval data based on the
   * static translations variables.
   *
   * @return An array of Link-objects
   */
  public boolean isContainingLink() {
    final List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
    for (final ApprovalDataText row : newTextRows) {
      if (row.getHeader().equals(CERTSERIALNUMBER)
          || row.getHeader().equals(ISSUERDN)
          || row.getHeader().equals(USERNAME)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extract all certificate and user links from approval data based on the
   * static translations variables.
   *
   * @return An array of Link-objects
   */
  public List<LinkView> getApprovalDataLinks() {
    List<LinkView> certificateLinks = new ArrayList<>();
    List<String> certificateSerialNumbers = new ArrayList<>();
    List<String> certificateIssuerDN = new ArrayList<>();
    List<ApprovalDataText> newTextRows = getNewRequestDataAsText();

    for (final ApprovalDataText row : newTextRows) {
      if (row.getHeader().equals(CERTSERIALNUMBER)) {
        certificateSerialNumbers.add(row.getData());
      }
      if (row.getHeader().equals(ISSUERDN)) {
        certificateIssuerDN.add(row.getData());
      }
    }
    if (certificateIssuerDN.size() != certificateSerialNumbers.size()) {
      // Return an empty array if we have a mismatch
      return certificateLinks;
    }
    String link = null;
    for (int i = 0; i < certificateSerialNumbers.size(); i++) {
      try {
        link =
            EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                + EjbcaJSFHelper.getBean()
                    .getEjbcaWebBean()
                    .getGlobalConfiguration()
                    .getAdminWebPath()
                + "viewcertificate.jsp?certsernoparameter="
                + java.net.URLEncoder.encode(
                    certificateSerialNumbers.get(i)
                        + ","
                        + certificateIssuerDN.get(i),
                    "UTF-8");
      } catch (UnsupportedEncodingException e) {
        LOG.warn("UnsupportedEncoding creating approval data link. ", e);
      }
      certificateLinks.add(
          new LinkView(
              link,
              EjbcaJSFHelper.getBean()
                      .getEjbcaWebBean()
                      .getText(CERTSERIALNUMBER)
                  + ": ",
              certificateSerialNumbers.get(i),
              ""));
    }
    return certificateLinks;
  }

  /**
  * @return List
  */
  public List<TextComparisonView> getTextListExceptLinks() {
    ArrayList<TextComparisonView> textComparisonList = new ArrayList<>();
    List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
    for (final ApprovalDataText row : newTextRows) {
      if (row.getHeader().equals(CERTSERIALNUMBER)
          || row.getHeader().equals(ISSUERDN)) {
        continue;
      }
      String newString = "";
      try {
        newString = translateApprovalDataText(row);
      } catch (ArrayIndexOutOfBoundsException e) {
        // Do nothing orgstring should be "";
      }
      textComparisonList.add(new TextComparisonView(null, newString));
    }
    return textComparisonList;
  }

  /**
   * @return List
   */
  public List<TextComparisonView> getTextComparisonList() {
    ArrayList<TextComparisonView> textComparisonList = new ArrayList<>();
    if (data.getApprovalRequest().getApprovalRequestType()
        == ApprovalRequest.REQUESTTYPE_COMPARING) {
      List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
      List<ApprovalDataText> orgTextRows = getOldRequestDataAsText();
      int size = newTextRows.size();
      if (orgTextRows.size() > size) {
        size = orgTextRows.size();
      }
      for (int i = 0; i < size; i++) {
        String orgString = "";
        try {
          orgString = translateApprovalDataText(orgTextRows.get(i));
        } catch (IndexOutOfBoundsException e) {
          // Do nothing orgstring should be "";
        }
        String newString = "";
        try {
          newString = translateApprovalDataText(newTextRows.get(i));
        } catch (IndexOutOfBoundsException e) {
          // Do nothing orgstring should be "";
        }
        textComparisonList.add(new TextComparisonView(orgString, newString));
      }
    } else {
      for (ApprovalDataText approvalDataText : getNewRequestDataAsText()) {
        textComparisonList.add(
            new TextComparisonView(
                null, translateApprovalDataText(approvalDataText)));
      }
    }
    return textComparisonList;
  }

  private String translateApprovalDataText(final ApprovalDataText adata) {
    String retval = "";
    if (adata.isHeaderTranslateable()) {
      retval =
          EjbcaJSFHelper.getBean()
              .getEjbcaWebBean()
              .getText(adata.getHeader(), true);
    } else {
      retval = adata.getHeader();
    }
    if (adata.isDataTranslatable()) {
      retval +=
          " : "
              + EjbcaJSFHelper.getBean()
                  .getEjbcaWebBean()
                  .getText(adata.getData(), true);
    } else {
      retval += " : " + adata.getData();
    }
    return retval;
  }

  private List<ApprovalDataText> getNewRequestDataAsText() {
    ApprovalRequest approvalRequest = data.getApprovalRequest();
    AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    if (approvalRequest instanceof EditEndEntityApprovalRequest) {
      return ((EditEndEntityApprovalRequest) approvalRequest)
          .getNewRequestDataAsText(
              ejbLocalHelper.getCaSession(),
              ejbLocalHelper.getEndEntityProfileSession(),
              ejbLocalHelper.getCertificateProfileSession(),
              ejbLocalHelper.getHardTokenSession());
    } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
      return ((AddEndEntityApprovalRequest) approvalRequest)
          .getNewRequestDataAsText(
              ejbLocalHelper.getCaSession(),
              ejbLocalHelper.getEndEntityProfileSession(),
              ejbLocalHelper.getCertificateProfileSession(),
              ejbLocalHelper.getHardTokenSession());
    } else {
      return approvalRequest.getNewRequestDataAsText(admin);
    }
  }

  private List<ApprovalDataText> getOldRequestDataAsText() {
    ApprovalRequest approvalRequest = data.getApprovalRequest();
    AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    if (approvalRequest instanceof EditEndEntityApprovalRequest) {
      return ((EditEndEntityApprovalRequest) approvalRequest)
          .getOldRequestDataAsText(
              admin,
              ejbLocalHelper.getCaSession(),
              ejbLocalHelper.getEndEntityProfileSession(),
              ejbLocalHelper.getCertificateProfileSession(),
              ejbLocalHelper.getHardTokenSession());
    } else {
      return approvalRequest.getOldRequestDataAsText(admin);
    }
  }
}
