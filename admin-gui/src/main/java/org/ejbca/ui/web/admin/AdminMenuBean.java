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
package org.ejbca.ui.web.admin;

import java.io.Serializable;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.RequestScoped;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Backing bean for the menu on the left (in the default theme) in the AdminWeb.
 *
 * @version $Id: AdminMenuBean.java 30655 2018-11-28 08:58:52Z aminkh $ TODO:
 *     Switch to CDI
 */
@SuppressWarnings("deprecation")
@RequestScoped
@ManagedBean
public class AdminMenuBean extends BaseManagedBean implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** Param. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;

  /**
   * @return config
   */
  private GlobalConfiguration getGlobalConfiguration() {
    return (GlobalConfiguration)
        globalConfigurationSession.getCachedConfiguration(
            GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
  }

  /*===CA FUNCTIONS===*/
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewCA() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.CAVIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewCertificateProfile() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.CERTIFICATEPROFILEVIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewCryptotoken() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), CryptoTokenRules.VIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewPublishers() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_VIEWPUBLISHER);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewValidators() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_VIEWVALIDATOR);
  }

  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewCAHeader() {
    return isAuthorizedToViewCA()
        || isAuthorizedToViewCertificateProfile()
        || isAuthorizedToViewCryptotoken()
        || isAuthorizedToViewPublishers()
        || isAuthorizedToViewValidators();
  }

  /*===RA FUNCTIONS===*/
  /**
   * @return Bool
   */
  public boolean isAuthorizedToCreateEndEntity() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_CREATEENDENTITY);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewEndEntityProfiles() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewEndEntity() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITY);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToEditUserDataSources() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.REGULAR_EDITUSERDATASOURCES);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewRAHeader() {
    return isAuthorizedToCreateEndEntity()
        || isAuthorizedToViewEndEntityProfiles()
        || isAuthorizedToViewEndEntity()
        || isAuthorizedToEditUserDataSources();
  }

  /*===HARD TOKEN FUNCTIONALITY===*/
  /**
   * @return Bool
   */
  public boolean isAuthorizedToEditHardTokenIssuers() {
    return getGlobalConfiguration().getIssueHardwareTokens()
        && authorizationSession.isAuthorizedNoLogging(
            getAdmin(), "/hardtoken_functionality/edit_hardtoken_issuers");
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToEditHardTokenProfiles() {
    return getGlobalConfiguration().getIssueHardwareTokens()
        && authorizationSession.isAuthorizedNoLogging(
            getAdmin(), "/hardtoken_functionality/edit_hardtoken_profiles");
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewHTHeader() {
    return getGlobalConfiguration().getIssueHardwareTokens()
        && (isAuthorizedToEditHardTokenIssuers()
            || isAuthorizedToEditHardTokenProfiles());
  }

  /*===SUPERVISION FUNCTIONS===*/
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewApprovalProfiles() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.APPROVALPROFILEVIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToApproveActions() {
    return authorizationSession.isAuthorizedNoLogging(
            getAdmin(), AccessRulesConstants.REGULAR_APPROVEENDENTITY)
        || authorizationSession.isAuthorizedNoLogging(
            getAdmin(), AccessRulesConstants.REGULAR_APPROVECAACTION);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewLog() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AuditLogRules.VIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewSupervisionFunctionsHeader() {
    return isAuthorizedToViewApprovalProfiles()
        || isAuthorizedToApproveActions()
        || isAuthorizedToViewLog();
  }

  /*===SYSTEM FUNCTIONS===*/
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewRoles() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.VIEWROLES.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedViewInternalKeyBindings() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), InternalKeyBindingRules.VIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewPeerConnectors() {
    return getEjbcaWebBean().isPeerConnectorPresent()
        && authorizationSession.isAuthorizedNoLogging(
            getAdmin(), AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewServices() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.SERVICES_VIEW);
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewSystemFunctionsHeader() {
    return isAuthorizedToViewRoles()
        || isAuthorizedViewInternalKeyBindings()
        || isAuthorizedToViewPeerConnectors()
        || isAuthorizedToViewServices();
  }

  /*===SYSTEM CONFIGURATION===*/
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewSystemConfiguration() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
  }

  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewEstConfiguration() {
    return getEjbcaWebBean().isRunningEnterprise()
        && isAuthorizedToViewSystemConfiguration();
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewAcmeConfiguration() {
    return getEjbcaWebBean().isRunningEnterprise()
        && isAuthorizedToViewSystemConfiguration();
  }
  /**
   * @return Bool
   */
  public boolean isAuthorizedToConfigureSystem() {
    return authorizationSession.isAuthorizedNoLogging(
            getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())
        || authorizationSession.isAuthorizedNoLogging(
            getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource())
        || authorizationSession.isAuthorizedNoLogging(
            getAdmin(),
            StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource());
  }
  /**
   * @return Bool
   */
  public boolean isUpgradeRequired() {
    return EjbcaJSFHelper.getBean().getEjbcaWebBean().isPostUpgradeRequired();
  }

  /**
   * @return Bool
   */
  public boolean isAuthorizedToViewSystemConfigurationHeader() {
    return isAuthorizedToViewSystemConfiguration()
        || isAuthorizedToViewEstConfiguration()
        || isAuthorizedToConfigureSystem()
        || isUpgradeRequired();
  }

  /*===OTHER===*/

  /**
   * @return Bool
   */
  public boolean isAuthorizedToEditPreferences() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), AccessRulesConstants.ROLE_ADMINISTRATOR);
  }

  /**
   * @return Bool
   */
  public boolean isHelpEnabled() {
    return EjbcaJSFHelper.getBean().getEjbcaWebBean().isHelpEnabled();
  }

  /**
   * @return URL
   */
  public String getHeadBannerUrl() {
    return EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
        + getGlobalConfiguration().getHeadBanner();
  }

  /**
   * @return Bool
   */
  public boolean isNonDefaultHeadBanner() {
    return getGlobalConfiguration().isNonDefaultHeadBanner();
  }

  /**
   * @return Name
   */
  public String getAppNameCapital() {
    return InternalConfiguration.getAppNameCapital();
  }

  /**
   * @return URL
   */
  public String getLogoUrl() {
    return getEjbcaWebBean()
        .getImagefileInfix(
            "banner_" + InternalConfiguration.getAppNameLower() + "-admin.png");
  }

  /**
   * @return URL
   */
  public String getAdminWebUrl() {
    return getEjbcaWebBean().getBaseUrl()
        + getGlobalConfiguration().getAdminWebPath();
  }
}
