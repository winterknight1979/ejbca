/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.acme;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.AcmeConfiguration;
import org.ejbca.config.GlobalAcmeConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing ACME configuration.
 *
 * @version $Id: AcmeConfigMBean.java 28125 2018-01-29 16:41:28Z bastianf $
 */
public class AcmeConfigMBean extends BaseManagedBean implements Serializable {
  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(AcmeConfigMBean.class);
  /** Param. */
  private ListDataModel<AcmeAliasGuiInfo> aliasGuiList = null;

  /** Param. */
  private GlobalAcmeConfiguration globalAcmeConfigurationConfig;
  /** Param. */
  private AcmeAliasGuiInfo currentAlias = null;
  /** Param. */
  private AcmeGlobalGuiInfo globalInfo = null;
  /** Param. */
  private boolean currentAliasEditMode = false;
  /** Param. */
  private String currentAliasStr;
  /** Param. */
  private String newAlias = "";

  /** Param. */
  private final GlobalConfigurationSessionLocal globalConfigSession =
      getEjbcaWebBean().getEjb().getGlobalConfigurationSession();
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession =
      getEjbcaWebBean().getEjb().getAuthorizationSession();
  /** Param. */
  private final EndEntityProfileSessionLocal endentityProfileSession =
      getEjbcaWebBean().getEjb().getEndEntityProfileSession();
  /** Param. */
  private final AuthenticationToken authenticationToken = getAdmin();

  /** Constructor. */
  public AcmeConfigMBean() {
    super();
    globalAcmeConfigurationConfig =
        (GlobalAcmeConfiguration)
            globalConfigSession.getCachedConfiguration(
                GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
  }

  /**
   * Force reload from underlying (cache) layer for the current ACME
   * configuration alias.
   */
  private void flushCache() {
    currentAlias = null;
    aliasGuiList = null;
    currentAliasEditMode = false;
    globalAcmeConfigurationConfig =
        (GlobalAcmeConfiguration)
            globalConfigSession.getCachedConfiguration(
                GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
    globalInfo = new AcmeGlobalGuiInfo(globalAcmeConfigurationConfig);
  }
  /**
   * Build a list sorted by name from the existing ACME configuration aliases.
   *
   * @return Model
   */
  public ListDataModel<AcmeAliasGuiInfo> getAliasGuiList() {
    flushCache();
    final List<AcmeAliasGuiInfo> list = new ArrayList<>();
    for (String alias
        : globalAcmeConfigurationConfig.getAcmeConfigurationIds()) {
      list.add(new AcmeAliasGuiInfo(globalAcmeConfigurationConfig, alias));
      Collections.sort(
          list,
          new Comparator<AcmeAliasGuiInfo>() {
            @Override
            public int compare(
                final AcmeAliasGuiInfo alias1, final AcmeAliasGuiInfo alias2) {
              return alias1.getAlias().compareToIgnoreCase(alias2.getAlias());
            }
          });
      aliasGuiList = new ListDataModel<>(list);
    }
    // If show the list, then we are on the main page and want to flush the
    // cache
    currentAlias = null;
    return aliasGuiList;
  }

  /** Add. */
  public void addAlias() {
    if (StringUtils.isNotEmpty(newAlias)
        && !globalAcmeConfigurationConfig.aliasExists(newAlias)) {
      AcmeConfiguration newConfig = new AcmeConfiguration();
      newConfig.setConfigurationId(newAlias);
      newConfig.initialize(newAlias);
      globalAcmeConfigurationConfig.updateAcmeConfiguration(newConfig);
      try {
        globalConfigSession.saveConfiguration(
            authenticationToken, globalAcmeConfigurationConfig);
      } catch (AuthorizationDeniedException e) {
        String msg = "Failed to add alias: " + e.getLocalizedMessage();
        LOG.info(msg, e);
        super.addNonTranslatedErrorMessage(msg);
      }
    } else {
      String msg = "Cannot add alias. Alias '" + newAlias + "' already exists.";
      LOG.info(msg);
      super.addNonTranslatedErrorMessage(msg);
    }
    flushCache();
  }

  /** Rename. */
  public void renameAlias() {
    if (StringUtils.isNotEmpty(newAlias)
        && !globalAcmeConfigurationConfig.aliasExists(newAlias)) {
      globalAcmeConfigurationConfig.renameConfigId(newAlias, currentAliasStr);
      try {
        globalConfigSession.saveConfiguration(
            authenticationToken, globalAcmeConfigurationConfig);
      } catch (AuthorizationDeniedException e) {
        String msg = "Failed to rename alias: " + e.getLocalizedMessage();
        LOG.info(msg, e);
        super.addNonTranslatedErrorMessage(msg);
      }
    } else {
      String msg =
          "Cannot rename alias. Either the new alias is empty or it already"
              + " exists.";
      LOG.info(msg);
      super.addNonTranslatedErrorMessage(msg);
    }
    flushCache();
  }

  /** Delete. */
  public void deleteAlias() {
    if (globalAcmeConfigurationConfig.aliasExists(currentAliasStr)) {
      globalAcmeConfigurationConfig.removeConfigId(currentAliasStr);
      try {
        globalConfigSession.saveConfiguration(
            authenticationToken, globalAcmeConfigurationConfig);
      } catch (AuthorizationDeniedException e) {
        String msg = "Failed to remove alias: " + e.getLocalizedMessage();
        LOG.info(msg, e);
        super.addNonTranslatedErrorMessage(msg);
      }
    } else {
      String msg = "Cannot remove alias. It does not exist.";
      LOG.info(msg);
      super.addNonTranslatedErrorMessage(msg);
    }
    flushCache();
  }

  /**
   * @return cached or populate a new ACME alias GUI representation for view or
   *     edit
   */
  public AcmeAliasGuiInfo getCurrentAlias() {
    if (this.currentAlias == null) {
      final String alias = getCurrentAliasStr();
      this.currentAlias =
          new AcmeAliasGuiInfo(globalAcmeConfigurationConfig, alias);
    }

    return this.currentAlias;
  }

  /**
   * @return Alias
   */
  public String getNewAlias() {
    return newAlias;
  }

  /**
   * @param anewAlias Alias
   */
  public void setNewAlias(final String anewAlias) {
    this.newAlias = anewAlias;
  }

  /** @return the name of the ACME alias that is subject to view or edit */
  public String getCurrentAliasStr() {
    // Get the HTTP GET/POST parameter named "alias"
    final String inputAlias =
        FacesContext.getCurrentInstance()
            .getExternalContext()
            .getRequestParameterMap()
            .get("alias");
    if (inputAlias != null && inputAlias.length() > 0) {
      if (!inputAlias.equals(currentAliasStr)) {
        flushCache();
        this.currentAliasStr = inputAlias;
      }
    }
    return currentAliasStr;
  }

  /**
   * @return a list of EndEntity profiles that this admin is authorized to, and
   *     that are usable for ACME
   */
  public List<SelectItem> getUsableEEProfileNames() {
    Collection<Integer> endEntityProfileIds =
        endentityProfileSession.getAuthorizedEndEntityProfileIds(
            getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
    Map<Integer, String> nameMap =
        endentityProfileSession.getEndEntityProfileIdToNameMap();
    final List<SelectItem> ret = new ArrayList<>();
    for (Integer id : endEntityProfileIds) {
      if (id != EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
        String name = nameMap.get(id);
        ret.add(new SelectItem(id, name));
      }
    }
    sortSelectItemsByLabel(ret);
    return ret;
  }

  /**
   * Returns an information text to show below the End Entity Profile selection.
   *
   * @return String
   */
  public String getDefaultCaText() {
    if (getUsableEEProfileNames().isEmpty()) {
      return getEjbcaWebBean().getText("ACME_MUST_HAVE_ONE_PROFILE");
    } else {
      return getEjbcaWebBean().getText("ACME_DEFAULT_CA_WILL_BE_USED");
    }
  }

  /**
   * @return Items
   */
  public List<SelectItem> getAliasSeletItemList() {
    final List<SelectItem> ret = new ArrayList<>();
    for (String alias
        : globalAcmeConfigurationConfig.getAcmeConfigurationIds()) {
      ret.add(new SelectItem(alias, alias));
    }
    return ret;
  }

  /** Invoked when admin cancels a ACME alias create or edit. */
  public void cancelCurrentAlias() {
    flushCache();
  }

  /**
   * Invoked when admin saves the ACME alias configurations.
   *
   * @throws EjbcaException On fail
   */
  public void saveCurrentAlias() throws EjbcaException {
    if (currentAlias != null) {
      AcmeConfiguration acmeConfig =
          globalAcmeConfigurationConfig.getAcmeConfiguration(currentAliasStr);
      acmeConfig.setEndEntityProfileId(
          Integer.valueOf(currentAlias.endEntityProfileId));
      acmeConfig.setPreAuthorizationAllowed(
          currentAlias.isPreAuthorizationAllowed());
      acmeConfig.setRequireExternalAccountBinding(
          currentAlias.isRequireExternalAccountBinding());
      acmeConfig.setWildcardCertificateIssuanceAllowed(
          currentAlias.isWildcardCertificateIssuanceAllowed());
      acmeConfig.setWebSiteUrl(currentAlias.getUrlTemplate());
      acmeConfig.setDnsResolver(currentAlias.getDnsResolver());
      acmeConfig.setDnsPort(currentAlias.getDnsPort());
      acmeConfig.setDnssecTrustAnchor(currentAlias.getDnssecTrustAnchor());
      acmeConfig.setUseDnsSecValidation(currentAlias.isUseDnsSecValidation());
      acmeConfig.setTermsOfServiceRequireNewApproval(
          currentAlias.getTermsOfServiceApproval());
      acmeConfig.setTermsOfServiceUrl(currentAlias.getTermsOfServiceUrl());

      if (StringUtils.isEmpty(acmeConfig.getTermsOfServiceUrl())) {
        throw new EjbcaException("Please enter Terms of Service URL");
      }

      globalAcmeConfigurationConfig.updateAcmeConfiguration(acmeConfig);
      try {
        globalConfigSession.saveConfiguration(
            authenticationToken, globalAcmeConfigurationConfig);
      } catch (AuthorizationDeniedException e) {
        String msg = "Cannot save alias. Administrator is not authorized.";
        LOG.info(msg + e.getLocalizedMessage());
        super.addNonTranslatedErrorMessage(msg);
      }
    }
    flushCache();
  }

  /**
   * @return Bool
   */
  public boolean isSaveCurrentAliasDisabled() {
    return getUsableEEProfileNames().isEmpty();
  }

  /** Save. */
  public void saveGlobalConfigs() {
    globalAcmeConfigurationConfig.setDefaultAcmeConfigurationId(
        globalInfo.getDefaultAcmeConfiguration());
    globalAcmeConfigurationConfig.setReplayNonceValidity(
        Long.valueOf(globalInfo.getReplayNonceValidity()));
    try {
      globalConfigSession.saveConfiguration(
          authenticationToken, globalAcmeConfigurationConfig);
    } catch (AuthorizationDeniedException e) {
      String msg =
          "Cannot save ACME configurations. Administrator is not authorized.";
      LOG.info(msg + e.getLocalizedMessage());
      super.addNonTranslatedErrorMessage(msg);
    }
  }

  /**
   * @param acurrentAliasStr Alias
   */
  public void setCurrentAliasStr(final String acurrentAliasStr) {
    this.currentAliasStr = acurrentAliasStr;
  }

  /**
   * @return Bool
   */
  public boolean isCurrentAliasEditMode() {
    return currentAliasEditMode;
  }

  /**
   * @param acurrentAliasEditMode Bool
   */
  public void setCurrentAliasEditMode(final boolean acurrentAliasEditMode) {
    this.currentAliasEditMode = acurrentAliasEditMode && isAllowedToEdit();
  }

  /** Yoggle. */
  public void toggleCurrentAliasEditMode() {
    currentAliasEditMode ^= true;
    currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
  }

  /**
   * @return Bool
   */
  public boolean isAllowedToEdit() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
  }

  /**
   * @return Bool
   */
  public AcmeGlobalGuiInfo getGlobalInfo() {
    return globalInfo;
  }

  /**
   * @param aglobalInfo Info
   */
  public void setGlobalInfo(final AcmeGlobalGuiInfo aglobalInfo) {
    this.globalInfo = aglobalInfo;
  }

  public class AcmeAliasGuiInfo {
        /** Param. */
    private String alias;
    /** Param. */
    private String endEntityProfileId;
    /** Param. */
    private boolean preAuthorizationAllowed;
    /** Param. */
    private boolean requireExternalAccountBinding;
    /** Param. */
    private String urlTemplate;
    /** Param. */
    private boolean wildcardCertificateIssuanceAllowed;
    /** Param. */
    private String dnsResolver;
    /** Param. */
    private int dnsPort;
    /** Param. */
    private String dnssecTrustAnchor;
    /** Param. */
    private String termsOfServiceUrl;
    /** Param. */
    private boolean termsOfServiceApproval;
    /** Param. */
    private boolean useDnsSecValidation;

    /**
     * @param aglobalAcmeConfigurationConfig Config
     * @param analias Alias
     */
    public AcmeAliasGuiInfo(
        final GlobalAcmeConfiguration aglobalAcmeConfigurationConfig,
        final String analias) {
      if (analias != null) {
        this.alias = analias;
        AcmeConfiguration acmeConfiguration =
            aglobalAcmeConfigurationConfig.getAcmeConfiguration(analias);
        if (acmeConfiguration != null) {
          this.endEntityProfileId =
              String.valueOf(acmeConfiguration.getEndEntityProfileId());
          this.preAuthorizationAllowed =
              acmeConfiguration.isPreAuthorizationAllowed();
          this.requireExternalAccountBinding =
              acmeConfiguration.isRequireExternalAccountBinding();
          this.urlTemplate = acmeConfiguration.getWebSiteUrl();
          this.wildcardCertificateIssuanceAllowed =
              acmeConfiguration.isWildcardCertificateIssuanceAllowed();
          this.dnsResolver = acmeConfiguration.getDnsResolver();
          this.dnsPort = acmeConfiguration.getDnsPort();
          this.dnssecTrustAnchor = acmeConfiguration.getDnssecTrustAnchor();
          this.termsOfServiceUrl =
              String.valueOf(acmeConfiguration.getTermsOfServiceUrl());
          this.useDnsSecValidation = acmeConfiguration.isUseDnsSecValidation();
          this.termsOfServiceApproval =
              acmeConfiguration.isTermsOfServiceRequireNewApproval();
        }
      }
    }

    /**
     * @return Alias
     */
    public String getAlias() {
      return alias;
    }

    /**
     * @param analias Alias
     */
    public void setAlias(final String analias) {
      this.alias = analias;
    }

    /**
     * @return Profile
     */
    public String getEndEntityProfileId() {
      return endEntityProfileId;
    }

    /**
     * @param anendEntityProfileId Profile
     */
    public void setEndEntityProfileId(final String anendEntityProfileId) {
      this.endEntityProfileId = anendEntityProfileId;
    }

    /**
     * @return Bool
     */
    public boolean isPreAuthorizationAllowed() {
      return preAuthorizationAllowed;
    }

    /**
     * @param apreAuthorizationAllowed Bool
     */
    public void setPreAuthorizationAllowed(
        final boolean apreAuthorizationAllowed) {
      this.preAuthorizationAllowed = apreAuthorizationAllowed;
    }

    /**
     * @return Bool
     */
    public boolean isRequireExternalAccountBinding() {
      return requireExternalAccountBinding;
    }

    /**
     * @param arequireExternalAccountBinding Bool
     */
    public void setRequireExternalAccountBinding(
        final boolean arequireExternalAccountBinding) {
      this.requireExternalAccountBinding = arequireExternalAccountBinding;
    }

    /**
     * @return URL
     */
    public String getUrlTemplate() {
      return urlTemplate;
    }

    /**
     * @param aurlTemplate URL
     */
    public void setUrlTemplate(final String aurlTemplate) {
      this.urlTemplate = aurlTemplate;
    }

    /**
     * @return Bool
     */
    public boolean isWildcardCertificateIssuanceAllowed() {
      return wildcardCertificateIssuanceAllowed;
    }

    /**
     * @param awildcardCertificateIssuanceAllowed Bool
     */
    public void setWildcardCertificateIssuanceAllowed(
        final boolean awildcardCertificateIssuanceAllowed) {
      this.wildcardCertificateIssuanceAllowed =
          awildcardCertificateIssuanceAllowed;
    }

    /**
     * @return Anchor
     */
    public String getDnssecTrustAnchor() {
      return dnssecTrustAnchor;
    }

    /**
     * @param adnssecTrustAnchor Anchor
     */
    public void setDnssecTrustAnchor(final String adnssecTrustAnchor) {
      this.dnssecTrustAnchor = adnssecTrustAnchor;
    }

    /**
     * @return Resolver
     */
    public String getDnsResolver() {
      return dnsResolver;
    }

    /**
     * @param adnsResolver Resolver
     */
    public void setDnsResolver(final String adnsResolver) {
      this.dnsResolver = adnsResolver;
    }

    /**
     * @return port
     */
    public int getDnsPort() {
      return dnsPort;
    }

    /**
     * @param adnsPort Port
     */
    public void setDnsPort(final int adnsPort) {
      this.dnsPort = adnsPort;
    }

    /**
     * @return URL
     */
    public String getTermsOfServiceUrl() {
      return termsOfServiceUrl;
    }


    /**
     * @param atermsOfServiceUrl URL
     */
    public void setTermsOfServiceUrl(final String atermsOfServiceUrl) {
      this.termsOfServiceUrl = atermsOfServiceUrl;
    }

    /**
     * @return bool
     */
    public boolean getTermsOfServiceApproval() {
      return termsOfServiceApproval;
    }

    /**
     * @param atermsOfServiceApproval bool
     */
    public void setTermsOfServiceApproval(
        final boolean atermsOfServiceApproval) {
      this.termsOfServiceApproval = atermsOfServiceApproval;
    }

    /**
     * @return Bool
     */
    public boolean isUseDnsSecValidation() {
      return useDnsSecValidation;
    }

    /**
     * @param auseDnsSecValidation bool
     */
    public void setUseDnsSecValidation(final boolean auseDnsSecValidation) {
      this.useDnsSecValidation = auseDnsSecValidation;
    }
  }

  public class AcmeGlobalGuiInfo {
        /** Param. */
    private String defaultAcmeConfiguration;
    /** Param. */
    private String replayNonceValidity;

    /**
     * @param aglobalAcmeConfigurationConfig Config
     */
    public AcmeGlobalGuiInfo(
        final GlobalAcmeConfiguration aglobalAcmeConfigurationConfig) {
      this.defaultAcmeConfiguration =
          aglobalAcmeConfigurationConfig.getDefaultAcmeConfigurationId();
      this.replayNonceValidity =
          String.valueOf(
              aglobalAcmeConfigurationConfig.getReplayNonceValidity());
    }

    /**
     * @return Vonfig */
    public String getDefaultAcmeConfiguration() {
      return defaultAcmeConfiguration;
    }

    /**
     * @param adefaultAcmeConfiguration Config
     */
    public void setDefaultAcmeConfiguration(
        final String adefaultAcmeConfiguration) {
      this.defaultAcmeConfiguration = adefaultAcmeConfiguration;
    }

    /**
     * @return Validity
     */
    public String getReplayNonceValidity() {
      return replayNonceValidity;
    }

    /**
     * @param areplayNonceValidity validity
     */
    public void setReplayNonceValidity(final String areplayNonceValidity) {
      this.replayNonceValidity = areplayNonceValidity;
    }
  }
}
