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
package org.ejbca.ui.web.admin.configuration;

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
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing SCEP configuration.
 *
 * @version $Id: ScepConfigMBean.java 28125 2018-01-29 16:41:28Z bastianf $
 */
public class ScepConfigMBean extends BaseManagedBean implements Serializable {

  /** GUI table representation of a SCEP alias that can be interacted with. */
  public final class ScepAliasGuiInfo {
        /** Param. */
    private String alias;
    /** Param. */
    private String mode;
    /** Param. */
    private boolean includeCA;
    /** Param. */
    private String raCertProfile;
    /** Param. */
    private String raEEProfile;
    /** Param. */
    private String raAuthPassword;
    /** Param. */
    private String raDefaultCA;
    /** Param. */
    private String raNameGenScheme;
    /** Param. */
    private String raNameGenParameters;
    /** Param. */
    private String raNameGenPrefix;
    /** Param. */
    private String raNameGenPostfix;
    /** Param. */
    private boolean clientCertificateRenewal;
    /** Param. */
    private boolean allowClientCertificateRenewaWithOldKey;

    private ScepAliasGuiInfo(
        final ScepConfiguration ascepConfig, final String analias) {
      if (analias != null) {
        this.alias = analias;
        if (ascepConfig.aliasExists(analias)) {
          this.mode =
              (ascepConfig.getRAMode(analias)
                  ? ScepConfiguration.Mode.RA.getResource()
                  : ScepConfiguration.Mode.CA.getResource());
          this.includeCA = ascepConfig.getIncludeCA(analias);
          this.raCertProfile = ascepConfig.getRACertProfile(analias);
          this.raEEProfile = ascepConfig.getRAEndEntityProfile(analias);
          this.raAuthPassword = ascepConfig.getRAAuthPassword(analias);
          this.raDefaultCA = ascepConfig.getRADefaultCA(analias);
          this.raNameGenScheme = ascepConfig.getRANameGenerationScheme(analias);
          this.raNameGenParameters =
              ascepConfig.getRANameGenerationParameters(analias);
          this.raNameGenPrefix = ascepConfig.getRANameGenerationPrefix(analias);
          this.raNameGenPostfix
              = ascepConfig.getRANameGenerationPostfix(analias);
          this.clientCertificateRenewal =
              ascepConfig.getClientCertificateRenewal(analias);
          this.allowClientCertificateRenewaWithOldKey =
              ascepConfig.getAllowClientCertificateRenewalWithOldKey(analias);
        } else {
          this.mode = ScepConfiguration.DEFAULT_OPERATION_MODE.toUpperCase();
          this.includeCA =
              Boolean.valueOf(ScepConfiguration.DEFAULT_INCLUDE_CA);
          this.raCertProfile = ScepConfiguration.DEFAULT_RA_CERTPROFILE;
          this.raEEProfile = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
          this.raAuthPassword = ScepConfiguration.DEFAULT_RA_AUTHPWD;
          this.raDefaultCA = ScepConfiguration.DEFAULT_RA_DEFAULTCA;
          this.raNameGenScheme =
              ScepConfiguration.DEFAULT_RA_NAME_GENERATION_SCHEME;
          this.raNameGenParameters =
              ScepConfiguration.DEFAULT_RA_NAME_GENERATION_PARAMETERS;
          this.raNameGenPrefix =
              ScepConfiguration.DEFAULT_RA_NAME_GENERATION_PREFIX;
          this.raNameGenPostfix =
              ScepConfiguration.DEFAULT_RA_NAME_GENERATION_POSTFIX;
          this.clientCertificateRenewal =
              Boolean.valueOf(
                  ScepConfiguration.DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
          this.allowClientCertificateRenewaWithOldKey =
              Boolean.valueOf(
                  ScepConfiguration
                      .DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
        }
      }
    }

    /**
     * @return alias
     */
    public String getAlias() {
      return alias;
    }

    /**
     * @param analias alias
     */
    public void setAlias(final String analias) {
      this.alias = analias;
    }

    /**
     * @return mode
     */
    public String getMode() {
      return mode;
    }

    /**
     * @param amode mode
     */
    public void setMode(final String amode) {
      this.mode = amode;
    }

    /**
     * @return Bool
     */
    public boolean isModeRa() {
      return ScepConfiguration.Mode.RA.getResource().equals(mode);
    }

    /**
     * @return CA
     */
    public boolean isModeCa() {
      return ScepConfiguration.Mode.CA.getResource().equals(mode);
    }

    /**
     * @return CA
     */
    public boolean isIncludeCA() {
      return includeCA;
    }

    /**
     * @param includeca CA
     */
    public void setIncludeCA(final boolean includeca) {
      this.includeCA = includeca;
    }

    /**
     * @return CP
     */
    public String getRaCertProfile() {
      return raCertProfile;
    }

    /**
     * @param cp CP
     */
    public void setRaCertProfile(final String cp) {
      this.raCertProfile = cp;
    }

    /**
     * @return EEP
     */
    public String getRaEEProfile() {
      return raEEProfile;
    }

    /**
     * @param eep EEP
     */
    public void setRaEEProfile(final String eep) {
      this.raEEProfile = eep;
    }

    /**
     * @return CA
     */
    public String getRaDefaultCA() {
      return raDefaultCA;
    }

    /**
     * @param caname CA
     */
    public void setRaDefaultCA(final String caname) {
      this.raDefaultCA = caname;
    }

    /**
     * @return pwd
     */
    public String getRaAuthPassword() {
      return this.raAuthPassword;
    }

    /**
     * @param raAuthPwd pwd
     */
    public void setRaAuthPassword(final String raAuthPwd) {
      this.raAuthPassword = raAuthPwd;
    }

    /**
     * @return sceme
     */
    public String getRaNameGenScheme() {
      return raNameGenScheme;
    }

    /**
     * @param scheme scheme
     */
    public void setRaNameGenScheme(final String scheme) {
      this.raNameGenScheme = scheme;
    }

    /**
     * @return bool
     */
    public boolean isRaNameGenSchemeFixed() {
      return "FIXED".equals(raNameGenScheme);
    }

    /**
     * @return bool
     */
    public boolean isRaNameGenSchemeDn() {
      return "DN".equals(raNameGenScheme);
    }

    /**
     * @return params
     */
    public String getRaNameGenParams() {
      return raNameGenParameters;
    }

    /**
     * @param params Params
     */
    public void setRaNameGenParams(final String params) {
      this.raNameGenParameters = params;
    }

    /**
     * @return prefix
     */
    public String getRaNameGenPrefix() {
      return raNameGenPrefix;
    }

    /**
     * @param prefix Prefix
     */
    public void setRaNameGenPrefix(final String prefix) {
      this.raNameGenPrefix = prefix;
    }

    /**
     * @return postfix
     */
    public String getRaNameGenPostfix() {
      return raNameGenPostfix;
    }

    /**
     * @param postfix postfix
     */
    public void setRaNameGenPostfix(final String postfix) {
      this.raNameGenPostfix = postfix;
    }

    /**
     * @return bool
     */
    public boolean getClientCertificateRenewal() {
      return this.clientCertificateRenewal;
    }

    /**
     * @param aclientCertificateRenewal bool
     */
    public void setClientCertificateRenewal(
        final boolean aclientCertificateRenewal) {
      this.clientCertificateRenewal = aclientCertificateRenewal;
    }

    /**
     * @return bool
     */
    public boolean getAllowClientCertificateRenewaWithOldKey() {
      return this.allowClientCertificateRenewaWithOldKey;
    }

    /**
     * @param doallowClientCertificateRenewaWithOldKey bool
     */
    public void setAllowClientCertificateRenewaWithOldKey(
        final boolean doallowClientCertificateRenewaWithOldKey) {
      this.allowClientCertificateRenewaWithOldKey =
          doallowClientCertificateRenewaWithOldKey;
    }
  }

  private static final long serialVersionUID = 2L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(ScepConfigMBean.class);

  /** Param. */
  private ListDataModel<ScepAliasGuiInfo> aliasGuiList = null;
  /** Param. */
  private String currentAliasStr;
  /** Param. */
  private ScepAliasGuiInfo currentAlias = null;
  /** Param. */
  private String newAlias = "";
  /** Param. */
  private ScepConfiguration scepConfig;
  /** Param. */
  private boolean currentAliasEditMode = false;

  /** Param. */
  private final GlobalConfigurationSessionLocal globalConfigSession =
      getEjbcaWebBean().getEjb().getGlobalConfigurationSession();
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession =
      getEjbcaWebBean().getEjb().getAuthorizationSession();
  /** Param. */
  private final AuthenticationToken authenticationToken = getAdmin();
  /** Param. */
  private final CaSessionLocal caSession =
      getEjbcaWebBean().getEjb().getCaSession();
  /** Param. */
  private final CertificateProfileSessionLocal certProfileSession =
      getEjbcaWebBean().getEjb().getCertificateProfileSession();
  /** Param. */
  private final EndEntityProfileSessionLocal endentityProfileSession =
      getEjbcaWebBean().getEjb().getEndEntityProfileSession();
  /** Param. */
  private final EnterpriseEditionEjbBridgeSessionLocal editionEjbBridgeSession =
      getEjbcaWebBean().getEnterpriseEjb();

  /** Constructor. */
  public ScepConfigMBean() {
    super();
    scepConfig =
        (ScepConfiguration)
            globalConfigSession.getCachedConfiguration(
                ScepConfiguration.SCEP_CONFIGURATION_ID);
  }

  /**
   * Force reload from underlying (cache) layer for the current SCEP
   * configuration alias.
   */
  private void flushCache() {
    currentAlias = null;
    aliasGuiList = null;
    currentAliasEditMode = false;
    scepConfig =
        (ScepConfiguration)
            globalConfigSession.getCachedConfiguration(
                ScepConfiguration.SCEP_CONFIGURATION_ID);
  }

  /**
   * @return alias
   */
  public String getNewAlias() {
    return newAlias;
  }

  /**
   * @param na alias
   */
  public void setNewAlias(final String na) {
    newAlias = na;
  }

  /**
   * @return bool
   */
  public boolean isCurrentAliasEditMode() {
    return currentAliasEditMode;
  }

  /**
   * @return bool
   */
  public boolean isAllowedToEdit() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
  }

  /**
   * @param acurrentAliasEditMode bool
   */
  public void setCurrentAliasEditMode(final boolean acurrentAliasEditMode) {
    this.currentAliasEditMode = acurrentAliasEditMode && isAllowedToEdit();
  }

  /** Edit. */
  public void toggleCurrentAliasEditMode() {
    currentAliasEditMode ^= true;
    currentAliasEditMode = currentAliasEditMode && isAllowedToEdit();
  }

  /**
   * Build a list sorted by name from the existing SCEP configuration aliases.
   *
   * @return model
   */
  public ListDataModel<ScepAliasGuiInfo> getAliasGuiList() {

    flushCache();
    final List<ScepAliasGuiInfo> list = new ArrayList<>();
    for (String alias : scepConfig.getAliasList()) {
      list.add(new ScepAliasGuiInfo(scepConfig, alias));
      Collections.sort(
          list,
          new Comparator<ScepAliasGuiInfo>() {
            @Override
            public int compare(
                final ScepAliasGuiInfo alias1, final ScepAliasGuiInfo alias2) {
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

  /**
   * @param as String
   */
  public void setCurrentAliasStr(final String as) {
    currentAliasStr = as;
  }

  /** @return the name of the Scep alias that is subject to view or edit */
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
   * @return cached or populate a new SCEP alias GUI representation for view or
   *     edit
   */
  public ScepAliasGuiInfo getCurrentAlias() {
    if (this.currentAlias == null) {
      final String alias = getCurrentAliasStr();
      this.currentAlias = new ScepAliasGuiInfo(scepConfig, alias);
    }

    return this.currentAlias;
  }

  /** Invoked when admin saves the SCEP alias configurations. */
  public void saveCurrentAlias() {
    if (currentAlias != null) {
      String alias = currentAlias.getAlias();
      scepConfig.setRAMode(
          alias, "ra".equalsIgnoreCase(currentAlias.getMode()));
      scepConfig.setIncludeCA(alias, currentAlias.isIncludeCA());
      scepConfig.setRACertProfile(alias, currentAlias.getRaCertProfile());
      scepConfig.setRAEndEntityProfile(alias, currentAlias.getRaEEProfile());
      scepConfig.setRADefaultCA(alias, currentAlias.getRaDefaultCA());
      scepConfig.setRAAuthpassword(alias, currentAlias.getRaAuthPassword());
      scepConfig.setRANameGenerationScheme(
          alias, currentAlias.getRaNameGenScheme());
      scepConfig.setRANameGenerationParameters(
          alias, currentAlias.getRaNameGenParams());
      scepConfig.setRANameGenerationPrefix(
          alias, currentAlias.getRaNameGenPrefix());
      scepConfig.setRANameGenerationPostfix(
          alias, currentAlias.getRaNameGenPostfix());
      scepConfig.setClientCertificateRenewal(
          alias, currentAlias.getClientCertificateRenewal());
      scepConfig.setAllowClientCertificateRenewalWithOldKey(
          alias, currentAlias.getAllowClientCertificateRenewaWithOldKey());

      try {
        globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
      } catch (AuthorizationDeniedException e) {
        String msg = "Cannot save alias. Administrator is not authorized.";
        LOG.info(msg + e.getLocalizedMessage());
        super.addNonTranslatedErrorMessage(msg);
      }
    }
    flushCache();
  }

  /** Delete. */
  public void deleteAlias() {
    if (scepConfig.aliasExists(currentAliasStr)) {
      scepConfig.removeAlias(currentAliasStr);
      try {
        globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
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

  /** Rename.
   */
  public void renameAlias() {
    if (StringUtils.isNotEmpty(newAlias) && !scepConfig.aliasExists(newAlias)) {
      scepConfig.renameAlias(currentAliasStr, newAlias);
      try {
        globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
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

  /**
   * Alias.
   */
  public void addAlias() {
    if (StringUtils.isNotEmpty(newAlias) && !scepConfig.aliasExists(newAlias)) {
      scepConfig.addAlias(newAlias);
      try {
        globalConfigSession.saveConfiguration(authenticationToken, scepConfig);
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

  /** Invoked when admin cancels a SCEP alias create or edit. */
  public void cancelCurrentAlias() {
    flushCache();
  }

  /** Update. */
  public void selectUpdate() {
    // NOOP: Only for page reload
  }

  /** @return a list of usable operational modes */
  public List<SelectItem> getAvailableModes() {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(
        new SelectItem(
            ScepConfiguration.Mode.RA.getResource(),
            ScepConfiguration.Mode.RA.getResource()));
    ret.add(
        new SelectItem(
            ScepConfiguration.Mode.CA.getResource(),
            ScepConfiguration.Mode.CA.getResource()));
    return ret;
  }

  /** @return a list of all CA names */
  public List<SelectItem> getAvailableCAs() {
    final List<SelectItem> ret = new ArrayList<>();
    final Collection<String> cas =
        caSession.getAuthorizedCaNames(authenticationToken);
    for (String caname : cas) {
      ret.add(new SelectItem(caname, caname));
    }
    return ret;
  }

  /** @return a list of EndEntity profiles that this admin is authorized to */
  public List<SelectItem> getAuthorizedEEProfileNames() {
    Collection<Integer> endEntityProfileIds =
        endentityProfileSession.getAuthorizedEndEntityProfileIds(
            getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
    Map<Integer, String> nameMap =
        endentityProfileSession.getEndEntityProfileIdToNameMap();
    final List<SelectItem> ret = new ArrayList<>();
    for (Integer id : endEntityProfileIds) {
      String name = nameMap.get(id);
      ret.add(new SelectItem(name, name));
    }
    return ret;
  }

  /**
   * @return a list of certificate profiles that are available for the current
   *     end entity profile
   */
  public List<SelectItem> getAvailableCertProfilesOfEEProfile() {
    String eep = currentAlias.getRaEEProfile();
    if ((eep == null) || (eep.length() <= 0)) {
      eep = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
    }
    EndEntityProfile p = endentityProfileSession.getEndEntityProfile(eep);
    final List<SelectItem> ret = new ArrayList<>();
    final Collection<Integer> cpids = p.getAvailableCertificateProfileIds();
    for (final int cpid : cpids) {
      String cpname = certProfileSession.getCertificateProfileName(cpid);
      ret.add(new SelectItem(cpname, cpname));
    }
    return ret;
  }

  /**
   * @return a list of CAs that are available for the current end entity profile
   */
  public List<SelectItem> getAvailableCAsOfEEProfile() {
    String eep = currentAlias.getRaEEProfile();
    if ((eep == null) || (eep.length() <= 0)) {
      eep = ScepConfiguration.DEFAULT_RA_ENTITYPROFILE;
    }
    EndEntityProfile p = endentityProfileSession.getEndEntityProfile(eep);

    final List<SelectItem> ret = new ArrayList<>();
    Map<Integer, String> caidname = getEjbcaWebBean().getCAIdToNameMap();
    for (int caid : p.getAvailableCAs()) {
      if (caid == CAConstants.ALLCAS) {
        return getAvailableCAs();
      }
      String caname = caidname.get(caid);
      ret.add(new SelectItem(caname, caname));
    }
    return ret;
  }

  /**
   * @return schemes
   */
  public List<SelectItem> getAvailableSchemes() {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(new SelectItem("DN", "DN Part"));
    ret.add(
        new SelectItem(
            "RANDOM",
            "RANDOM (Generates a 12 characters long random username)"));
    ret.add(new SelectItem("FIXED", "FIXED"));
    ret.add(new SelectItem("USERNAME", "Use entire request DN as username"));
    return ret;
  }

  /**
   * @return Parts
   */
  public List<SelectItem> getDnParts() {
    final List<SelectItem> ret = new ArrayList<>();
    ret.add(new SelectItem("CN", "CN"));
    ret.add(new SelectItem("UID", "UID"));
    ret.add(new SelectItem("OU", "OU"));
    ret.add(new SelectItem("O", "O"));
    ret.add(new SelectItem("L", "L"));
    ret.add(new SelectItem("ST", "ST"));
    ret.add(new SelectItem("DC", "DC"));
    ret.add(new SelectItem("C", "C"));
    ret.add(new SelectItem("emailAddress", "emailAddress"));
    ret.add(new SelectItem("serialNumber", "serialNumber"));
    ret.add(new SelectItem("givenName", "givenName"));
    ret.add(new SelectItem("initials", "initials"));
    ret.add(new SelectItem("surname", "surname"));
    ret.add(new SelectItem("title", "title"));
    ret.add(new SelectItem("unstructuredAddress", "unstructuredAddress"));
    ret.add(new SelectItem("unstructuredName", "unstructuredName"));
    ret.add(new SelectItem("postalCode", "postalCode"));
    ret.add(new SelectItem("businessCategory", "businessCategory"));
    ret.add(new SelectItem("dnQualifier", "dnQualifier"));
    ret.add(new SelectItem("postalAddress", "postalAddress"));
    ret.add(new SelectItem("telephoneNumber", "telephoneNumber"));
    ret.add(new SelectItem("pseudonym", "pseudonym"));
    ret.add(new SelectItem("streetAddress", "streetAddress"));
    ret.add(new SelectItem("name", "name"));
    ret.add(new SelectItem("CIF", "CIF"));
    ret.add(new SelectItem("NIF", "NIF"));
    return ret;
  }

  /**
   * @return pool
   */
  public boolean isExistsClientCertificateRenewalExtension() {
    return editionEjbBridgeSession.isRunningEnterprise();
  }
}
