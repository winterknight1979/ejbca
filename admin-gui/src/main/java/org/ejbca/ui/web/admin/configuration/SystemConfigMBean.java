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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.InvalidConfigurationException;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.config.RaStyleInfo.RaCssInfo;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.FileTools;
import org.cesecore.util.StreamSizeLimitExceededException;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.GlobalCustomCssConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.statedump.ejb.StatedumpImportOptions;
import org.ejbca.statedump.ejb.StatedumpImportResult;
import org.ejbca.statedump.ejb.StatedumpObjectKey;
import org.ejbca.statedump.ejb.StatedumpResolution;
import org.ejbca.statedump.ejb.StatedumpSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the various system configuration pages.
 *
 * @version $Id: SystemConfigMBean.java 30655 2018-11-28 08:58:52Z aminkh $
 */
public class SystemConfigMBean extends BaseManagedBean implements Serializable {

  private static final long serialVersionUID = -6653610614851741905L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(SystemConfigMBean.class);

  public final class GuiInfo {
        /** Param. */
    private String title;
    /** Param. */
    private String headBanner;
    /** Param. */
    private String footBanner;
    /** Param. */
    private boolean enableEndEntityProfileLimitations;
    /** Param. */
    private boolean enableKeyRecovery;
    /** Param. */
    private boolean localKeyRecovery;
    /** Param. */
    private int localKeyRecoveryCryptoTokenId;
    /** Param. */
    private String localKeyRecoveryKeyAlias;
    /** Param. */
    private boolean enableIcaoCANameChange;
    /** Param. */
    private boolean issueHardwareToken;
    /** Param. */
    private int hardTokenDataEncryptCA;
    /** Param. */
    private boolean useAutoEnrollment;
    /** Param. */
    private int autoEnrollmentCA;
    /** Param. */
    private boolean autoEnrollUseSSLConnection;
    /** Param. */
    private String autoEnrollAdServer;
    /** Param. */
    private int autoEnrollAdServerPort;
    /** Param. */
    private String autoEnrollConnectionDN;
    /** Param. */
    private String autoEnrollUserBaseDN;
    /** Param. */
    private String autoEnrollConnectionPassword;
    /** Param. */
    private Set<String> nodesInCluster;
    /** Param. */
    private boolean enableCommandLine;
    /** Param. */
    private boolean enableCommandLineDefaultUser;
    /** Param. */
    private boolean enableExternalScripts;
    /** Param. */
    private List<CTLogInfo> ctLogs;
    /** Param. */
    private boolean publicWebCertChainOrderRootFirst;

    // Admin Preferences
    /** Param. */
    private int preferedLanguage;
    /** Param. */
    private int secondaryLanguage;
    /** Param. */
    private String theme;
    /** Param. */
    private int entriesPerPage;

    // Database preferences
    /** Param. */
    private int maximumQueryCount;
    /** Param. */
    private long maximumQueryTimeout;

    /**
     * @param oaglobalConfig Config
     * @param aglobalCesecoreConfiguration config
     * @param oanadminPreference Prefs
     */
    private GuiInfo(
        final GlobalConfiguration oaglobalConfig,
        final GlobalCesecoreConfiguration aglobalCesecoreConfiguration,
        final AdminPreference oanadminPreference) {
      GlobalConfiguration aglobalConfig = oaglobalConfig;
      AdminPreference anadminPreference = oanadminPreference;
      if (aglobalConfig == null) {
        aglobalConfig = getEjbcaWebBean().getGlobalConfiguration();
      }

      try {
        this.title = aglobalConfig.getEjbcaTitle();
        this.headBanner = aglobalConfig.getHeadBanner();
        this.footBanner = aglobalConfig.getFootBanner();
        this.enableEndEntityProfileLimitations =
            aglobalConfig.getEnableEndEntityProfileLimitations();
        this.enableKeyRecovery = aglobalConfig.getEnableKeyRecovery();
        this.localKeyRecovery = aglobalConfig.getLocalKeyRecovery();
        this.localKeyRecoveryCryptoTokenId =
            aglobalConfig.getLocalKeyRecoveryCryptoTokenId() != null
                ? aglobalConfig.getLocalKeyRecoveryCryptoTokenId()
                : 0;
        this.localKeyRecoveryKeyAlias =
            aglobalConfig.getLocalKeyRecoveryKeyAlias();
        this.issueHardwareToken = aglobalConfig.getIssueHardwareTokens();
        this.hardTokenDataEncryptCA = aglobalConfig.getHardTokenEncryptCA();
        this.useAutoEnrollment = aglobalConfig.getAutoEnrollUse();
        this.autoEnrollmentCA = aglobalConfig.getAutoEnrollCA();
        this.autoEnrollUseSSLConnection =
            aglobalConfig.getAutoEnrollSSLConnection();
        this.autoEnrollAdServer = aglobalConfig.getAutoEnrollADServer();
        this.autoEnrollAdServerPort = aglobalConfig.getAutoEnrollADPort();
        this.autoEnrollConnectionDN = aglobalConfig.getAutoEnrollConnectionDN();
        this.autoEnrollUserBaseDN = aglobalConfig.getAutoEnrollBaseDNUser();
        this.autoEnrollConnectionPassword =
            aglobalConfig.getAutoEnrollConnectionPwd();
        this.nodesInCluster = aglobalConfig.getNodesInCluster();
        this.enableCommandLine = aglobalConfig.getEnableCommandLineInterface();
        this.enableCommandLineDefaultUser =
            aglobalConfig.getEnableCommandLineInterfaceDefaultUser();
        this.enableExternalScripts = aglobalConfig.getEnableExternalScripts();
        this.publicWebCertChainOrderRootFirst =
            aglobalConfig.getPublicWebCertChainOrderRootFirst();
        this.setEnableIcaoCANameChange(
            aglobalConfig.getEnableIcaoCANameChange());
        this.ctLogs = new ArrayList<>(aglobalConfig.getCTLogs().values());
        // Admin Preferences
        if (anadminPreference == null) {
          anadminPreference = getEjbcaWebBean().getAdminPreference();
        }
        this.preferedLanguage = anadminPreference.getPreferedLanguage();
        this.secondaryLanguage = anadminPreference.getSecondaryLanguage();
        this.theme = anadminPreference.getTheme();
        this.entriesPerPage = anadminPreference.getEntriesPerPage();

        this.maximumQueryCount =
            aglobalCesecoreConfiguration.getMaximumQueryCount();
        this.maximumQueryTimeout =
            aglobalCesecoreConfiguration.getMaximumQueryTimeout();
      } catch (RuntimeException e) {
        LOG.error(e.getMessage(), e);
      }
    }

    /**
     * @return Title
     */
    public String getTitle() {
      return this.title;
    }

    /**
     * @param atitle title
     */
    public void setTitle(final String atitle) {
      this.title = atitle;
    }

    /**
     * @return banner
     */
    public String getHeadBanner() {
      return this.headBanner;
    }

    /**
     * @param banner banner
     */
    public void setHeadBanner(final String banner) {
      this.headBanner = banner;
    }

    /**
     * @return banner
     */
    public String getFootBanner() {
      return this.footBanner;
    }

    /**
     * @param banner banner
     */
    public void setFootBanner(final String banner) {
      this.footBanner = banner;
    }

    /**
     * @return bool
     */
    public boolean getEnableEndEntityProfileLimitations() {
      return this.enableEndEntityProfileLimitations;
    }

    /**
     * @param enableLimitations bool
     */
    public void setEnableEndEntityProfileLimitations(
        final boolean enableLimitations) {
      this.enableEndEntityProfileLimitations = enableLimitations;
    }

    /**
     * @return bool
     */
    public boolean getEnableKeyRecovery() {
      return this.enableKeyRecovery;
    }

    /**
     * @param doenableKeyRecovery bool
     */
    public void setEnableKeyRecovery(final boolean doenableKeyRecovery) {
      this.enableKeyRecovery = doenableKeyRecovery;
    }

    /**
     * @return bool
     */
    public boolean getLocalKeyRecovery() {
      return this.localKeyRecovery;
    }

    /**
     * @param dolocalKeyRecovery bool
     */
    public void setLocalKeyRecovery(final boolean dolocalKeyRecovery) {
      this.localKeyRecovery = dolocalKeyRecovery;
    }

    /**
     * @return ID
     */
    public int getLocalKeyRecoveryCryptoTokenId() {
      return this.localKeyRecoveryCryptoTokenId;
    }

    /**
     * @param alocalKeyRecoveryCryptoTokenId ID
     */
    public void setLocalKeyRecoveryCryptoTokenId(
        final int alocalKeyRecoveryCryptoTokenId) {
      this.localKeyRecoveryCryptoTokenId = alocalKeyRecoveryCryptoTokenId;
    }

    /**
     * @return Alias
     */
    public String getLocalKeyRecoveryKeyAlias() {
      return this.localKeyRecoveryKeyAlias;
    }

    /**
     * @param alocalKeyRecoveryKeyAlias Alias
     */
    public void setLocalKeyRecoveryKeyAlias(
        final String alocalKeyRecoveryKeyAlias) {
      this.localKeyRecoveryKeyAlias = alocalKeyRecoveryKeyAlias;
    }

    /**
     * @return bool
     */
    public boolean getIssueHardwareToken() {
      return this.issueHardwareToken;
    }

    /**
     * @param issueHWtoken bool
     */
    public void setIssueHardwareToken(final boolean issueHWtoken) {
      this.issueHardwareToken = issueHWtoken;
    }

    /**
     * @return CA
     */
    public int getHardTokenDataEncryptCA() {
      return hardTokenDataEncryptCA;
    }

    /**
     * @param caid CVA
     */
    public void setHardTokenDataEncryptCA(final int caid) {
      this.hardTokenDataEncryptCA = caid;
    }

    /**
     * @return bool
     */
    public boolean getUseAutoEnrollment() {
      return this.useAutoEnrollment;
    }

    /**
     * @param douseAutoEnrollment bool
     */
    public void setUseAutoEnrollment(final boolean douseAutoEnrollment) {
      this.useAutoEnrollment = douseAutoEnrollment;
    }

    /**
     * @return CA
     */
    public int getAutoEnrollmentCA() {
      return this.autoEnrollmentCA;
    }

    /**
     * @param caid CA
     */
    public void setAutoEnrollmentCA(final int caid) {
      this.autoEnrollmentCA = caid;
    }

    /**
     * @return bool
     */
    public boolean getAutoEnrollUseSSLConnection() {
      return autoEnrollUseSSLConnection;
    }

    /**
     * @param useSSLConnection bool
     */
    public void setAutoEnrollUseSSLConnection(final boolean useSSLConnection) {
      this.autoEnrollUseSSLConnection = useSSLConnection;
    }

    /**
     * @return Server
     */
    public String getAutoEnrollAdServer() {
      return this.autoEnrollAdServer;
    }

    /**
     * @param server Server
     */
    public void setAutoEnrollAdServer(final String server) {
      this.autoEnrollAdServer = server;
    }

    /**
     * @return Port
     */
    public int getAutoEnrollAdServerPort() {
      return this.autoEnrollAdServerPort;
    }

    /**
     * @param port Port
     */
    public void setAutoEnrollAdServerPort(final int port) {
      this.autoEnrollAdServerPort = port;
    }

    /**
     * @return DN
     */
    public String getAutoEnrollConnectionDN() {
      return this.autoEnrollConnectionDN;
    }

    /**
     * @param dn DN
     */
    public void setAutoEnrollConnectionDN(final String dn) {
      this.autoEnrollConnectionDN = dn;
    }

    /**
     * @return DN
     */
    public String getAutoEnrollUserBaseDN() {
      return this.autoEnrollUserBaseDN;
    }

    /**
     * @param dn DN
     */
    public void setAutoEnrollUserBaseDN(final String dn) {
      this.autoEnrollUserBaseDN = dn;
    }

    /**
     * @return pwd
     */
    public String getAutoEnrollConnectionPassword() {
      return this.autoEnrollConnectionPassword;
    }

    /**
     * @param password pwd
     */
    public void setAutoEnrollConnectionPassword(final String password) {
      this.autoEnrollConnectionPassword = password;
    }

    /**
     * @return nodes
     */
    public Set<String> getNodesInCluster() {
      return this.nodesInCluster;
    }

    /**
     * @param nodes nodes
     */
    public void setNodesInCluster(final Set<String> nodes) {
      this.nodesInCluster = nodes;
    }

    /**
     * @return do
     */
    public boolean getEnableCommandLine() {
      return this.enableCommandLine;
    }

    /**
     * @param doenableCommandLine do
     */
    public void setEnableCommandLine(final boolean doenableCommandLine) {
      this.enableCommandLine = doenableCommandLine;
    }

    /**
     * @return bool
     */
    public boolean getEnableCommandLineDefaultUser() {
      return this.enableCommandLineDefaultUser;
    }

    /**
     * @param doenableCommandLineDefaultUser bool
     */
    public void setEnableCommandLineDefaultUser(
        final boolean doenableCommandLineDefaultUser) {
      this.enableCommandLineDefaultUser = doenableCommandLineDefaultUser;
    }

    /**
     * @return bool
     */
    public boolean getEnableExternalScripts() {
      return this.enableExternalScripts;
    }

    /**
     * @param aenableExternalScripts bool
     */
    public void setEnableExternalScripts(final boolean aenableExternalScripts) {
      this.enableExternalScripts = aenableExternalScripts;
    }

    /**
     * @return logs
     */
    public List<CTLogInfo> getCtLogs() {
      return this.ctLogs;
    }

    /**
     * @param thectlogs logs
     */
    public void setCtLogs(final List<CTLogInfo> thectlogs) {
      this.ctLogs = thectlogs;
    }

    /**
     * @return bool
     */
    public boolean getPublicWebCertChainOrderRootFirst() {
      return this.publicWebCertChainOrderRootFirst;
    }

    /**
     * @param apublicWebCertChainOrderRootFirst bool
     */
    public void setPublicWebCertChainOrderRootFirst(
        final boolean apublicWebCertChainOrderRootFirst) {
      this.publicWebCertChainOrderRootFirst = apublicWebCertChainOrderRootFirst;
    }

    /**
     * @return bool
     */
    public boolean getEnableIcaoCANameChange() {
      return enableIcaoCANameChange;
    }

    /**
     * @param doenableIcaoCANameChange bool
     */
    public void setEnableIcaoCANameChange(
        final boolean doenableIcaoCANameChange) {
      this.enableIcaoCANameChange = doenableIcaoCANameChange;
    }

    // Admin Preferences
    /**
     * @return Lang
     */
    public int getPreferedLanguage() {
      return this.preferedLanguage;
    }

    /**
     * @param apreferedLanguage Lang
     */
    public void setPreferedLanguage(final int apreferedLanguage) {
      this.preferedLanguage = apreferedLanguage;
    }

    /**
     * @return lang
     */
    public int getSecondaryLanguage() {
      return this.secondaryLanguage;
    }

    /**
     * @param asecondaryLanguage Lang
     */
    public void setSecondaryLanguage(final int asecondaryLanguage) {
      this.secondaryLanguage = asecondaryLanguage;
    }

    /**
     * @return Theme
     */
    public String getTheme() {
      return this.theme;
    }

    /**
     * @param atheme theme
     */
    public void setTheme(final String atheme) {
      this.theme = atheme;
    }

    /**
     * @return entries
     */
    public int getEntriesPerPage() {
      return this.entriesPerPage;
    }

    /**
     * @param theentriesPerPage entries
     */
    public void setEntriesPerPage(final int theentriesPerPage) {
      this.entriesPerPage = theentriesPerPage;
    }

    /**
     * @return count
     */
    public int getMaximumQueryCount() {
      return maximumQueryCount;
    }

    /**
     * @param amaximumQueryCount count
     */
    public void setMaximumQueryCount(final int amaximumQueryCount) {
      this.maximumQueryCount = amaximumQueryCount;
    }

    /**
     * @return timeout
     */
    public long getMaximumQueryTimeout() {
      return maximumQueryTimeout;
    }

    /**         *
     * @param amaximumQueryTimeout timeout
     */
    public void setMaximumQueryTimeout(final long amaximumQueryTimeout) {
      this.maximumQueryTimeout = amaximumQueryTimeout;
    }
  }

  public final class EKUInfo {
        /** Param. */
    private String oid;
    /** Param. */
    private String name;

    /**
     * @param anoid OID
     * @param aname Name
     */
    private EKUInfo(final String anoid, final String aname) {
      this.oid = anoid;
      this.name = aname;
    }

    /**
     * @return OID
     */
    public String getOid() {
      return this.oid;
    }

    /**
     * @param anoid OID
     */
    public void setOid(final String anoid) {
      this.oid = anoid;
    }

    /**
     * @return name
     */
    public String getName() {
      return this.name;
    }

    /**
     * @param aname name
     */
    public void setName(final String aname) {
      this.name = aname;
    }
  }

  public class CustomCertExtensionInfo {
        /** Param. */
    private int id;
    /** Param. */
    private String oid;
    /** Param. */
    private String displayName;
    /** Param. */
    private final boolean critical;
    /** Param. */
    private final boolean required;
    /** Param. */
    private final String encoding;

    /**
     * @param extension Ext
     */
    public CustomCertExtensionInfo(final CertificateExtension extension) {
      this.id = extension.getId();
      this.oid = extension.getOID();
      this.displayName = getEjbcaWebBean().getText(extension.getDisplayName());
      this.critical = extension.isCriticalFlag();
      this.required = extension.isRequiredFlag();
      Properties props = extension.getProperties();
      this.encoding = props.getProperty("encoding", "");
    }

    /**
     * @return ID
     */
    public int getId() {
      return this.id;
    }

    /**
     * @param anid ID
     */
    public void setId(final int anid) {
      this.id = anid;
    }

    /**
     * @return OID
     */
    public String getOid() {
      return this.oid;
    }

    /**
     * @param anoid OID
     */
    public void setOid(final String anoid) {
      this.oid = anoid;
    }

    /**
     * @return name
     */
    public String getDisplayName() {
      return this.displayName;
    }

    /**
     * @param adisplayName name
     */
    public void setDisplayName(final String adisplayName) {
      this.displayName = adisplayName;
    }

    /**
     * @return bool
     */
    public boolean isCritical() {
      return this.critical;
    }

    /**
     * @return bool
     */
    public boolean isRequired() {
      return this.required;
    }

    /**
     * @return encoding
     */
    public String getEncoding() {
      return this.encoding;
    }
  }

  /** Param. */
  private String selectedTab = null;
  /** Param. */
  private GlobalConfiguration globalConfig = null;
  /** Param. */
  private GlobalCesecoreConfiguration globalCesecoreConfiguration = null;
  /** Param. */
  private AdminPreference adminPreference = null;
  /** Param. */
  private GuiInfo currentConfig = null;
  /** Param. */
  private ValidatorSettings validatorSettings;
  /** Param. */
  private List<SelectItem> availableCryptoTokens;
  /** Param. */
  private List<SelectItem> availableKeyAliases;
  /** Param. */
  private ListDataModel<String> nodesInCluster = null;
  /** Param. */
  private String currentNode = null;
  /** Param. */
  private boolean excludeActiveCryptoTokensFromClearCaches = true;
  /** Param. */
  private boolean customCertificateExtensionViewMode = false;
  /** Param. */
  private UploadedFile statedumpFile = null;
  /** Param. */
  private String statedumpDir = null;
  /** Param. */
  private boolean statedumpLockdownAfterImport = false;

  /** Param. */
  private final CaSessionLocal caSession =
      getEjbcaWebBean().getEjb().getCaSession();
  /** Param. */
  private final CertificateProfileSessionLocal certificateProfileSession =
      getEjbcaWebBean().getEjb().getCertificateProfileSession();
  /** Param. */
  private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession =
      getEjbcaWebBean().getEjb().getCryptoTokenManagementSession();
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession =
      getEjbcaWebBean().getEjb().getAuthorizationSession();
  /**
   * Session bean for importing statedump. Will be null if statedump isn't
   * available
   */
  private final StatedumpSessionLocal statedumpSession =
      new EjbLocalHelper().getStatedumpSession();

  /** Param. */
  private SystemConfigurationCtLogManager ctLogManager;
  /** Param. */
  private GoogleCtPolicy googleCtPolicy;

  /** Constructor. */
  public SystemConfigMBean() {
    super();
  }

  /**
   * Get an object which can be used to manage the CT log configuration. This
   * will create a new CT log manager for the CT logs in the current
   * configuration if no CT log manager has been created, or the old CT log
   * manager was flushed.
   *
   * @return the CT log manager for this bean
   */
  public SystemConfigurationCtLogManager getCtLogManager() {
    if (ctLogManager == null) {
      ctLogManager =
          new SystemConfigurationCtLogManager(
              getCurrentConfig().getCtLogs(),
              new SystemConfigurationCtLogManager.SystemConfigurationHelper() {
                @Override
                public void saveCtLogs(final List<CTLogInfo> ctLogs) {
                  getCurrentConfig().setCtLogs(ctLogs);
                  saveCurrentConfig();
                }

                @Override
                public void addInfoMessage(final String languageKey) {
                  SystemConfigMBean.this.addInfoMessage(languageKey);
                }

                @Override
                public void addErrorMessage(
                    final String languageKey, final Object... params) {
                  SystemConfigMBean.this.addErrorMessage(languageKey, params);
                }

                @Override
                public void addErrorMessage(final String languageKey) {
                  SystemConfigMBean.this.addErrorMessage(languageKey);
                }

                @Override
                public List<String> getCertificateProfileNamesByCtLog(
                    final CTLogInfo ctLog) {
                  final List<String> usedByProfiles = new ArrayList<>();
                  final Map<Integer, String> idToName =
                      certificateProfileSession
                          .getCertificateProfileIdToNameMap();
                  for (Entry<Integer, CertificateProfile> entry
                      : certificateProfileSession
                          .getAllCertificateProfiles()
                          .entrySet()) {
                    final int certificateProfileId = entry.getKey();
                    final CertificateProfile certificateProfile =
                        entry.getValue();
                    if (certificateProfile
                        .getEnabledCtLabels()
                        .contains(ctLog.getLabel())) {
                      usedByProfiles.add(idToName.get(certificateProfileId));
                    }
                  }
                  return usedByProfiles;
                }
              });
    }
    return ctLogManager;
  }

  /**
   * @return Policy
   */
  public GoogleCtPolicy getGoogleCtPolicy() {
    if (googleCtPolicy == null) {
      googleCtPolicy = getGlobalConfiguration().getGoogleCtPolicy();
    }
    return googleCtPolicy;
  }

  /**
   * @return Config
   */
  public GlobalCesecoreConfiguration getGlobalCesecoreConfiguration() {
    if (globalCesecoreConfiguration == null) {
      globalCesecoreConfiguration =
          (GlobalCesecoreConfiguration)
              getEjbcaWebBean()
                  .getEjb()
                  .getGlobalConfigurationSession()
                  .getCachedConfiguration(
                      GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
    }
    return globalCesecoreConfiguration;
  }

  /**
   * @return Config
   */
  public GlobalConfiguration getGlobalConfiguration() {
    if (globalConfig == null) {
      globalConfig = getEjbcaWebBean().getGlobalConfiguration();
    }
    return globalConfig;
  }

  /**
   * @return Prefs
   * @throws Exception Fail
   */
  public AdminPreference getAdminPreference() throws Exception {
    if (adminPreference == null) {
      adminPreference = getEjbcaWebBean().getDefaultAdminPreference();
    }
    return adminPreference;
  }

  /**
   * @return cached or populate a new system configuration GUI representation
   *     for view or edit
   */
  public GuiInfo getCurrentConfig() {
    if (this.currentConfig == null) {
      try {
        this.currentConfig =
            new GuiInfo(
                getGlobalConfiguration(),
                getGlobalCesecoreConfiguration(),
                getAdminPreference());
      } catch (Exception e) {
        String msg = "Cannot read Administrator Preferences.";
        LOG.info(msg + e.getLocalizedMessage());
        super.addNonTranslatedErrorMessage(msg);
      }
    }
    return this.currentConfig;
  }

  /** @return current settings for the Validators tab */
  public ValidatorSettings getValidatorSettings() {
    if (validatorSettings == null) {
      validatorSettings =
          new ValidatorSettings(
              new ValidatorSettings.ValidatorSettingsHelper() {
                @Override
                public GlobalConfiguration getGlobalConfiguration() {
                  return SystemConfigMBean.this.getGlobalConfiguration();
                }

                @Override
                public void addErrorMessage(
                    final String languageKey, final Object... params) {
                  SystemConfigMBean.this.addErrorMessage(languageKey, params);
                }

                @Override
                public void addInfoMessage(final String languageKey) {
                  SystemConfigMBean.this.addInfoMessage(languageKey);
                }

                @Override
                public void persistConfiguration(
                    final GlobalConfiguration globalConfiguration)
                    throws AuthorizationDeniedException {
                  getEjbcaWebBean()
                      .saveGlobalConfiguration(globalConfiguration);
                }
              });
    }
    return validatorSettings;
  }

  /**
   * @return tab
   */
  public String getSelectedTab() {
    final String tabHttpParam =
        ((HttpServletRequest)
                FacesContext.getCurrentInstance()
                    .getExternalContext()
                    .getRequest())
            .getParameter("tab");
    // First, check if the user has requested a valid tab
    List<String> availableTabs = getAvailableTabs();
    if (tabHttpParam != null && availableTabs.contains(tabHttpParam)) {
      // The requested tab is an existing tab. Flush caches so we reload the
      // page content
      flushCache();
      selectedTab = tabHttpParam;
    }
    if (selectedTab == null) {
      // If no tab was requested, we use the first available tab as default
      selectedTab = availableTabs.get(0);
    }
    return selectedTab;
  }

  /**
   * @return node
   */
  public String getCurrentNode() {
    return this.currentNode;
  }

  /**
   * @param node node
   */
  public void setCurrentNode(final String node) {
    this.currentNode = node;
  }

  /**
   * @return bool
   */
  public boolean getExcludeActiveCryptoTokensFromClearCaches() {
    return this.excludeActiveCryptoTokensFromClearCaches;
  }

  /**
   * @param exclude bool
   */
  public void setExcludeActiveCryptoTokensFromClearCaches(
      final boolean exclude) {
    this.excludeActiveCryptoTokensFromClearCaches = exclude;
  }

  /** Clear. */
  public void clearAllCaches() {
    boolean execludeActiveCryptoTokens =
        getExcludeActiveCryptoTokensFromClearCaches();
    try {
      getEjbcaWebBean().clearClusterCache(execludeActiveCryptoTokens);
    } catch (CacheClearException e) {
      String msg = "Cannot clear caches: " + e.getLocalizedMessage();
      LOG.info(msg);
      super.addNonTranslatedErrorMessage(msg);
    }
  }

  /**
   * @return dir
   */
  public String getStatedumpDir() {
    return statedumpDir;
  }

  /**
   * @param astatedumpDir Dir
   */
  public void setStatedumpDir(final String astatedumpDir) {
    this.statedumpDir = astatedumpDir;
  }

  /**
   * @return file
   */
  public UploadedFile getStatedumpFile() {
    return statedumpFile;
  }

  /**
   * @param astatedumpFile file
   */
  public void setStatedumpFile(final UploadedFile astatedumpFile) {
    this.statedumpFile = astatedumpFile;
  }

  /**
   * @return bool
   */
  public boolean getStatedumpLockdownAfterImport() {
    return statedumpLockdownAfterImport;
  }

  /**
   * @param isstatedumpLockdownAfterImport bool
   */
  public void setStatedumpLockdownAfterImport(
      final boolean isstatedumpLockdownAfterImport) {
    this.statedumpLockdownAfterImport = isstatedumpLockdownAfterImport;
  }

  /**
   * Returns true if EJBCA was built with Statedump (from EJBCA 6.5.0 or later)
   * and it hasn't been locked down in the user interface.
   *
   * @return bool
   */
  public boolean isStatedumpAvailable() {
    return statedumpSession != null
        && !getGlobalConfiguration().getStatedumpLockedDown();
  }

  /**
   * @return templates
   */
  public List<SelectItem> getStatedumpAvailableTemplates() {
    final List<SelectItem> templates = new ArrayList<>();
    try {
      for (Map.Entry<String, String> entry
          : statedumpSession.getAvailableTemplates(getAdmin()).entrySet()) {
        final String description = getEjbcaWebBean().getText(entry.getValue());
        templates.add(new SelectItem(entry.getKey(), description));
      }
    } catch (AuthorizationDeniedException e) {
      LOG.debug("Authorization was denied to list statedump templates");
    }
    sortSelectItemsByLabel(templates);
    templates.add(0, new SelectItem("", getEjbcaWebBean().getText("NONE")));
    return templates;
  }

  /**
   * @return bool
   */
  public boolean isStatedumpTemplatesVisible() {
    try {
      final String basedir = statedumpSession.getTemplatesBasedir(getAdmin());
      return basedir != null
          && !basedir.isEmpty()
          && new File(basedir).isDirectory();
    } catch (AuthorizationDeniedException e) {
      return false;
    }
  }

  private void importStatedump(final File path, final boolean lockdown)
      throws IOException, AuthorizationDeniedException {
    final StatedumpImportOptions options = new StatedumpImportOptions();
    options.setLocation(path);
    // Since we currently don't give the user any option to upload an overrides
    // file, we look for an overrides file in the .zip file
    options.setOverridesFile(new File(path, "overrides.properties"));
    options.setMergeCryptoTokens(true);

    StatedumpImportResult result =
        statedumpSession.performDryRun(getAdmin(), options);
    for (final StatedumpObjectKey key : result.getConflicts()) {
      LOG.info("Will overwrite " + key);
      options.addConflictResolution(key, StatedumpResolution.OVERWRITE);
    }
    for (final StatedumpObjectKey key : result.getPasswordsNeeded()) {
      LOG.info(
          "Will use dummy 'foo123' password for "
              + key
              + ", please disable or change it!");
      options.addPassword(key, "foo123");
    }

    LOG.info("Performing statedump import");
    result = statedumpSession.performImport(getAdmin(), options);
    LOG.info("Statedump successfully imported.");

    // Lock down after import
    if (lockdown) {
      LOG.info("Locking down Statedump in the Admin Web.");
      lockDownStatedump();
    } else {
      LOG.debug("Not locking down statedump.");
    }

    // Done, add result messages
    for (String msg : result.getNotices()) {
      super.addNonTranslatedInfoMessage(msg);
    }
    super.addNonTranslatedInfoMessage("State dump was successfully imported.");
  }

  private void importStatedump(final byte[] zip, final boolean lockdown)
      throws IOException, AuthorizationDeniedException {
    // Check that it's a ZIP file
    if (zip.length < 2 || zip[0] != 'P' || zip[1] != 'K') {
      throw new IOException("File is not a valid zip file.");
    }

    // Create temporary directory
    final Path tempdirPath = Files.createTempDirectory("ejbca_statedump_gui");
    final File tempdir = tempdirPath.toFile();
    LOG.info(
        "Importing "
            + zip.length
            + " byte statedump zip file, using temporary directory "
            + tempdir);

    // Unpack the zip file
    try (ZipInputStream zipStream =
        new ZipInputStream(new ByteArrayInputStream(zip))) {
      boolean empty = true;
      final long max = 100_000_000;
      long limit = max; // Maximum total uncompressed size is 100 MB
      while (true) {
        final ZipEntry entry = zipStream.getNextEntry();
        if (entry == null) {
          break;
        }
        if (entry.isDirectory()) {
          zipStream.closeEntry();
          continue;
        }

        final String name = entry.getName().replaceFirst("^.*/([^/]+)$", "$1");
        if (name.matches("([a-z0-9_-]+\\.xml|replacements.properties)")) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Extracting zip file entry "
                    + name
                    + " into temporary directory");
          }

          if (entry.getSize() == 0) {
            LOG.debug("Ignoring empty file");
            zipStream.closeEntry();
            continue;
          }

          // Create file exclusively (don't overwrite, and don't write to
          // special devices or operating system special files)
          final Path filepath =
              Files.createFile(new File(tempdir, name).toPath());
          try (FileOutputStream fos =
              new FileOutputStream(filepath.toFile())) {
            try {
              limit -= FileTools.streamCopyWithLimit(zipStream, fos, limit);
            } catch (StreamSizeLimitExceededException ssle) {
              throw new IOException(
                  "Zip file is larger than 100 MB. Aborting.");
            }
          }
          zipStream.closeEntry();
          empty = false;
        } else if (LOG.isDebugEnabled()) {
          LOG.debug("Ignoring zip file entry " + name);
        }
      }

      if (empty) {
        throw new IOException(
            "Zip file didn't contain any statedump xml files.");
      }

      // Import statedump
      importStatedump(tempdir, lockdown);

    } finally {
      // Clean up
      LOG.debug("Removing temporary directory for statedump XML files");
      FileUtils.deleteDirectory(tempdir);
    }
  }

  private void lockDownStatedump() throws AuthorizationDeniedException {
    getGlobalConfiguration(); // sets globalConfig
    globalConfig.setStatedumpLockedDown(true);
    getEjbcaWebBean().saveGlobalConfiguration(globalConfig);
    if (LOG.isDebugEnabled()) {
      final boolean state =
          getEjbcaWebBean().getGlobalConfiguration().getStatedumpLockedDown();
      LOG.debug("Statedump lockdown state changed to " + state);
    }
  }

  /** import.
   */
  public void importStatedump() {
    final boolean importFromDir =
        (statedumpDir != null && !statedumpDir.isEmpty());

    if (!importFromDir && statedumpFile == null) {
      if (statedumpLockdownAfterImport) {
        try {
          lockDownStatedump();
        } catch (AuthorizationDeniedException e) {
          final String msg = "Authorization denied: " + e.getLocalizedMessage();
          LOG.info(msg);
          super.addNonTranslatedErrorMessage(msg);
        }
      } else {
        FacesContext.getCurrentInstance()
            .addMessage(
                null,
                new FacesMessage(
                    FacesMessage.SEVERITY_ERROR,
                    "Please select a statedump to import.",
                    null));
      }
      return;
    }

    if (importFromDir && statedumpFile != null) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Please import from either a directory or an uploaded ZIP"
                      + " file, but not both.",
                  null));
      return;
    }

    if (getGlobalConfiguration().getStatedumpLockedDown()) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Statedump has been locked down on this EJBCA installation"
                      + " and is not available.",
                  null));
      return;
    }

    try {
      if (importFromDir) {
        final File basedir =
            new File(statedumpSession.getTemplatesBasedir(getAdmin()));
        importStatedump(
            new File(basedir, statedumpDir), statedumpLockdownAfterImport);
      } else {
        byte[] uploadedFileBytes = statedumpFile.getBytes();
        importStatedump(uploadedFileBytes, statedumpLockdownAfterImport);
      }
    } catch (Exception e) {
      String msg = "Statedump import failed. " + e.getLocalizedMessage();
      LOG.info(msg, e);
      super.addNonTranslatedErrorMessage(msg);
    }

    // Clear GUI caches
    try {
      getEjbcaWebBean().clearClusterCache(true); // exclude crypto tokens
    } catch (Exception e) {
      String msg =
          "Statedump was successful, but the cache could not be cleared"
              + " automatically. Please manually restart your browser or"
              + " JBoss. "
              + e.getLocalizedMessage();
      LOG.info(msg);
      super.addNonTranslatedErrorMessage(msg);
    }
  }

  /**
   * @return bool
   */
  public boolean validateCurrentConfig() {
    if (!currentConfig.getEnableKeyRecovery()) {
      currentConfig.setLocalKeyRecovery(false);
    }
    if (currentConfig.getLocalKeyRecovery()) {
      if (currentConfig.getLocalKeyRecoveryCryptoTokenId() == 0) {
        String msg = "Please select a crypto token for local key recovery";
        LOG.info(msg);
        super.addNonTranslatedErrorMessage(msg);
        return false;
      } else if (StringUtils.isEmpty(
          currentConfig.getLocalKeyRecoveryKeyAlias())) {
        String msg = "Please select a key alias for local key recovery";
        LOG.info(msg);
        super.addNonTranslatedErrorMessage(msg);
        return false;
      }
    }
    return true;
  }

  private Integer zeroToNull(final int value) {
    return value == 0 ? null : value;
  }

  /** Invoked when admin saves the configurations. */
  public void saveCurrentConfig() {
    if (currentConfig != null) {
      if (!validateCurrentConfig()) {
        return;
      }
      try {
        globalConfig.setEjbcaTitle(currentConfig.getTitle());
        globalConfig.setHeadBanner(currentConfig.getHeadBanner());
        globalConfig.setFootBanner(currentConfig.getFootBanner());
        globalConfig.setEnableEndEntityProfileLimitations(
            currentConfig.getEnableEndEntityProfileLimitations());
        globalConfig.setEnableKeyRecovery(currentConfig.getEnableKeyRecovery());
        globalConfig.setLocalKeyRecovery(currentConfig.getLocalKeyRecovery());
        globalConfig.setLocalKeyRecoveryCryptoTokenId(
            zeroToNull(currentConfig.getLocalKeyRecoveryCryptoTokenId()));
        globalConfig.setLocalKeyRecoveryKeyAlias(
            currentConfig.getLocalKeyRecoveryKeyAlias());
        globalConfig.setIssueHardwareTokens(
            currentConfig.getIssueHardwareToken());
        globalConfig.setHardTokenEncryptCA(
            currentConfig.getHardTokenDataEncryptCA());
        globalConfig.setAutoEnrollUse(currentConfig.getUseAutoEnrollment());
        globalConfig.setAutoEnrollCA(currentConfig.getAutoEnrollmentCA());
        globalConfig.setAutoEnrollSSLConnection(
            currentConfig.getAutoEnrollUseSSLConnection());
        globalConfig.setAutoEnrollADServer(
            currentConfig.getAutoEnrollAdServer());
        globalConfig.setAutoEnrollADPort(
            currentConfig.getAutoEnrollAdServerPort());
        globalConfig.setAutoEnrollConnectionDN(
            currentConfig.getAutoEnrollConnectionDN());
        globalConfig.setAutoEnrollBaseDNUser(
            currentConfig.getAutoEnrollUserBaseDN());
        globalConfig.setAutoEnrollConnectionPwd(
            currentConfig.getAutoEnrollConnectionPassword());
        globalConfig.setNodesInCluster(currentConfig.getNodesInCluster());
        globalConfig.setEnableCommandLineInterface(
            currentConfig.getEnableCommandLine());
        globalConfig.setEnableCommandLineInterfaceDefaultUser(
            currentConfig.getEnableCommandLineDefaultUser());
        globalConfig.setEnableExternalScripts(
            currentConfig.getEnableExternalScripts());
        globalConfig.setPublicWebCertChainOrderRootFirst(
            currentConfig.getPublicWebCertChainOrderRootFirst());
        globalConfig.setEnableIcaoCANameChange(
            currentConfig.getEnableIcaoCANameChange());
        LinkedHashMap<Integer, CTLogInfo> ctlogsMap = new LinkedHashMap<>();
        for (CTLogInfo ctlog : currentConfig.getCtLogs()) {
          ctlogsMap.put(ctlog.getLogId(), ctlog);
        }
        globalConfig.setCTLogs(ctlogsMap);

        if (getGoogleCtPolicy().isValid()) {
          globalConfig.setGoogleCtPolicy(getGoogleCtPolicy());
        } else {
          addErrorMessage("INVALID_CT_POLICY");
        }

        getEjbcaWebBean().saveGlobalConfiguration(globalConfig);

        globalCesecoreConfiguration.setMaximumQueryCount(
            currentConfig.getMaximumQueryCount());
        globalCesecoreConfiguration.setMaximumQueryTimeout(
            currentConfig.getMaximumQueryTimeout());
        getEjbcaWebBean()
            .getEjb()
            .getGlobalConfigurationSession()
            .saveConfiguration(getAdmin(), globalCesecoreConfiguration);

      } catch (AuthorizationDeniedException | InvalidConfigurationException e) {
        String msg =
            "Cannot save System Configuration. " + e.getLocalizedMessage();
        LOG.info(msg);
        super.addNonTranslatedErrorMessage(msg);
      }

      try {
        adminPreference.setPreferedLanguage(
            currentConfig.getPreferedLanguage());
        adminPreference.setSecondaryLanguage(
            currentConfig.getSecondaryLanguage());
        adminPreference.setTheme(currentConfig.getTheme());
        adminPreference.setEntriesPerPage(currentConfig.getEntriesPerPage());

        getEjbcaWebBean().saveDefaultAdminPreference(adminPreference);
      } catch (AuthorizationDeniedException e) {
        String msg =
            "Cannot save Administrator Preferences. " + e.getLocalizedMessage();
        LOG.info(msg);
        super.addNonTranslatedErrorMessage(msg);
      }

      // GlobalConfiguration validates and modifies some fields when they are
      // set, so these fields need to be updated.
      // Also, this ensures that the values shown are those actually stored in
      // the database.
      flushCache(); // must be done last
    }
  }

  /** Invoked when admin saves the admin preferences. */
  public void saveCurrentAdminPreferences() {
    if (currentConfig != null) {
      try {
        adminPreference.setPreferedLanguage(
            currentConfig.getPreferedLanguage());
        adminPreference.setSecondaryLanguage(
            currentConfig.getSecondaryLanguage());
        adminPreference.setTheme(currentConfig.getTheme());
        adminPreference.setEntriesPerPage(currentConfig.getEntriesPerPage());

        getEjbcaWebBean().saveDefaultAdminPreference(adminPreference);
      } catch (Exception e) {
        String msg =
            "Cannot save Administrator Preferences. " + e.getLocalizedMessage();
        LOG.info(msg);
        super.addNonTranslatedErrorMessage(msg);
      }
    }
  }

  /** Flush. */
  public void flushCache() {
    globalConfig = null;
    adminPreference = null;
    currentConfig = null;
    nodesInCluster = null;
    ctLogManager = null;
    raStyleInfos = null;
    excludeActiveCryptoTokensFromClearCaches = true;
    availableExtendedKeyUsages = null;
    availableExtendedKeyUsagesConfig = null;
    availableCustomCertExtensions = null;
    availableCustomCertExtensionsConfig = null;
    selectedCustomCertExtensionID = 0;
    googleCtPolicy = null;
    validatorSettings = null;
  }

  /** Toggle. */
  public void toggleUseAutoEnrollment() {
    currentConfig.setUseAutoEnrollment(!currentConfig.getUseAutoEnrollment());
  }

  /** Toggle. */
  public void toggleEnableKeyRecovery() {
    currentConfig.setEnableKeyRecovery(!currentConfig.getEnableKeyRecovery());
  }

  /** Toggle. */
  public void toggleLocalKeyRecovery() {
    currentConfig.setLocalKeyRecovery(!currentConfig.getLocalKeyRecovery());
  }

  /**
   * @return tokens
   */
  public List<SelectItem> getAvailableCryptoTokens() {
    if (availableCryptoTokens == null) {
      availableCryptoTokens = new ArrayList<>();
      for (final CryptoTokenInfo cryptoTokenInfo
          : cryptoTokenManagementSession.getCryptoTokenInfos(
              getEjbcaWebBean().getAdminObject())) {
        availableCryptoTokens.add(
            new SelectItem(
                cryptoTokenInfo.getCryptoTokenId(), cryptoTokenInfo.getName()));
      }
      Collections.sort(
          availableCryptoTokens,
          new Comparator<SelectItem>() {
            @Override
            public int compare(final SelectItem o1, final SelectItem o2) {
              return o1.getLabel().compareToIgnoreCase(o1.getLabel());
            }
          });
      availableCryptoTokens.add(
          0,
          new SelectItem(
              null,
              getEjbcaWebBean()
                  .getText("PLEASE_SELECT_ENCRYPTION_CRYPTOTOKEN")));
    }
    return availableCryptoTokens;
  }

  /** Select. */
  public void selectLocalKeyRecoveryCryptoToken() {
    availableKeyAliases = null; // force reload
    currentConfig.setLocalKeyRecoveryKeyAlias(null);
    getAvailableKeyAliases();
  }

  /**
   * @return bool
   */
  public boolean getHasSelectedCryptoToken() {
    return currentConfig.getLocalKeyRecoveryCryptoTokenId() != 0;
  }

  /**
   * @return Aliases
   */
  public List<SelectItem> getAvailableKeyAliases() {
    if (availableKeyAliases == null) {
      availableKeyAliases = new ArrayList<>();
      if (currentConfig.getLocalKeyRecoveryCryptoTokenId() != 0) {
        try {
          final List<String> aliases =
              new ArrayList<>(
                  cryptoTokenManagementSession.getKeyPairAliases(
                      getEjbcaWebBean().getAdminObject(),
                      currentConfig.getLocalKeyRecoveryCryptoTokenId()));
          Collections.sort(aliases);
          for (final String keyAlias : aliases) {
            if (currentConfig.getLocalKeyRecoveryKeyAlias() == null
                && keyAlias != null
                && (keyAlias.startsWith("default")
                    || keyAlias.startsWith("privatedec"))) {
              currentConfig.setLocalKeyRecoveryKeyAlias(keyAlias);
            }
            availableKeyAliases.add(new SelectItem(keyAlias));
          }
          availableKeyAliases.add(
              0,
              new SelectItem(
                  null, getEjbcaWebBean().getText("PLEASE_SELECT_KEY")));
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
          LOG.debug("Crypto Token is not usable. Can't list key aliases", e);
        }
      }
    }
    return availableKeyAliases;
  }

  /** @return a list of all currently connected nodes in a cluster */
  public ListDataModel<String> getNodesInCluster() {
    if (nodesInCluster == null) {
      List<String> nodesList =
          getListFromSet(currentConfig.getNodesInCluster());
      nodesInCluster = new ListDataModel<>(nodesList);
    }
    return nodesInCluster;
  }

  /** Invoked when the user wants to a add a new node to the cluster. */
  public void addNode() {
    final String nodeToAdd = getCurrentNode();
    Set<String> nodes = currentConfig.getNodesInCluster();
    nodes.add(nodeToAdd);
    currentConfig.setNodesInCluster(nodes);
    nodesInCluster = new ListDataModel<>(getListFromSet(nodes));
  }

  /** Invoked when the user wants to remove a node from the cluster. */
  public void removeNode() {
    final String nodeToRemove = nodesInCluster.getRowData();
    Set<String> nodes = currentConfig.getNodesInCluster();
    nodes.remove(nodeToRemove);
    currentConfig.setNodesInCluster(nodes);
    nodesInCluster = new ListDataModel<>(getListFromSet(nodes));
  }

  private List<String> getListFromSet(final Set<String> set) {
    List<String> list = new ArrayList<>();
    if (set != null && !set.isEmpty()) {
      for (String entry : set) {
        list.add(entry);
      }
    }
    return list;
  }

  // --------------------------------------------
  //               Protocol Configuration
  // --------------------------------------------

  /**
   * @return config
   */
  public AvailableProtocolsConfiguration getAvailableProtocolsConfiguration() {
    return (AvailableProtocolsConfiguration)
        getEjbcaWebBean()
            .getEjb()
            .getGlobalConfigurationSession()
            .getCachedConfiguration(
                AvailableProtocolsConfiguration.CONFIGURATION_ID);
  }

  /**
   * @param protocolToToggle Toggle
   */
  public void toggleProtocolStatus(final ProtocolGuiInfo protocolToToggle) {
    final AvailableProtocolsConfiguration availableProtocolsConfiguration =
        getAvailableProtocolsConfiguration();
    if (protocolToToggle.isEnabled()) {
      availableProtocolsConfiguration.setProtocolStatus(
          protocolToToggle.getProtocol(), false);
    } else {
      availableProtocolsConfiguration.setProtocolStatus(
          protocolToToggle.getProtocol(), true);
    }
    // Save config
    try {
      getEjbcaWebBean()
          .getEjb()
          .getGlobalConfigurationSession()
          .saveConfiguration(getAdmin(), availableProtocolsConfiguration);
    } catch (AuthorizationDeniedException e) {
      String msg =
          "Cannot save System Configuration. " + e.getLocalizedMessage();
      LOG.info("Administrator '" + getAdmin() + "' " + msg);
      super.addNonTranslatedErrorMessage(msg);
    }
  }

  /**
   * @return info
   */
  public ArrayList<ProtocolGuiInfo> getAvailableProtocolInfos() {
    ArrayList<ProtocolGuiInfo> protocolInfos = new ArrayList<>();
    LinkedHashMap<String, Boolean> allPC =
        getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
    for (Entry<String, Boolean> entry : allPC.entrySet()) {
      protocolInfos.add(new ProtocolGuiInfo(entry.getKey(), entry.getValue()));
    }
    return protocolInfos;
  }

  /**
   * @return true if CRLStore is deployed. Determined by crlstore.properties
   *     file
   */
  public boolean isCrlStoreAvailable() {
    return WebConfiguration.isCrlStoreEnabled();
  }

  /**
   * @return true if CRLStore is deployed. Determined by crlstore.properties
   *     file
   */
  public boolean isCertStoreAvailable() {
    return WebConfiguration.isCertStoreEnabled();
  }

  /** @return true if EST is enabled. Should be false for EJBCA CE */
  public boolean isEstAvailable() {
    return getEjbcaWebBean().isRunningEnterprise();
  }

  /** @return true if REST is enabled. Should be false for EJBCA CE */
  public boolean isRestAvailable() {
    return getEjbcaWebBean().isRunningEnterprise();
  }

  /** @return true if ACME is enabled. Should be false for EJBCA CE */
  public boolean isAcmeAvailable() {
    return getEjbcaWebBean().isRunningEnterprise();
  }

  public class ProtocolGuiInfo {
      /** PAram. */
    private final String protocol;
    /** PAram. */
    private final String url;
    /** PAram. */
    private final boolean enabled;
    /** PAram. */
    private boolean available;

    /**
     * @param aprotocol Protocol
     * @param isenabled Bool
     */
    public ProtocolGuiInfo(final String aprotocol, final boolean isenabled) {
      this.protocol = aprotocol;
      this.enabled = isenabled;
      this.url = AvailableProtocols.getContextPathByName(aprotocol);
      this.available = true;
    }

    /** @return user friendly protocol/service name */
    public String getProtocol() {
      return protocol;
    }

    /** @return URL to service */
    public String getUrl() {
      return url;
    }

    /** @return true if protocol is enabled */
    public boolean isEnabled() {
      return enabled;
    }

    /** @return true if service is available in the deployed instance */
    public boolean isAvailable() {
      // This is only applicable to services/protocols which may be unavailable
      // for some installations,
      // such as community edition or installations where CRLStore is disabled
      // by .properties file.
      if (protocol.equals(AvailableProtocols.CRL_STORE.getName())
          && !isCrlStoreAvailable()) {
        available = false;
      }
      if (protocol.equals(AvailableProtocols.CERT_STORE.getName())
          && !isCertStoreAvailable()) {
        available = false;
      }
      if (protocol.equals(AvailableProtocols.EST.getName())
          && !isEstAvailable()) {
        available = false;
      }
      if (protocol.equals(AvailableProtocols.REST.getName())
          && !isRestAvailable()) {
        available = false;
      }
      if (protocol.equals(AvailableProtocols.ACME.getName())
          && !isAcmeAvailable()) {
        available = false;
      }
      return available;
    }

    /**
     * @return user friendly status text. 'Enabled', 'Disabled' or 'Unavailable'
     *     if module isn't deployed
     */
    public String getStatus() {
      if (!isAvailable()) {
        return getEjbcaWebBean().getText("PC_STATUS_UNAVAILABLE");
      }
      return enabled
          ? getEjbcaWebBean().getText("PC_STATUS_ENABLED")
          : getEjbcaWebBean().getText("PC_STATUS_DISABLED");
    }
  }

  // --------------------------------------------
  //               Extended Key Usage
  // --------------------------------------------

  /** PAram. */
  private AvailableExtendedKeyUsagesConfiguration
      availableExtendedKeyUsagesConfig = null;
  /** PAram. */
  private ListDataModel<EKUInfo> availableExtendedKeyUsages = null;
  /** PAram. */
  private String currentEKUOid = "";
  /** PAram. */
  private String currentEKUName = "";

  /**
   * @return OID
   */
  public String getCurrentEKUOid() {
    return currentEKUOid;
  }

  /**
   * @param oid OID
   */
  public void setCurrentEKUOid(final String oid) {
    currentEKUOid = oid;
  }

  /**
   * @return name
   */
  public String getCurrentEKUReadableName() {
    return currentEKUName;
  }

  /**
   * @param readableName name
   */
  public void setCurrentEKUReadableName(final String readableName) {
    currentEKUName = readableName;
  }

  private void flushNewEKUCache() {
    currentEKUOid = "";
    currentEKUName = "";
  }

  private AvailableExtendedKeyUsagesConfiguration getAvailableEKUConfig() {
    if (availableExtendedKeyUsagesConfig == null) {
      availableExtendedKeyUsagesConfig =
          getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
    }
    return availableExtendedKeyUsagesConfig;
  }

  /**
   * @return OID
   */
  public String getEKUOid() {
    return availableExtendedKeyUsages.getRowData().getOid();
  }

  /**
   * @return name
   */
  public String getEKUName() {
    return availableExtendedKeyUsages.getRowData().getName();
  }

  /**
   * @return Usage
   */
  public ListDataModel<EKUInfo> getAvailableExtendedKeyUsages() {
    if (availableExtendedKeyUsages == null) {
      availableExtendedKeyUsages =
          new ListDataModel<>(getNewAvailableExtendedKeyUsages());
    }
    return availableExtendedKeyUsages;
  }

  private ArrayList<EKUInfo> getNewAvailableExtendedKeyUsages() {
    availableExtendedKeyUsagesConfig =
        getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
    ArrayList<EKUInfo> ekus = new ArrayList<>();
    Map<String, String> allEKU =
        availableExtendedKeyUsagesConfig.getAllEKUOidsAndNames();
    for (Entry<String, String> entry : allEKU.entrySet()) {
      ekus.add(
          new EKUInfo(
              entry.getKey(), getEjbcaWebBean().getText(entry.getValue())));
    }
    Collections.sort(
        ekus,
        new Comparator<EKUInfo>() {
          @Override
          public int compare(final EKUInfo ekuInfo1, final EKUInfo ekuInfo2) {
            String[] oidFirst = ekuInfo1.getOid().split("\\.");
            String[] oidSecond = ekuInfo2.getOid().split("\\.");
            int length = Math.min(oidFirst.length, oidSecond.length);
            try {
              for (int i = 0; i < length; i++) {
                if (!StringUtils.equals(oidFirst[i], oidSecond[i])) {
                  if (Integer.parseInt(oidFirst[i])
                      < Integer.parseInt(oidSecond[i])) {
                    return -1;
                  }
                  return 1;
                }
              }
            } catch (NumberFormatException e) {
              LOG.error(
                  "OID contains non-numerical values. This should not happen"
                      + " at this point");
            }

            if (oidFirst.length != oidSecond.length) {
              return oidFirst.length < oidSecond.length ? -1 : 1;
            }

            return 0;
          }
        });
    return ekus;
  }

  /** Add. */
  public void addEKU() {

    if (StringUtils.isEmpty(currentEKUOid)) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No ExtendedKeyUsage OID is set.",
                  null));
      return;
    }
    if (!isOidNumericalOnly(currentEKUOid)) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "OID " + currentEKUOid + " contains non-numerical values.",
                  null));
      return;
    }
    if (StringUtils.isEmpty(currentEKUName)) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No ExtendedKeyUsage Name is set.",
                  null));
      return;
    }

    AvailableExtendedKeyUsagesConfiguration ekuConfig = getAvailableEKUConfig();
    ekuConfig.addExtKeyUsage(currentEKUOid, currentEKUName);
    try {
      getEjbcaWebBean().saveAvailableExtendedKeyUsagesConfiguration(ekuConfig);
      availableExtendedKeyUsages =
          new ListDataModel<>(getNewAvailableExtendedKeyUsages());
    } catch (Exception e) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Failed to save AvailableExtendedKeyUsagesConfiguration.",
                  e.getLocalizedMessage()));
      return;
    }
    flushNewEKUCache();
  }

  /** Remove. */
  public void removeEKU() {
    final EKUInfo ekuToRemove = (availableExtendedKeyUsages.getRowData());
    final String oid = ekuToRemove.getOid();
    AvailableExtendedKeyUsagesConfiguration ekuConfig = getAvailableEKUConfig();
    ekuConfig.removeExtKeyUsage(oid);
    try {
      getEjbcaWebBean().saveAvailableExtendedKeyUsagesConfiguration(ekuConfig);
    } catch (Exception e) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Failed to save AvailableExtendedKeyUsagesConfiguration: "
                      + e.getLocalizedMessage(),
                  null));
      return;
    }
    availableExtendedKeyUsages =
        new ListDataModel<>(getNewAvailableExtendedKeyUsages());

    ArrayList<String> cpNamesUsingEKU = getCertProfilesUsingEKU(oid);
    if (!cpNamesUsingEKU.isEmpty()) {
      final String cpNamesMessage =
          getCertProfilesNamesMessage(cpNamesUsingEKU);
      final String message =
          "ExtendedKeyUsage '"
              + ekuToRemove.getName()
              + "' has been removed, but is still used in the following"
              + " certitifcate profiles: "
              + cpNamesMessage;
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(FacesMessage.SEVERITY_WARN, message, null));
    }
  }

  private ArrayList<String> getCertProfilesUsingEKU(final String oid) {
    ArrayList<String> ret = new ArrayList<>();
    final CertificateProfileSessionLocal certprofileSession =
        getEjbcaWebBean().getEjb().getCertificateProfileSession();
    Map<Integer, CertificateProfile> allCertProfiles =
        certprofileSession.getAllCertificateProfiles();
    for (Entry<Integer, CertificateProfile> entry
        : allCertProfiles.entrySet()) {
      final CertificateProfile cp = entry.getValue();
      List<String> ekuOids = cp.getExtendedKeyUsageOids();
      if (ekuOids.contains(oid)) {
        ret.add(certprofileSession.getCertificateProfileName(entry.getKey()));
      }
    }
    return ret;
  }

  private String getCertProfilesNamesMessage(
      final ArrayList<String> certProfileNames) {
    int nrOfProfiles = certProfileNames.size();
    int nrOfdisplayedProfiles = nrOfProfiles > 10 ? 10 : nrOfProfiles;

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < nrOfdisplayedProfiles; i++) {
      sb.append(" " + certProfileNames.get(i) + ",");
    }
    sb.deleteCharAt(sb.length() - 1);
    if (nrOfProfiles > nrOfdisplayedProfiles) {
      sb.append(
          " and "
              + (nrOfProfiles - nrOfdisplayedProfiles)
              + " more certificate profiles.");
    }
    return sb.toString();
  }

  private boolean isOidNumericalOnly(final String oid) {
    String[] oidParts = oid.split("\\.");
    for (int i = 0; i < oidParts.length; i++) {
      if (oidParts[i].equals("*")) {
        // Allow wildcard characters
        continue;
      }
      try {
        Integer.parseInt(oidParts[i]);
      } catch (NumberFormatException e) {
        return false;
      }
    }
    return true;
  }

  // ----------------------------------------------------
  //               Custom RA Styles
  // ----------------------------------------------------

  /** Param. */
  private GlobalCustomCssConfiguration globalCustomCssConfiguration = null;
  /** Param. */
  private ListDataModel<RaStyleInfo> raStyleInfos = null;
  /** Param. */
  private List<RaStyleInfo> raStyleInfosList;
  /** Param. */
  private UploadedFile raCssFile = null;
  /** Param. */
  private UploadedFile raLogoFile = null;
  /** Param. */
  private Map<String, RaCssInfo> importedRaCssInfos = null;
  /** Param. */
  private String archiveName = null;
  /** Param. */
  private String logoName = null;
  /** Param. */
  private byte[] logoBytes = null;

  /**
   * @return Config
   */
  public GlobalCustomCssConfiguration getGlobalCustomCssConfiguration() {
    if (globalCustomCssConfiguration == null) {
      globalCustomCssConfiguration =
          (GlobalCustomCssConfiguration)
              getEjbcaWebBean()
                  .getEjb()
                  .getGlobalConfigurationSession()
                  .getCachedConfiguration(
                      GlobalCustomCssConfiguration.CSS_CONFIGURATION_ID);
    }
    return globalCustomCssConfiguration;
  }

  /** Import. */
  public void actionImportRaStyle() {
    // Basic checks
    if (raCssFile == null && raLogoFile == null) {
      addErrorMessage("NOFILESELECTED");
      return;
    }
    if (archiveName == null || archiveName.equals("")) {
      addErrorMessage("STYLENONAME");
      return;
    }
    if (raStyleNameExists(archiveName)) {
      addErrorMessage("STYLEEXISTS", archiveName);
      return;
    }

    try {
      // Authorazation check
      if (!isAllowedToEditSystemConfiguration()) {
        addErrorMessage("CSS_NOT_AUTH");
        LOG.info(
            "Administrator '"
                + getAdmin()
                + "' attempted to import css / logo files. Authorazation"
                + " denied: Insufficient privileges");
        return;
      }
      if (raCssFile != null) {
        // File is selected but something went wrong. Import nothing!
        importCssFromFile();
        if (importedRaCssInfos == null) {
          return;
        }
      }
      if (raLogoFile != null) {
        importLogoFromImageFile();
        // File is selected but something went wrong. Import nothing!
        if (logoBytes == null) {
          return;
        }
      }

      RaStyleInfo importedRaStyleInfo =
          new RaStyleInfo(archiveName, importedRaCssInfos, logoBytes, logoName);
      if (raLogoFile != null) {
        importedRaStyleInfo.setLogoContentType(raLogoFile.getContentType());
      }
      raStyleInfosList.add(importedRaStyleInfo);
      raStyleInfos = new ListDataModel<>(raStyleInfosList);
      saveCustomCssConfiguration();
      importedRaCssInfos = null;
      logoBytes = null;
      logoName = null;

    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
      addErrorMessage("STYLEIMPORTFAIL", e.getLocalizedMessage());
      LOG.info("Failed to import style files", e);
    }
  }

  private boolean raStyleNameExists(final String name) {
    LinkedHashMap<Integer, RaStyleInfo> storedRaStyles =
        globalCustomCssConfiguration.getRaStyleInfo();
    for (Map.Entry<Integer, RaStyleInfo> raStyle : storedRaStyles.entrySet()) {
      if (raStyle.getValue().getArchiveName().equals(name)) {
        return true;
      }
    }
    return false;
  }

  private void importLogoFromImageFile() throws IOException {
    String contentType = raLogoFile.getContentType();
    if (!contentType.equals("image/jpeg") && !contentType.equals("image/png")) {
      addErrorMessage("LOGOIMPORTIGNORE", raLogoFile.getName());
      return;
    }
    logoName = raLogoFile.getName();
    logoBytes = raLogoFile.getBytes();
    addInfoMessage("LOGOIMPORTSUCCESS", logoName);
  }

  private void importCssFromFile()
      throws IOException, IllegalArgumentException, IllegalStateException {
    byte[] fileBuffer = raCssFile.getBytes();
    if (fileBuffer.length == 0) {
      throw new IllegalArgumentException("Empty input file");
    }
    String importedFiles = "";
    String ignoredFiles = "";
    int numberOfZipEntries = 0;
    int numberOfImportedFiles = 0;
    int numberOfignoredFiles = 0;
    Map<String, RaCssInfo> raCssInfosMap = new HashMap<>();
    try (ZipInputStream zis =
        new ZipInputStream(new ByteArrayInputStream(fileBuffer))) {
      ZipEntry ze;
      // Read each zip entry
      while ((ze = zis.getNextEntry()) != null) {
        String fileName = ze.getName();
        if (LOG.isDebugEnabled()) {
          LOG.debug("Reading zip entry: " + fileName);
        }
        try {
          fileName = URLDecoder.decode(fileName, "UTF-8");
        } catch (UnsupportedEncodingException e) {
          throw new IllegalStateException(
              "UTF-8 was not a known character encoding", e);
        }
        numberOfZipEntries++;
        if (!ze.getName().endsWith(".css")) {
          LOG.info(
              fileName
                  + " not recognized as a css file. Expected file extension"
                  + " '.css'. Skipping...");
          numberOfignoredFiles++;
          ignoredFiles += ze.getName() + ", ";
          continue;
        }
        // Extract bytes from this entry
        byte[] filebytes = new byte[(int) ze.getSize()];
        int i = 0;
        while ((zis.available() == 1) && (i < filebytes.length)) {
          filebytes[i++] = (byte) zis.read();
        }
        RaCssInfo raCssInfo = new RaCssInfo(filebytes, fileName);
        raCssInfosMap.put(fileName, raCssInfo);
        importedFiles += fileName + ", ";
        numberOfImportedFiles++;
      }
    }
    if (numberOfZipEntries == 0 && raCssFile.getName().endsWith(".css")) {
      // Single file selected (not zip)
      raCssInfosMap.put(
          raCssFile.getName(),
          new RaCssInfo(raCssFile.getBytes(), raCssFile.getName()));
      numberOfImportedFiles++;
      importedFiles = raCssFile.getName();
    } else if (numberOfZipEntries == 0) {
      addErrorMessage("ISNOTAZIPFILE");
      return;
    }
    if (numberOfignoredFiles == 0) {
      addInfoMessage("CSSIMPORTSUCCESS", numberOfImportedFiles, importedFiles);
    } else {
      addInfoMessage(
          "CSSIMPORTIGNORED",
          numberOfImportedFiles,
          importedFiles,
          numberOfignoredFiles,
          ignoredFiles);
    }
    importedRaCssInfos = raCssInfosMap;
  }

  /** Remove. */
  public void removeRaStyleInfo() {
    final RaStyleInfo styleToRemove = raStyleInfos.getRowData();
    List<RaStyleInfo> raCssInfosList = getRaStyleInfosList();
    raCssInfosList.remove(styleToRemove);
    setRaStyleInfosList(raCssInfosList);
    raStyleInfos = new ListDataModel<>(raCssInfosList);
    saveCustomCssConfiguration();
  }

  /**
   * @return file
   */
  public UploadedFile getRaCssFile() {
    return raCssFile;
  }

  /**
   * @param anraCssFile file
   */
  public void setRaCssFile(final UploadedFile anraCssFile) {
    this.raCssFile = anraCssFile;
  }

  /**
   * @return file
   */
  public UploadedFile getRaLogoFile() {
    return raLogoFile;
  }

  /**
   * @param anraLogoFile file
   */
  public void setRaLogoFile(final UploadedFile anraLogoFile) {
    this.raLogoFile = anraLogoFile;
  }

  /**
   * @return name
   */
  public String getArchiveName() {
    return archiveName;
  }

  /**
   * @param anarchiveName name
   */
  public void setArchiveName(final String anarchiveName) {
    this.archiveName = anarchiveName;
  }

  // Necessary for front end row handling etc.
  /**
   * @return info
   */
  public ListDataModel<RaStyleInfo> getRaStyleInfos() {
    if (raStyleInfos == null) {
      List<RaStyleInfo> raCssInfosList = getRaStyleInfosList();
      raStyleInfos = new ListDataModel<>(raCssInfosList);
    }
    return raStyleInfos;
  }

  /**
   * @return info
   */
  public List<RaStyleInfo> getRaStyleInfosList() {
    raStyleInfosList =
        new ArrayList<>(
            getGlobalCustomCssConfiguration().getRaStyleInfo().values());
    return raStyleInfosList;
  }

  /**
   * @param theraStyleInfos Info
   */
  public void setRaStyleInfosList(final List<RaStyleInfo> theraStyleInfos) {
    raStyleInfosList = theraStyleInfos;
  }

  private void saveCustomCssConfiguration() {
    LinkedHashMap<Integer, RaStyleInfo> raStyleMap = new LinkedHashMap<>();
    for (RaStyleInfo raStyleInfo : raStyleInfosList) {
      raStyleMap.put(raStyleInfo.getArchiveId(), raStyleInfo);
    }
    globalCustomCssConfiguration.setRaStyle(raStyleMap);
    try {
      getEjbcaWebBean()
          .getEjb()
          .getGlobalConfigurationSession()
          .saveConfiguration(getAdmin(), globalCustomCssConfiguration);
    } catch (AuthorizationDeniedException e) {
      String msg =
          "Cannot save System Configuration. " + e.getLocalizedMessage();
      LOG.info("Administrator '" + getAdmin() + "' " + msg);
      super.addNonTranslatedErrorMessage(msg);
    }
  }

  // ----------------------------------------------------
  //               Custom Certificate Extensions
  // ----------------------------------------------------

  /** Param. */
  private final String defaultExtClasspath =
      "org.cesecore.certificates.certificate"
      + ".certextensions.BasicCertificateExtension";
  /** Param. */
  private AvailableCustomCertificateExtensionsConfiguration
      availableCustomCertExtensionsConfig = null;
  /** Param. */
  private ListDataModel<CustomCertExtensionInfo> availableCustomCertExtensions =
      null;
  /** Param. */
  private int selectedCustomCertExtensionID = 0;
  /** Param. */
  private String newOID = "";
  /** Param. */
  private String newDisplayName = "";

  /**
   * @return ID
   */
  public int getSelectedCustomCertExtensionID() {
    return selectedCustomCertExtensionID;
  }

  /**
   * @param id ID
   */
  public void setSelectedCustomCertExtensionID(final int id) {
    selectedCustomCertExtensionID = id;
  }

  /**
   * @return OID
   */
  public String getNewOID() {
    return newOID;
  }
/**
 * @param oid OID
 */
  public void setNewOID(final String oid) {
    newOID = oid;
  }

  /**
   * @return label
   */
  public String getNewDisplayName() {
    return newDisplayName;
  }

  /**
   * @param label label
   */
  public void setNewDisplayName(final String label) {
    newDisplayName = label;
  }

  private void flushNewExtensionCache() {
    newOID = "";
    newDisplayName = "";
  }

  private AvailableCustomCertificateExtensionsConfiguration
      getAvailableCustomCertExtensionsConfig() {
    if (availableCustomCertExtensionsConfig == null) {
      availableCustomCertExtensionsConfig =
          getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
    }
    return availableCustomCertExtensionsConfig;
  }

  /**
   * @return info
   */
  public ListDataModel<CustomCertExtensionInfo>
      getAvailableCustomCertExtensions() {
    availableCustomCertExtensions =
        new ListDataModel<>(getNewAvailableCustomCertExtensions());
    return availableCustomCertExtensions;
  }

  /**
   * @return info
   */
  private ArrayList<CustomCertExtensionInfo>
      getNewAvailableCustomCertExtensions() {
    availableCustomCertExtensionsConfig =
        getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
    ArrayList<CustomCertExtensionInfo> extensionsInfo = new ArrayList<>();
    Collection<CertificateExtension> allExtensions =
        availableCustomCertExtensionsConfig
            .getAllAvailableCustomCertificateExtensions();
    for (CertificateExtension extension : allExtensions) {
      extensionsInfo.add(new CustomCertExtensionInfo(extension));
    }

    Collections.sort(
        extensionsInfo,
        new Comparator<CustomCertExtensionInfo>() {
          @Override
          public int compare(
              final CustomCertExtensionInfo first,
              final CustomCertExtensionInfo second) {
            return Integer.compare(first.getId(), second.getId());
          }
        });

    return extensionsInfo;
  }

  /** Remove. */
  public void removeCustomCertExtension() {
    final CustomCertExtensionInfo extensionToRemove =
        availableCustomCertExtensions.getRowData();
    final int extID = extensionToRemove.getId();
    AvailableCustomCertificateExtensionsConfiguration cceConfig =
        getAvailableCustomCertExtensionsConfig();
    cceConfig.removeCustomCertExtension(extID);
    try {
      getEjbcaWebBean()
          .saveAvailableCustomCertExtensionsConfiguration(cceConfig);
    } catch (Exception e) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Failed to save"
                      + " AvailableCustomCertificateExtensionsConfiguration: "
                      + e.getLocalizedMessage(),
                  null));
      return;
    }
    availableCustomCertExtensions =
        new ListDataModel<>(getNewAvailableCustomCertExtensions());

    final ArrayList<String> cpNamedUsingExtension =
        getCertProfilesUsingExtension(extID);
    if (!cpNamedUsingExtension.isEmpty()) {
      final String cpNamesMessage =
          getCertProfilesNamesMessage(cpNamedUsingExtension);
      final String message =
          "CustomCertificateExtension '"
              + extensionToRemove.getDisplayName()
              + "' has been removed, but it is still used in the following"
              + " certitifcate profiles: "
              + cpNamesMessage;
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(FacesMessage.SEVERITY_WARN, message, null));
    }
  }

  /** Add.
   */
  public void addCustomCertExtension() {
    String anewOID = getNewOID();
    if (StringUtils.isEmpty(anewOID)) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No CustomCertificateExenstion OID is set.",
                  null));
      return;
    }
    if (!isOidNumericalOnly(anewOID)) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "OID " + currentEKUOid + " contains non-numerical values.",
                  null));
      return;
    }

    AvailableCustomCertificateExtensionsConfiguration cceConfig =
        getAvailableCustomCertExtensionsConfig();

    int newID = generateNewExtensionID(cceConfig);
    if (newID == Integer.MAX_VALUE) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Cannot add more extensions. There are already "
                      + cceConfig
                          .getAllAvailableCustomCertificateExtensions()
                          .size()
                      + " extensions.",
                  null));
      return;
    }

    if (StringUtils.isEmpty(getNewDisplayName())) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No CustomCertificateExension Label is set.",
                  null));
      return;
    }

    try {
      cceConfig.addCustomCertExtension(
          newID,
          anewOID,
          getNewDisplayName(),
          defaultExtClasspath,
          false,
          true,
          new Properties());
      getEjbcaWebBean()
          .saveAvailableCustomCertExtensionsConfiguration(cceConfig);
    } catch (Exception e) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Failed to add Custom Certificate Extension. "
                      + e.getLocalizedMessage(),
                  e.getLocalizedMessage()));
      return;
    }
    availableCustomCertExtensions =
        new ListDataModel<>(getNewAvailableCustomCertExtensions());
    flushNewExtensionCache();
    flushCache();
  }

  /**
   * @return edit
   */
  public String actionEdit() {
    selectCurrentRowData();
    customCertificateExtensionViewMode = false;
    return "edit"; // Outcome is defined in faces-config.xml
  }

  /**
   * @return view
   */
  public String actionView() {
    selectCurrentRowData();
    customCertificateExtensionViewMode = true;
    return "view"; // Outcome is defined in faces-config.xml
  }

  /**
   * @return mode
   */
  public boolean getCustomCertificateExtensionViewMode() {
    return customCertificateExtensionViewMode;
  }

  private void selectCurrentRowData() {
    final CustomCertExtensionInfo cceInfo =
        availableCustomCertExtensions.getRowData();
    selectedCustomCertExtensionID = cceInfo.getId();
  }

  private int generateNewExtensionID(
      final AvailableCustomCertificateExtensionsConfiguration cceConfig) {
    final CertificateProfileSessionLocal certprofileSession =
        getEjbcaWebBean().getEjb().getCertificateProfileSession();
    Map<Integer, CertificateProfile> allCertProfiles =
        certprofileSession.getAllCertificateProfiles();

    int i = 0;
    while ((cceConfig.isCustomCertExtensionSupported(i)
            || isExtensionUsedInCertProfiles(i, allCertProfiles))
        && (i < Integer.MAX_VALUE)) {
      i++;
    }
    return i;
  }

  private boolean isExtensionUsedInCertProfiles(
      final int id, final Map<Integer, CertificateProfile> allCertProfiles) {
    for (Entry<Integer, CertificateProfile> entry
        : allCertProfiles.entrySet()) {
      final CertificateProfile cp = entry.getValue();
      List<Integer> usedCertExts = cp.getUsedCertificateExtensions();
      if (usedCertExts.contains(id)) {
        return true;
      }
    }
    return false;
  }

  private ArrayList<String> getCertProfilesUsingExtension(final int id) {
    ArrayList<String> ret = new ArrayList<>();
    final CertificateProfileSessionLocal certprofileSession =
        getEjbcaWebBean().getEjb().getCertificateProfileSession();
    Map<Integer, CertificateProfile> allCertProfiles =
        certprofileSession.getAllCertificateProfiles();
    for (Entry<Integer, CertificateProfile> entry
        : allCertProfiles.entrySet()) {
      final CertificateProfile cp = entry.getValue();
      List<Integer> usedCertExts = cp.getUsedCertificateExtensions();
      if (usedCertExts.contains(id)) {
        ret.add(certprofileSession.getCertificateProfileName(entry.getKey()));
      }
    }
    return ret;
  }

  /** @return true if admin may create new or modify System Configuration. */
  public boolean isAllowedToEditSystemConfiguration() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
  }

  /**
   * @return true if admin may create new or modify existing Extended Key
   *     Usages.
   */
  public boolean isAllowedToEditExtendedKeyUsages() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.EKUCONFIGURATION_EDIT.resource());
  }

  /**
   * @return true if admin may create new or modify existing Custom Certificate
   *     Extensions.
   */
  public boolean isAllowedToEditCustomCertificateExtension() {
    return authorizationSession.isAuthorizedNoLogging(
        getAdmin(),
        StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource());
  }

  // ------------------------------------------------
  //             Drop-down menu options
  // ------------------------------------------------
  /** @return a list of all CA names */
  public List<SelectItem> getAvailableCAsAndNoEncryptionOption() {
    final List<SelectItem> ret = getAvailableCAs();
    ret.add(new SelectItem(0, "No encryption"));
    return ret;
  }

  /** @return a list of all CA names and caids */
  public List<SelectItem> getAvailableCAs() {
    final List<SelectItem> ret = new ArrayList<>();
    Map<Integer, String> caidToName = caSession.getCAIdToNameMap();
    List<Integer> allCaIds = caSession.getAllCaIds();
    for (int caid : allCaIds) {
      if (caSession.authorizedToCANoLogging(getAdmin(), caid)) {
        String caname = caidToName.get(caid);
        ret.add(new SelectItem(caid, caname));
      } else {
        ret.add(
            new SelectItem(
                0,
                "<Unauthorized CA>",
                "A CA that the current admin lack access to.",
                true));
      }
    }
    return ret;
  }

  /**
   * @return Langs
   */
  public List<SelectItem> getAvailableLanguages() {
    final List<SelectItem> ret = new ArrayList<>();
    final String[] availableLanguages =
        getEjbcaWebBean().getAvailableLanguages();
    final String[] availableLanguagesEnglishNames =
        getEjbcaWebBean().getLanguagesEnglishNames();
    final String[] availableLanguagesNativeNames =
        getEjbcaWebBean().getLanguagesNativeNames();
    for (int i = 0; i < availableLanguages.length; i++) {
      String output = availableLanguagesEnglishNames[i];
      if (availableLanguagesNativeNames[i] != null) {
        output += " - " + availableLanguagesNativeNames[i];
      }
      output += " [" + availableLanguages[i] + "]";
      ret.add(new SelectItem(i, output));
    }
    return ret;
  }

  /**
   * @return teams
   */
  public List<SelectItem> getAvailableThemes() {
    final List<SelectItem> ret = new ArrayList<>();
    final String[] themes = globalConfig.getAvailableThemes();
    for (String theme : themes) {
      ret.add(new SelectItem(theme, theme));
    }
    return ret;
  }

  /**
   * @return entries
   */
  public List<SelectItem> getPossibleEntriesPerPage() {
    final List<SelectItem> ret = new ArrayList<>();
    final String[] possibleValues = globalConfig.getPossibleEntiresPerPage();
    for (String value : possibleValues) {
      ret.add(new SelectItem(Integer.parseInt(value), value));
    }
    return ret;
  }

  /**
   * @return tabs
   */
  public List<String> getAvailableTabs() {
    final List<String> availableTabs = new ArrayList<>();
    if (authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
      availableTabs.add("Basic Configurations");
      availableTabs.add("Administrator Preferences");
    }
    if (authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
      availableTabs.add("Protocol Configuration");
    }
    if (authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource())) {
      availableTabs.add("Extended Key Usages");
    }
    if (authorizationSession.isAuthorizedNoLogging(
            getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())
        && CertificateTransparencyFactory.isCTAvailable()) {
      availableTabs.add("Certificate Transparency Logs");
    }
    if (authorizationSession.isAuthorizedNoLogging(
        getAdmin(),
        StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource())) {
      availableTabs.add("Custom Certificate Extensions");
    }
    if (authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.ROLE_ROOT.resource())) {
      availableTabs.add("Custom RA Styles");
    }
    if (authorizationSession.isAuthorizedNoLogging(
            getAdmin(), StandardRules.ROLE_ROOT.resource())
        && isStatedumpAvailable()) {
      availableTabs.add("Statedump");
    }
    if (authorizationSession.isAuthorizedNoLogging(
        getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
      availableTabs.add("External Scripts");
    }
    return availableTabs;
  }
}
