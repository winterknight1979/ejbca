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

package org.ejbca.config;

import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.config.ExternalScriptsConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.util.StringTools;

/**
 * This is a class containing global configuration parameters.
 *
 * @version $Id: GlobalConfiguration.java 31276 2019-01-21 23:52:29Z jeklund $
 */
public class GlobalConfiguration extends ConfigurationBase
    implements ExternalScriptsConfiguration, Serializable {

  private static final long serialVersionUID = -2051789798029184421L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(GlobalConfiguration.class);

  // Default Values
  /** Config. */
  public static final float LATEST_VERSION = 3f;

  /** Config. */
  public static final String EJBCA_VERSION =
      InternalConfiguration.getAppVersion();

  /** Config. */
  public static final String PREFEREDINTERNALRESOURCES =
      CesecoreConfigurationHelper.getInternalResourcesPreferredLanguage();
  /** Config. */
  public static final String SECONDARYINTERNALRESOURCES =
      CesecoreConfigurationHelper.getInternalResourcesSecondaryLanguage();


  /** Entries to choose from in userpreference part, defines the size of data to
   * be displayed on one page. */
  private final String[] defaultPossibleEntriesPerPage = {
    "10", "25", "50", "100"
  };
  /** Entries to choose from in view log part, defines the size of data to be
   * displayed on one page.*/
  private final String[] defaultPossibleLogEntriesPerPage = {
    "10", "25", "50", "100", "200", "400"
  };

  /** Config. */
  public static final String GLOBAL_CONFIGURATION_ID = "0";

  /** Path added to baseurl used as default value in CRLDistributionPointURI
   * field in Certificate Profile definitions. */
  private static final String DEFAULTCRLDISTURIPATH =
      "publicweb/webdist/certdist?cmd=crl&issuer=";

  /** Path added to baseurl used as default value
   *  in DeltaCRLDistributionPointURI
   * field in Certificate Profile definitions. */
  private static final String DEFAULTDELTACRLDISTURIPATH =
      "publicweb/webdist/certdist?cmd=deltacrl&issuer=";

  /** Path added to baseurl used as default value in CRLDistributionPointURI
   * field in Certificate Profile definitions. */
  private static final String DEFAULTCRLDISTURIPATHDN =
      "CN=TestCA,O=AnaTom,C=SE";

  /** Path added to baseurl used as default value in OCSP Service Locator URI
   * field in Certificate Profile definitions. */
  private static final String DEFAULTOCSPSERVICELOCATORURIPATH =
      "publicweb/status/ocsp";

  /** Default name of headbanner in web interface. */
  public static final String DEFAULTHEADBANNER = "head_banner.jsp";
  /** Default name of footbanner page in web interface. */
  public static final String DEFAULTFOOTBANNER =
      "foot_banner.jsp"; // used from systemconfiguration.jsp

  /** Default list of nodes in cluster. */
  private static final Set<String> NODESINCLUSTER_DEFAULT =
      new LinkedHashSet<>();

  /** Title of ra admin web interface. */
  private static final String DEFAULTEJBCATITLE =
      InternalConfiguration.getAppNameCapital() + " Administration";

  // Default values for AutoEnroll
  /** Config. */
  private static final String AUTOENROLL_DEFAULT_ADSERVER = "dc1.company.local";
  /** Config. */
  private static final int AUTOENROLL_DEFAULT_ADPORT = 0;
  /** Config. */
  private static final String AUTOENROLL_DEFAULT_BASEDN_USER =
      "CN=Users,DC=company,DC=local";
  /** Config. */
  public static final int AUTOENROLL_DEFAULT_CA = -1;
  /** Config. */
  private static final String AUTOENROLL_DEFAULT_CONNECTIONDN =
      "CN=ADReader,CN=Users,DC=company,DC=local";
  /** Config. */
  private static final String AUTOENROLL_DEFAULT_CONNECTIONPWD = "foo123";
  /** Config. */
  private static final boolean AUTOENROLL_DEFAULT_SSLCONNECTION = false;
  /** Config. */
  private static final boolean AUTOENROLL_DEFAULT_USE = false;

  /** Default value for Enable Command Line Interface. */
  private static final boolean DEFAULTENABLECOMMANDLINEINTERFACE = true;

  /** Config. */
  private static final boolean DEFAULTENABLECOMMANDLINEINTERFACEDEFAULTUSER =
      true;

  /** Config. */
  private static final boolean DEFAULTENABLEEXTERNALSCRIPTS = false;

  /** Config. */
  private static final boolean DEFAULTPUBLICWEBCERTCHAINORDEROOTFIRST = true;

  // Default CT Logs
  /** Config. */
  private static final LinkedHashMap<Integer, CTLogInfo> CTLOGS_DEFAULT =
      new LinkedHashMap<>();

  // Language codes. Observe the order is important
  /** Config. */
  public static final int EN = 0;
  /** Config. */
  public static final int SE = 1;

  // Public constants.
  /** Config. */
  public static final String DOCWINDOW =
      "_ejbcaDocWindow"; // Name of browser window used to display help

  // Private constants
  /** Config. */
  private static final String ADMINPATH = "raadminpath";
  /** Config. */
  private static final String AVAILABLELANGUAGES = "availablelanguages";
  /** Config. */
  private static final String AVAILABLETHEMES = "availablethemes";
  /** Config. */
  private static final String PUBLICPORT = "publicport";
  /** Config. */
  private static final String PRIVATEPORT = "privateport";
  /** Config. */
  private static final String PUBLICPROTOCOL = "publicprotocol";
  /** Config. */
  private static final String PRIVATEPROTOCOL = "privateprotocol";

  // Title
  /** Config. */
  private static final String TITLE = "title";

  // Banner files.
  /** Config. */
  private static final String HEADBANNER = "headbanner";
  /** Config. */
  private static final String FOOTBANNER = "footbanner";
  // Other configuration.
  /** Config. */
  private static final String ENABLEEEPROFILELIMITATIONS =
      "endentityprofilelimitations";
  /** Config. */
  private static final String ENABLEAUTHENTICATEDUSERSONLY =
      "authenticatedusersonly";
  /** Config. */
  private static final String ENABLEKEYRECOVERY = "enablekeyrecovery";
  /** Config. */
  private static final String LOCALKEYRECOVERY = "localkeyrecovery";
  /** Config. */
  private static final String LOCALKEYRECOVERYCRYPTOTOKEN =
      "localkeyrecoverycryptotoken";
  /** Config. */
  private static final String LOCALKEYRECOVERYKEYALIAS =
      "localkeyrecoverykeyalias";
  /** Config. */
  private static final String ISSUEHARDWARETOKENS = "issuehardwaretokens";
  /** Config. */

  private static final String ENABLEICAOCANAMECHANGE = "enableicaocanamechange";
  /** Config. */

  private static final String NUMBEROFAPPROVALSTOVIEWPUK =
      "numberofapprovalstoviewpuk";
  /** Config. */
  private static final String HARDTOKENENCRYPTCA = "hardtokenencryptca";
  /** Config. */
  private static final String USEAPPROVALNOTIFICATIONS =
      "useapprovalnotifications";
  /** Config. */
  private static final String APPROVALADMINEMAILADDRESS =
      "approvaladminemailaddress";
  /** Config. */
  private static final String APPROVALNOTIFICATIONFROMADDR =
      "approvalnotificationfromaddr";
  /** Config. */

  private static final String NODESINCLUSTER = "nodesincluster";
  /** Config. */

  private static final String ENABLECOMMANDLINEINTERFACE =
      "enablecommandlineinterface";
  /** Config. */
  private static final String ENABLECOMMANDLINEINTERFACEDEFAULTUSER =
      "enablecommandlineinterfacedefaultuser";
  /** Config. */

  private static final String ENABLEEXTERNALSCRIPTS = "enableexternalscripts";


  // Configuration for Auto Enrollment
  /** Config. */
  private static final String AUTOENROLL_USE = "autoenroll.use";
  /** Config. */
  private static final String AUTOENROLL_ADSERVER = "autoenroll.adserver";
  /** Config. */
  private static final String AUTOENROLL_ADPORT = "autoenroll.adport";
  /** Config. */
  private static final String AUTOENROLL_SSLCONNECTION =
      "autoenroll.sslconnection";
  /** Config. */
  private static final String AUTOENROLL_CONNECTIONDN =
      "autoenroll.connectiondn";
  /** Config. */
  private static final String AUTOENROLL_CONNECTIONPWD =
      "autoenroll.connectionpwd";
  /** Config. */
  private static final String AUTOENROLL_BASEDN_USER = "autoenroll.basedn.user";
  /** Config. */
  private static final String AUTOENROLL_CA = "autoenroll.caid";


  // Paths
  /** Config. */
  private static final String AUTHORIZATION_PATH = "authorization_path";
  /** Config. */
  private static final String BANNERS_PATH = "banners_path";
  /** Config. */
  private static final String CA_PATH = "ca_path";
  /** Config. */
  private static final String CONFIG_PATH = "data_path";
  /** Config. */
  private static final String IMAGES_PATH = "images_path";
  /** Config. */
  private static final String LANGUAGE_PATH = "language_path";
  /** Config. */
  private static final String LOG_PATH = "log_path";
  /** Config. */
  private static final String REPORTS_PATH = "reports_path";
  /** Config. */
  private static final String RA_PATH = "ra_path";
  /** Config. */
  private static final String THEME_PATH = "theme_path";
  /** Config. */
  private static final String HARDTOKEN_PATH = "hardtoken_path";
  /** Config. */

  private static final String CTLOGS = "ctlogs";
  /** Config. */

  private static final String STATEDUMP_LOCKDOWN = "statedump_lockdown";
  /** Config. */

  private static final String LANGUAGEFILENAME = "languagefilename";
  /** Config. */
  private static final String IECSSFILENAMEPOSTFIX = "iecssfilenamepostfix";
  /** Config. */
  private static final String GOOGLE_CT_POLICY = "google_ct_policy";
  /** Config. */
  private static final String EXTERNAL_SCRIPTS_WHITELIST =
      "external_scripts_whitelist";
  /** Config. */
  private static final String IS_EXTERNAL_SCRIPTS_WHITELIST_ENABLED =
      "is_external_scripts_whitelist_enabled";

  /** Config. */
  private static final String PUBLICWEBCERTCHAINORDEROOTFIRST =
      "publicwebcertchainorderrootfirst";

  /** Creates a new instance of GlobalConfiguration. */
  public GlobalConfiguration() {
    super();

    setEjbcaTitle(DEFAULTEJBCATITLE);
    setHeadBanner(DEFAULTHEADBANNER);
    setFootBanner(DEFAULTFOOTBANNER);
    setEnableEndEntityProfileLimitations(
        true); // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
    setEnableAuthenticatedUsersOnly(
        false); // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
    setEnableKeyRecovery(
        false); // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
    setIssueHardwareTokens(
        false); // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
    setEnableIcaoCANameChange(false);
  }

  /**
   * Initializes a new global configuration with data used in ra web interface.
   *
   * @param adminpath Path
   * @param availablelanguages Langs
   * @param availablethemes Themes
   * @param publicport Port
   * @param privateport private port
   * @param publicprotocol Protocol
   * @param privateprotocol Private protocol
   */
  public void initialize(
      final String adminpath,
      final String availablelanguages,
      final String availablethemes,
      final String publicport,
      final String privateport,
      final String publicprotocol,
      final String privateprotocol) {

    String tempadminpath = adminpath.trim();

    if (tempadminpath == null) {
      tempadminpath = "";
    }
    if (!tempadminpath.endsWith("/") && !tempadminpath.equals("")) {
      tempadminpath = tempadminpath + "/"; // Add ending '/'
    }
    if (tempadminpath.startsWith("/")) {
      tempadminpath = tempadminpath.substring(1); // Remove starting '/'
    }

    data.put(ADMINPATH, tempadminpath);
    data.put(AVAILABLELANGUAGES, availablelanguages.trim());
    data.put(AVAILABLETHEMES, availablethemes.trim());
    data.put(PUBLICPORT, publicport.trim());
    data.put(PRIVATEPORT, privateport.trim());
    data.put(PUBLICPROTOCOL, publicprotocol.trim());
    data.put(PRIVATEPROTOCOL, privateprotocol.trim());

    data.put(AUTHORIZATION_PATH, tempadminpath + "administratorprivileges");
    data.put(BANNERS_PATH, "banners");
    data.put(CA_PATH, tempadminpath + "ca");
    data.put(CONFIG_PATH, tempadminpath + "sysconfig");
    data.put(IMAGES_PATH, "images");
    data.put(LANGUAGE_PATH, "languages");
    data.put(LOG_PATH, tempadminpath + "log");
    data.put(REPORTS_PATH, tempadminpath + "reports");
    data.put(RA_PATH, tempadminpath + "ra");
    data.put(THEME_PATH, "themes");
    data.put(HARDTOKEN_PATH, tempadminpath + "hardtoken");

    data.put(LANGUAGEFILENAME, "languagefile");
    data.put(IECSSFILENAMEPOSTFIX, "_ie-fixes");
  }

  /**
   * init.
   */
  public void initializeAdminWeb() {
    initialize(
        "adminweb",
        WebConfiguration.getAvailableLanguages(),
        "default_theme.css,second_theme.css",
        "" + WebConfiguration.getPublicHttpPort(),
        "" + WebConfiguration.getPrivateHttpsPort(),
        "http",
        "https");
  }

  /**
   * Checks if global datauration have been initialized.
   *
   * @return bool
   */
  public boolean isInitialized() {
    return data.get(AVAILABLELANGUAGES) != null;
  }

  /**
   * @param scheme Scheme
   * @param requestServerName Server
   * @param port Port
   * @return The base URL of the application using the supplied values.
   */
  public String getBaseUrl(
      final String scheme, final String requestServerName, final int port) {
    return scheme
        + "://"
        + requestServerName
        + ":"
        + port
        + "/"
        + InternalConfiguration.getAppNameLower()
        + "/";
  }

  /**
   * @return The base path (and not the URL as the name suggests). The name was
   *     kept to enable a smaller patch between EJBCA 6.15 and 7.0.
   */
  public String getBaseUrl() {
    return "/" + InternalConfiguration.getAppNameLower() + "/";
  }

  /** @return The base path derived values in configuration files */
  public String getBaseUrlFromConfig() {
    return getBaseUrl(
        (String) data.get(GlobalConfiguration.PRIVATEPROTOCOL),
        WebConfiguration.getHostName(),
        Integer.parseInt((String) data.get(GlobalConfiguration.PRIVATEPORT)));
  }

  /**
   * @return url
   */
  private String getBaseUrlPublic() {
    return getBaseUrl(
        (String) data.get(PUBLICPROTOCOL),
        WebConfiguration.getHostName(),
        Integer.parseInt((String) data.get(PUBLICPORT)));
  }

  /**
   * @return path
   */
  public String getAdminWebPath() {
    return getString(ADMINPATH, "adminweb");
  }

  /**
   * @return url
   */
  public String getStandardCRLDistributionPointURI() {
    return getStandardCRLDistributionPointURINoDN() + DEFAULTCRLDISTURIPATHDN;
  }

  /**
   * @return url
   */
  public String getStandardCRLDistributionPointURINoDN() {
    return getBaseUrlPublic() + DEFAULTCRLDISTURIPATH;
  }

  /**
   * @return issuer
   */
  public String getStandardCRLIssuer() {
    return DEFAULTCRLDISTURIPATHDN;
  }

  /**
   * @return url
   */
  public String getStandardDeltaCRLDistributionPointURI() {
    return getStandardDeltaCRLDistributionPointURINoDN()
        + DEFAULTCRLDISTURIPATHDN;
  }

  /**
   * @return url
   */
  public String getStandardDeltaCRLDistributionPointURINoDN() {
    return getBaseUrlPublic() + DEFAULTDELTACRLDISTURIPATH;
  }

  /**
   * @return url
   */
  public String getStandardOCSPServiceLocatorURI() {
    return getBaseUrlPublic() + DEFAULTOCSPSERVICELOCATORURIPATH;
  }

  /**
   * Checks the themes path for css files and returns an array of filenames
   * without the ".css" ending.
   *
   * @return Themes
   */
  public String[] getAvailableThemes() {
    String[] availablethemes;
    final int f = 4;
    availablethemes = getAvailableThemesAsString().split(",");
    if (availablethemes != null) {
      for (int i = 0; i < availablethemes.length; i++) {
        availablethemes[i] = availablethemes[i].trim();
        if (availablethemes[i].endsWith(".css")) {
          availablethemes[i] =
              availablethemes[i].substring(0, availablethemes[i].length() - f);
        }
      }
    }
    return availablethemes;
  }

  /**
   * Returns the default available theme used by administrator preferences.
   *
   * @return Theme
   */
  public String getDefaultAvailableTheme() {
    return getAvailableThemes()[0];
  }

  // Methods for manipulating the headbanner filename.
  /**
   * @return header
   */
  public String getHeadBanner() {
    return fullHeadBannerPath((String) data.get(HEADBANNER));
  }

  /**
   * @param head header
   */
  public void setHeadBanner(final String head) {
    data.put(HEADBANNER, fullHeadBannerPath(head));
  }

  /**
   * @return bool
   */
  public boolean isNonDefaultHeadBanner() {
    return !fullHeadBannerPath(DEFAULTHEADBANNER).equals(data.get(HEADBANNER));
  }

  /**
   * @param head header
   * @return path
   */
  private String fullHeadBannerPath(final String head) {
    return ((String) data.get(ADMINPATH))
        + ((String) data.get(BANNERS_PATH))
        + "/"
        + (StringUtils.isNotBlank(head)
            ? head.substring(head.lastIndexOf('/') + 1)
            : DEFAULTHEADBANNER);
  }

  // Methods for manipulating the headbanner filename.
  /**
   * @return footer
   */
  public String getFootBanner() {
    return fullFootBannerPath((String) data.get(FOOTBANNER));
  }

  /**
   * @param foot footer
   */
  public void setFootBanner(final String foot) {
    data.put(FOOTBANNER, fullFootBannerPath(foot));
  }

  /**
   * @param foot footer
   * @return path
   */
  private String fullFootBannerPath(final String foot) {
    return "/"
        + ((String) data.get(BANNERS_PATH))
        + "/"
        + (StringUtils.isNotBlank(foot)
            ? foot.substring(foot.lastIndexOf('/') + 1)
            : DEFAULTFOOTBANNER);
  }

  // Methods for manipulating the title.
  /**
   * @return title
   */
  public String getEjbcaTitle() {
    return (String) data.get(TITLE);
  }

  /**
   * @return title
   */
  public static String getEjbcaDefaultTitle() {
    return DEFAULTEJBCATITLE;
  }

  /**
   * @param ejbcatitle path
   */
  public void setEjbcaTitle(final String ejbcatitle) {
    data.put(TITLE, ejbcatitle);
  }

  /**
   * @return path
   */
  public String getAuthorizationPath() {
    return (String) data.get(AUTHORIZATION_PATH);
  }

  /**
   * @return path
   */
  public String getBannersPath() {
    return (String) data.get(BANNERS_PATH);
  }

  /**
   * @return path
   */
  public String getCaPath() {
    return (String) data.get(CA_PATH);
  }

  /**
   * @return path
   */
  public String getConfigPath() {
    return (String) data.get(CONFIG_PATH);
  }

  /**
   * @return path
   */
  public String getImagesPath() {
    return (String) data.get(IMAGES_PATH);
  }

  /**
   * @return path
   */
  public String getLanguagePath() {
    return (String) data.get(LANGUAGE_PATH);
  }

  /**
   * @return path
   */
  public String getLogPath() {
    return (String) data.get(LOG_PATH);
  }

  /**
   * @return path
   */
  public String getReportsPath() {
    return (String) data.get(REPORTS_PATH);
  }

  /**
   * @return path
   */
  public String getRaPath() {
    return (String) data.get(RA_PATH);
  }

  /**
   * @return path
   */
  public String getThemePath() {
    return (String) data.get(THEME_PATH);
  }

  /**
   * @return path
   */
  public String getHardTokenPath() {
    return (String) data.get(HARDTOKEN_PATH);
  }

  /**
   * @return lang
   */
  public String getLanguageFilename() {
    return (String) data.get(LANGUAGEFILENAME);
  }

  /**
   * @return postfix
   */
  public String getIeCssFilenamePostfix() {
    return (String) data.get(IECSSFILENAMEPOSTFIX);
  }

  /**
   * @return entries
   */
  public String[] getPossibleEntiresPerPage() {
    return defaultPossibleEntriesPerPage;
  }

  /**
   * @return logs
   */
  public String[] getPossibleLogEntiresPerPage() {
    return defaultPossibleLogEntriesPerPage;
  }

  /**
   * @return langs
   */
  public String getAvailableLanguagesAsString() {
    return (String) data.get(AVAILABLELANGUAGES);
  }

  /**
   * @return themes
   */
  public String getAvailableThemesAsString() {
    return (String) data.get(AVAILABLETHEMES);
  }

  /**
   * @return bool
   */
  public boolean getEnableEndEntityProfileLimitations() {
    return getBoolean(ENABLEEEPROFILELIMITATIONS, true);
  }

  /**
   * @param value bool
   */
  public void setEnableEndEntityProfileLimitations(final boolean value) {
    putBoolean(ENABLEEEPROFILELIMITATIONS, value);
  }

  /**
   * @return bool
   */
  public boolean getEnableAuthenticatedUsersOnly() {
    return getBoolean(ENABLEAUTHENTICATEDUSERSONLY, false);
  }

  /**
   * @param value value
   */
  public void setEnableAuthenticatedUsersOnly(final boolean value) {
    putBoolean(ENABLEAUTHENTICATEDUSERSONLY, value);
  }

  /**
   * @return bool
   */
  public boolean getEnableKeyRecovery() {
    return getBoolean(ENABLEKEYRECOVERY, false);
  }

  /**
   * @param value bool
   */
  public void setEnableKeyRecovery(final boolean value) {
    putBoolean(ENABLEKEYRECOVERY, value);
  }

  /**
   * @return bool
   */
  public boolean getLocalKeyRecovery() {
    return getBoolean(LOCALKEYRECOVERY, false);
  }

  /**
   * @param value bool
   */
  public void setLocalKeyRecovery(final boolean value) {
    putBoolean(LOCALKEYRECOVERY, value);
  }

  /**
   * @return ID
   */
  public Integer getLocalKeyRecoveryCryptoTokenId() {
    return (Integer) data.get(LOCALKEYRECOVERYCRYPTOTOKEN);
  }

  /**
   * @param value Value
   */
  public void setLocalKeyRecoveryCryptoTokenId(final Integer value) {
    data.put(LOCALKEYRECOVERYCRYPTOTOKEN, value);
  }

  /**
   * @return Alias
   */
  public String getLocalKeyRecoveryKeyAlias() {
    return (String) data.get(LOCALKEYRECOVERYKEYALIAS);
  }

  /**
   * @param value alias
   */
  public void setLocalKeyRecoveryKeyAlias(final String value) {
    data.put(LOCALKEYRECOVERYKEYALIAS, value);
  }

  /**
   * @return bool
   */
  public boolean getIssueHardwareTokens() {
    return getBoolean(ISSUEHARDWARETOKENS, false);
  }

  /**
   * @param value bool
   */
  public void setIssueHardwareTokens(final boolean value) {
    putBoolean(ISSUEHARDWARETOKENS, value);
  }

  /**
   * @return bool
   */
  public boolean getEnableIcaoCANameChange() {
    return getBoolean(ENABLEICAOCANAMECHANGE, false);
  }

  /**
   * @param value bool
   */
  public void setEnableIcaoCANameChange(final boolean value) {
    putBoolean(ENABLEICAOCANAMECHANGE, value);
  }

  /**
   * @return the number of required approvals to access sensitive hard token
   *     data (default 0)
   */
  public int getNumberOfApprovalsToViewPUK() {
    Object num = data.get(NUMBEROFAPPROVALSTOVIEWPUK);
    if (num == null) {
      return 0;
    }
    return ((Integer) num).intValue();
  }

  /**
   * @param numberOfHardTokenApprovals num
   */
  public void setNumberOfApprovalsToViewPUK(
      final int numberOfHardTokenApprovals) {
    data.put(
        NUMBEROFAPPROVALSTOVIEWPUK,
        Integer.valueOf(numberOfHardTokenApprovals));
  }

  /**
   * @return the caid of the CA that should encrypt hardtoken data in the
   *     database. if CAid is 0 is the data stored unencrypted.
   */
  public int getHardTokenEncryptCA() {
    Object num = data.get(HARDTOKENENCRYPTCA);
    if (num == null) {
      return 0;
    }

    return ((Integer) num).intValue();
  }

  /**
   * @param hardTokenEncryptCA the caid of the CA that should encrypt hardtoken
   *     data in the database. if CAid is 0 is the data stored unencrypted.
   */
  public void setHardTokenEncryptCA(final int hardTokenEncryptCA) {
    data.put(HARDTOKENENCRYPTCA, Integer.valueOf(hardTokenEncryptCA));
  }

  /**
   * @return true of email notification of requested approvals should be sent
   *     (default false)
   */
  @Deprecated // Used during upgrade to EJBCA 6.6.0
  public boolean getUseApprovalNotifications() {
    return getBoolean(USEAPPROVALNOTIFICATIONS, false);
  }
  /**
   * Returns the email address to the administrators that should recieve
   * notification emails should be an alias to all approval administrators
   * default "" never null.
   *
   * @return String
   */
  @Deprecated // Used during upgrade to EJBCA 6.6.0
  public String getApprovalAdminEmailAddress() {
    final Object value = data.get(APPROVALADMINEMAILADDRESS);
    return value == null ? "" : (String) value;
  }
  /**
   * @return the email address used in the from field of approval notification
   *     emails.
   */
  @Deprecated // Used during upgrade to EJBCA 6.6.0
  public String getApprovalNotificationFromAddress() {
    final Object value = data.get(APPROVALNOTIFICATIONFROMADDR);
    return value == null ? "" : (String) value;
  }

  /**
   * @param server Server
   */
  public void setAutoEnrollADServer(final String server) {
    data.put(AUTOENROLL_ADSERVER, server);
  }

  /**
   * @return server
   */
  public String getAutoEnrollADServer() {
    String ret = (String) data.get(AUTOENROLL_ADSERVER);
    return (ret == null ? AUTOENROLL_DEFAULT_ADSERVER : ret);
  }

  /**
   *  @param caid Port
   */
  public void setAutoEnrollADPort(final int caid) {
    data.put(AUTOENROLL_ADPORT, Integer.valueOf(caid));
  }

  /**
   * @return Port
   */
  public int getAutoEnrollADPort() {
    Integer ret = (Integer) data.get(AUTOENROLL_ADPORT);
    return (ret == null ? AUTOENROLL_DEFAULT_ADPORT : ret);
  }

  /**
   * @param baseDN DN
   */
  public void setAutoEnrollBaseDNUser(final String baseDN) {
    data.put(AUTOENROLL_BASEDN_USER, baseDN);
  }

  /**
   * @return DN
   */
  public String getAutoEnrollBaseDNUser() {
    String ret = (String) data.get(AUTOENROLL_BASEDN_USER);
    return (ret == null ? AUTOENROLL_DEFAULT_BASEDN_USER : ret);
  }

  /**
   * @param caid CA
   */
  public void setAutoEnrollCA(final int caid) {
    data.put(AUTOENROLL_CA, Integer.valueOf(caid));
  }

  /**
   * @return CA
   */
  public int getAutoEnrollCA() {
    Integer ret = (Integer) data.get(AUTOENROLL_CA);
    return (ret == null ? AUTOENROLL_DEFAULT_CA : ret);
  }

  /**
   * @param connectionDN DN
   */
  public void setAutoEnrollConnectionDN(final String connectionDN) {
    data.put(AUTOENROLL_CONNECTIONDN, connectionDN);
  }

  /**
   * @return DN
   */
  public String getAutoEnrollConnectionDN() {
    String ret = (String) data.get(AUTOENROLL_CONNECTIONDN);
    return (ret == null ? AUTOENROLL_DEFAULT_CONNECTIONDN : ret);
  }

  /**
   * @param connectionPwd Password
   */
  public void setAutoEnrollConnectionPwd(final String connectionPwd) {
    data.put(
        AUTOENROLL_CONNECTIONPWD, StringTools.obfuscateIfNot(connectionPwd));
  }

  /**
   * @return Password
   */
  public String getAutoEnrollConnectionPwd() {
    String ret = (String) data.get(AUTOENROLL_CONNECTIONPWD);
    return (ret == null
        ? AUTOENROLL_DEFAULT_CONNECTIONPWD
        : StringTools.deobfuscateIf(ret));
  }

  /**
   * @param value bool
   */
  public void setAutoEnrollSSLConnection(final boolean value) {
    putBoolean(AUTOENROLL_SSLCONNECTION, value);
  }

  /**
   * @return bool
   */
  public boolean getAutoEnrollSSLConnection() {
    return getBoolean(
        AUTOENROLL_SSLCONNECTION, AUTOENROLL_DEFAULT_SSLCONNECTION);
  }

  /**
   * @param value bool
   */
  public void setAutoEnrollUse(final boolean value) {
    putBoolean(AUTOENROLL_USE, value);
  }

  /**
   * @return bool
   */
  public boolean getAutoEnrollUse() {
    return getBoolean(AUTOENROLL_USE, AUTOENROLL_DEFAULT_USE);
  }

  /**
   * @param nodes nodes
   */
  public void setNodesInCluster(final Set<String> nodes) {
    data.put(NODESINCLUSTER, nodes);
  }

  /**       *
   * @return Nodes
   */
  @SuppressWarnings("unchecked")
  public Set<String> getNodesInCluster() {
    // In an earlier version (<5.0.11) this was a HashSet, not a LinkedHashSet.
    // Using a HashSet causes order to be non-deterministic, that makes it
    // possible
    // to get verification failures if using Database Protection. This was then
    // changed to a LinkedHashSet that guarantees order.
    // Therefore we try to ensure that a LinkedHashSet is returned, seamlessly
    // upgrading any old HashSet.
    // If an old object is in the database, after a getNodesInCluster(),
    // setNodesInCluster() and saveGlobalConfiguration() it should be a
    // LinkedHashSet in the database.
    Set<String> ret = null;
    Object o = data.get(NODESINCLUSTER);
    if (o != null && !(o instanceof LinkedHashSet<?>)) {
      LOG.debug(
          "Converting GlobalConfiguration NodesInCluster from "
              + o.getClass().getName()
              + " to LinkedHashSet.");
      ret = new LinkedHashSet<>((Collection<String>) o);
    } else {
      ret = (Set<String>) o;
    }
    return (ret == null ? NODESINCLUSTER_DEFAULT : ret);
  }

  /**
   * @param value bool
   */
  public void setEnableCommandLineInterface(final boolean value) {
    putBoolean(ENABLECOMMANDLINEINTERFACE, value);
  }

  /**
   * @return bool
   */
  public boolean getEnableCommandLineInterface() {
    return getBoolean(
        ENABLECOMMANDLINEINTERFACE, DEFAULTENABLECOMMANDLINEINTERFACE);
  }

  /**
   * @param value bool
   */
  public void setEnableCommandLineInterfaceDefaultUser(final boolean value) {
    putBoolean(ENABLECOMMANDLINEINTERFACEDEFAULTUSER, value);
  }

  /**
   * @return bool
   */
  public boolean getEnableCommandLineInterfaceDefaultUser() {
    return getBoolean(
        ENABLECOMMANDLINEINTERFACEDEFAULTUSER,
        DEFAULTENABLECOMMANDLINEINTERFACEDEFAULTUSER);
  }

  /**
   * @param value bool
   */
  @Override
  public void setEnableExternalScripts(final boolean value) {
    putBoolean(ENABLEEXTERNALSCRIPTS, value);
  }

  /**
   * @return bool
   */
  @Override
  public boolean getEnableExternalScripts() {
    return getBoolean(ENABLEEXTERNALSCRIPTS, DEFAULTENABLEEXTERNALSCRIPTS);
  }

  /**
   * @return bool
   */
  public boolean getPublicWebCertChainOrderRootFirst() {
    return getBoolean(
        PUBLICWEBCERTCHAINORDEROOTFIRST,
        DEFAULTPUBLICWEBCERTCHAINORDEROOTFIRST);
  }

  /**
   * @param value bool
   */
  public void setPublicWebCertChainOrderRootFirst(final boolean value) {
    putBoolean(PUBLICWEBCERTCHAINORDEROOTFIRST, value);
  }

  /**
   * @return logs
   */
  @SuppressWarnings("unchecked")
  public LinkedHashMap<Integer, CTLogInfo> getCTLogs() {
    final Map<Integer, CTLogInfo> ret =
        (Map<Integer, CTLogInfo>) data.get(CTLOGS);
    return (ret == null ? CTLOGS_DEFAULT : new LinkedHashMap<>(ret));
  }

  /**
   * Sets the available CT logs. NOTE: The order of the is important, so this
   * MUST be called with a LinkedHashMap!
   *
   * @param ctlogs Logs
   */
  public void setCTLogs(final LinkedHashMap<Integer, CTLogInfo> ctlogs) {
    data.put(CTLOGS, ctlogs);
  }

  /**
   * @param ctlog Info
   */
  public void addCTLog(final CTLogInfo ctlog) {
    LinkedHashMap<Integer, CTLogInfo> logs = new LinkedHashMap<>(getCTLogs());
    logs.put(ctlog.getLogId(), ctlog);
    setCTLogs(logs);
  }

  /**
   * @param ctlogId ID
   */
  public void removeCTLog(final int ctlogId) {
    LinkedHashMap<Integer, CTLogInfo> logs = new LinkedHashMap<>(getCTLogs());
    logs.remove(ctlogId);
    setCTLogs(logs);
  }

  /**
   * @return policy
   */
  public GoogleCtPolicy getGoogleCtPolicy() {
    final GoogleCtPolicy googleCtPolicy =
        (GoogleCtPolicy) data.get(GOOGLE_CT_POLICY);
    if (googleCtPolicy == null) {
      return new GoogleCtPolicy();
    }
    return googleCtPolicy;
  }

  /**
   * @param value policy
   */
  public void setGoogleCtPolicy(final GoogleCtPolicy value) {
    data.put(GOOGLE_CT_POLICY, value);
  }

  /**
   * @return bool
   */
  public boolean getStatedumpLockedDown() {
    return getBoolean(STATEDUMP_LOCKDOWN, true);
  }

  /**
   * @param value bol
   */
  public void setStatedumpLockedDown(final boolean value) {
    data.put(STATEDUMP_LOCKDOWN, value);
  }

  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      if (data.get(HARDTOKEN_PATH) == null) {
        data.put(HARDTOKEN_PATH, ((String) data.get(ADMINPATH) + "hardtoken"));
      }
      if (data.get(REPORTS_PATH) == null) {
        data.put(REPORTS_PATH, ((String) data.get(ADMINPATH) + "reports"));
      }
      if (data.get(ENABLECOMMANDLINEINTERFACEDEFAULTUSER) == null) {
        data.put(ENABLECOMMANDLINEINTERFACEDEFAULTUSER, Boolean.TRUE);
      }
      if (data.get(ENABLEEXTERNALSCRIPTS) == null) {
        data.put(ENABLEEXTERNALSCRIPTS, DEFAULTENABLEEXTERNALSCRIPTS);
      }
      if (data.get(ENABLEICAOCANAMECHANGE) == null) {
        data.put(ENABLEICAOCANAMECHANGE, Boolean.FALSE);
      }
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  @Override
  public String getConfigurationId() {
    return GLOBAL_CONFIGURATION_ID;
  }

  @Override
  public String getExternalScriptsWhitelist() {
    return getString(EXTERNAL_SCRIPTS_WHITELIST, StringUtils.EMPTY);
  }

  @Override
  public void setExternalScriptsWhitelist(final String value) {
    data.put(EXTERNAL_SCRIPTS_WHITELIST, value);
  }

  @Override
  public boolean getIsExternalScriptsWhitelistEnabled() {
    return getBoolean(IS_EXTERNAL_SCRIPTS_WHITELIST_ENABLED, false);
  }

  @Override
  public void setIsExternalScriptsWhitelistEnabled(final boolean value) {
    data.put(IS_EXTERNAL_SCRIPTS_WHITELIST_ENABLED, value);
  }
}
