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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;

/**
 * This is a class containing CMP configuration parameters.
 *
 * @version $Id: CmpConfiguration.java 28618 2018-04-03 12:55:54Z samuellb $
 */
public class CmpConfiguration extends ConfigurationBase
    implements Serializable {

  private static final long serialVersionUID = -2787354158199916828L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(CmpConfiguration.class);

  // Constants: Authentication modules
  /** Config. */
  public static final String AUTHMODULE_REG_TOKEN_PWD = "RegTokenPwd";
  /** Config. */
  public static final String AUTHMODULE_DN_PART_PWD = "DnPartPwd";
  /** Config. */
  public static final String AUTHMODULE_HMAC = "HMAC";
  /** Config. */
  public static final String AUTHMODULE_ENDENTITY_CERTIFICATE =
      "EndEntityCertificate";

  // Constants: Configuration keys
  /** Config. */
  public static final String CONFIG_DEFAULTCA = "defaultca";
  /** Config. */
  public static final String CONFIG_ALLOWRAVERIFYPOPO = "allowraverifypopo";
  /** Config. */
  public static final String CONFIG_OPERATIONMODE = "operationmode";
  /** Config. */
  public static final String CONFIG_AUTHENTICATIONMODULE =
      "authenticationmodule";
  /** Config. */
  public static final String CONFIG_AUTHENTICATIONPARAMETERS =
      "authenticationparameters";
  /** Config. */
  public static final String CONFIG_EXTRACTUSERNAMECOMPONENT =
      "extractusernamecomponent";
  /** Config. */
  public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO =
      "ra.allowcustomcertserno";
  /** Config. */
  public static final String CONFIG_RA_NAMEGENERATIONSCHEME =
      "ra.namegenerationscheme";
  /** Config. */
  public static final String CONFIG_RA_NAMEGENERATIONPARAMS =
      "ra.namegenerationparameters";
  /** Config. */
  public static final String CONFIG_RA_NAMEGENERATIONPREFIX =
      "ra.namegenerationprefix";
  /** Config. */
  public static final String CONFIG_RA_NAMEGENERATIONPOSTFIX =
      "ra.namegenerationpostfix";
  /** Config. */
  public static final String CONFIG_RA_PASSWORDGENPARAMS =
      "ra.passwordgenparams";
  /**
   * @deprecated since 6.5.1, but remains to allow 100% uptime during upgrade.
   *     Use CONFIG_RA_ENDENTITYPROFILEID instead
   */
  @Deprecated
  public static final String CONFIG_RA_ENDENTITYPROFILE = "ra.endentityprofile";

  /** Config. */
  public static final String CONFIG_RA_ENDENTITYPROFILEID =
      "ra.endentityprofileid";
  /** Config. */
  public static final String CONFIG_RA_CERTIFICATEPROFILE =
      "ra.certificateprofile";
  /** Config. */
  public static final String CONFIG_RESPONSEPROTECTION = "responseprotection";
  /** Config. */
  public static final String CONFIG_RACANAME = "ra.caname";
  /** Config. */
  public static final String CONFIG_VENDORCERTIFICATEMODE =
      "vendorcertificatemode";
  /** Config. */
  public static final String CONFIG_VENDORCA = "vendorca";
  /** Config. */
  public static final String CONFIG_RESPONSE_CAPUBS_CA = "response.capubsca";
  /** Config. */
  public static final String CONFIG_RESPONSE_EXTRACERTS_CA =
      "response.extracertsca";
  /** Config. */
  public static final String CONFIG_RA_OMITVERIFICATIONSINEEC =
      "ra.endentitycertificate.omitverifications";
  /** Config. */
  public static final String CONFIG_RACERT_PATH = "racertificatepath";
  /** Config. */
  public static final String CONFIG_ALLOWAUTOMATICKEYUPDATE =
      "allowautomatickeyupdate";
  /** Config. */
  public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY =
      "allowupdatewithsamekey";
  /** Config. */
  public static final String CONFIG_ALLOWSERVERGENERATEDKEYS =
      "allowservergenkeys";
  /** Config. */
  public static final String CONFIG_CERTREQHANDLER_CLASS =
      "certreqhandler.class";
  /**
   * @deprecated since 6.12.0. No longer used, and can no longer be set. The
   *     datasource is now hard-coded to be UnidDS
   */
  @Deprecated
  public static final String CONFIG_UNIDDATASOURCE = "uniddatasource";

  /** Config. */
  public static final String PROFILE_USE_KEYID = "KeyId";
  /** Config. */
  public static final String PROFILE_DEFAULT = "ProfileDefault";

  // This List is used in the command line handling of updating a config value
  // to ensure a correct value.
  /** Config. */
  public static final List<String> CMP_BOOLEAN_KEYS =
      Arrays.asList(
          CONFIG_VENDORCERTIFICATEMODE,
          CONFIG_ALLOWRAVERIFYPOPO,
          CONFIG_RA_ALLOWCUSTOMCERTSERNO,
          CONFIG_ALLOWAUTOMATICKEYUPDATE,
          CONFIG_ALLOWUPDATEWITHSAMEKEY,
          CONFIG_ALLOWSERVERGENERATEDKEYS);

  /** Config. */
  private final String aliasList = "aliaslist";
  /** Config. */
  public static final String CMP_CONFIGURATION_ID = "1";

  // Default Values
  /** Config. */
  public static final float LATEST_VERSION = 8f;
  /** Config. */
  public static final String EJBCA_VERSION =
      InternalConfiguration.getAppVersion();

  // Default values
  /** Config. */
  private static final Set<String> DEFAULT_ALIAS_LIST = new LinkedHashSet<>();
  /** Config. */
  private static final String DEFAULT_DEFAULTCA = "";
  /** Config. */
  private static final String DEFAULT_OPERATION_MODE = "client";
  /** Config. */
  private static final String DEFAULT_EXTRACT_USERNAME_COMPONENT = "DN";
  /** Config. */
  private static final String DEFAULT_VENDOR_MODE = "false";
  /** Config. */
  private static final String DEFAULT_VENDOR_CA = "";
  /** Config. */
  private static final String DEFAULT_RESPONSE_CAPUBS_CA = "";
  /** Config. */
  private static final String DEFAULT_RESPONSE_EXTRACERTS_CA = "";
  /** Config. */
  private static final String DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE = "false";
  /** Config. */
  private static final String DEFAULT_ALLOW_SERVERGENERATED_KEYS = "false";
  /** Config. */
  private static final String DEFAULT_KUR_ALLOW_SAME_KEY = "true";
  /** Config. */
  private static final String DEFAULT_RESPONSE_PROTECTION = "signature";
  /** Config. */
  private static final String DEFAULT_ALLOW_RA_VERIFY_POPO = "false";
  /** Config. */
  private static final String DEFAULT_RA_USERNAME_GENERATION_SCHEME = "DN";
  /** Config. */
  private static final String DEFAULT_RA_USERNAME_GENERATION_PARAMS = "CN";
  /** Config. */
  private static final String DEFAULT_RA_USERNAME_GENERATION_PREFIX = "";
  /** Config. */
  private static final String DEFAULT_RA_USERNAME_GENERATION_POSTFIX = "";
  /** Config. */
  private static final String DEFAULT_RA_PASSWORD_GENERARION_PARAMS = "random";
  /** Config. */
  private static final String DEFAULT_RA_ALLOW_CUSTOM_SERNO = "false";
  /** Config. */
  public static final String DEFAULT_RA_EEPROFILE = "1";
  /** Config. */
  private static final String DEFAULT_RA_CERTPROFILE = "ENDUSER";
  /** Config. */
  private static final String DEFAULT_RA_CANAME = "ManagementCA";
  /** Config. */
  private static final String DEFAULT_CLIENT_AUTHENTICATION_MODULE =
      CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD
          + ";"
          + CmpConfiguration.AUTHMODULE_HMAC;
  /** Config. */
  private static final String DEFAULT_CLIENT_AUTHENTICATION_PARAMS = "-;-";
  /** Config. */
  private static final String DEFAULT_RA_OMITVERIFICATIONSINEEC = "false";
  /** Config. */
  private static final String DEFAULT_RACERT_PATH = "";
  /** Config. */
  private static final String DEFAULT_CERTREQHANDLER =
      ""; // "org.ejbca.core.protocol.unid.UnidFnrHandler";

  /** Creates a new instance of CmpConfiguration. */
  public CmpConfiguration() {
    super();
  }

  /**
   * @param dataobj Object.
   */
  public CmpConfiguration(final Serializable dataobj) {
    @SuppressWarnings("unchecked")
    LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
    data = d;
  }

  /**
   * Copy constructor for {@link CmpConfiguration}.
   *
   * @param cmpConfiguration config
   */
  public CmpConfiguration(final CmpConfiguration cmpConfiguration) {
    super();
    setAliasList(new LinkedHashSet<String>());
    for (String alias : cmpConfiguration.getAliasList()) {
      addAlias(alias);
      for (String key : getAllAliasKeys(alias)) {
        String value = cmpConfiguration.getValue(key, alias);
        setValue(key, value, alias);
      }
    }
  }

  /**
   * Initializes a new cmp configuration with default values.
   *
   * @param oalias alias
   */
  public void initialize(final String oalias) {
    if (StringUtils.isNotEmpty(oalias)) {
      String alias = oalias + ".";
      data.put(alias + CONFIG_DEFAULTCA, DEFAULT_DEFAULTCA);
      data.put(alias + CONFIG_RESPONSEPROTECTION, DEFAULT_RESPONSE_PROTECTION);
      data.put(alias + CONFIG_OPERATIONMODE, DEFAULT_OPERATION_MODE);
      data.put(
          alias + CONFIG_AUTHENTICATIONMODULE,
          DEFAULT_CLIENT_AUTHENTICATION_MODULE);
      data.put(
          alias + CONFIG_AUTHENTICATIONPARAMETERS,
          DEFAULT_CLIENT_AUTHENTICATION_PARAMS);
      data.put(
          alias + CONFIG_EXTRACTUSERNAMECOMPONENT,
          DEFAULT_EXTRACT_USERNAME_COMPONENT);
      data.put(alias + CONFIG_VENDORCERTIFICATEMODE, DEFAULT_VENDOR_MODE);
      data.put(alias + CONFIG_VENDORCA, DEFAULT_VENDOR_CA);
      data.put(alias + CONFIG_RESPONSE_CAPUBS_CA, DEFAULT_RESPONSE_CAPUBS_CA);
      data.put(
          alias + CONFIG_RESPONSE_EXTRACERTS_CA,
          DEFAULT_RESPONSE_EXTRACERTS_CA);
      data.put(alias + CONFIG_ALLOWRAVERIFYPOPO, DEFAULT_ALLOW_RA_VERIFY_POPO);
      data.put(
          alias + CONFIG_RA_NAMEGENERATIONSCHEME,
          DEFAULT_RA_USERNAME_GENERATION_SCHEME);
      data.put(
          alias + CONFIG_RA_NAMEGENERATIONPARAMS,
          DEFAULT_RA_USERNAME_GENERATION_PARAMS);
      data.put(
          alias + CONFIG_RA_NAMEGENERATIONPREFIX,
          DEFAULT_RA_USERNAME_GENERATION_PREFIX);
      data.put(
          alias + CONFIG_RA_NAMEGENERATIONPOSTFIX,
          DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
      data.put(
          alias + CONFIG_RA_PASSWORDGENPARAMS,
          DEFAULT_RA_PASSWORD_GENERARION_PARAMS);
      data.put(
          alias + CONFIG_RA_ALLOWCUSTOMCERTSERNO,
          DEFAULT_RA_ALLOW_CUSTOM_SERNO);
      data.put(alias + CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
      data.put(alias + CONFIG_RA_ENDENTITYPROFILEID, DEFAULT_RA_EEPROFILE);
      data.put(alias + CONFIG_RA_CERTIFICATEPROFILE, DEFAULT_RA_CERTPROFILE);
      data.put(alias + CONFIG_RACANAME, DEFAULT_RA_CANAME);
      data.put(alias + CONFIG_RACERT_PATH, DEFAULT_RACERT_PATH);
      data.put(
          alias + CONFIG_RA_OMITVERIFICATIONSINEEC,
          DEFAULT_RA_OMITVERIFICATIONSINEEC);
      data.put(
          alias + CONFIG_ALLOWAUTOMATICKEYUPDATE,
          DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE);
      data.put(
          alias + CONFIG_ALLOWSERVERGENERATEDKEYS,
          DEFAULT_ALLOW_SERVERGENERATED_KEYS);
      data.put(
          alias + CONFIG_ALLOWUPDATEWITHSAMEKEY, DEFAULT_KUR_ALLOW_SAME_KEY);
      data.put(alias + CONFIG_CERTREQHANDLER_CLASS, DEFAULT_CERTREQHANDLER);
    }
  }

  /** @param oalias Alias
 * @return all the key with an alias */
  public static Set<String> getAllAliasKeys(final String oalias) {
    String alias = oalias + ".";
    Set<String> keys = new LinkedHashSet<>();
    keys.add(alias + CONFIG_DEFAULTCA);
    keys.add(alias + CONFIG_RESPONSEPROTECTION);
    keys.add(alias + CONFIG_OPERATIONMODE);
    keys.add(alias + CONFIG_AUTHENTICATIONMODULE);
    keys.add(alias + CONFIG_AUTHENTICATIONPARAMETERS);
    keys.add(alias + CONFIG_EXTRACTUSERNAMECOMPONENT);
    keys.add(alias + CONFIG_VENDORCERTIFICATEMODE);
    keys.add(alias + CONFIG_VENDORCA);
    keys.add(alias + CONFIG_RESPONSE_CAPUBS_CA);
    keys.add(alias + CONFIG_RESPONSE_EXTRACERTS_CA);
    keys.add(alias + CONFIG_ALLOWRAVERIFYPOPO);
    keys.add(alias + CONFIG_RA_NAMEGENERATIONSCHEME);
    keys.add(alias + CONFIG_RA_NAMEGENERATIONPARAMS);
    keys.add(alias + CONFIG_RA_NAMEGENERATIONPREFIX);
    keys.add(alias + CONFIG_RA_NAMEGENERATIONPOSTFIX);
    keys.add(alias + CONFIG_RA_PASSWORDGENPARAMS);
    keys.add(alias + CONFIG_RA_ALLOWCUSTOMCERTSERNO);
    keys.add(alias + CONFIG_RA_ENDENTITYPROFILE);
    keys.add(alias + CONFIG_RA_ENDENTITYPROFILEID);
    keys.add(alias + CONFIG_RA_CERTIFICATEPROFILE);
    keys.add(alias + CONFIG_RACANAME);
    keys.add(alias + CONFIG_RACERT_PATH);
    keys.add(alias + CONFIG_RA_OMITVERIFICATIONSINEEC);
    keys.add(alias + CONFIG_ALLOWAUTOMATICKEYUPDATE);
    keys.add(alias + CONFIG_ALLOWUPDATEWITHSAMEKEY);
    keys.add(alias + CONFIG_CERTREQHANDLER_CLASS);
    keys.add(alias + CONFIG_ALLOWSERVERGENERATEDKEYS);
    return keys;
  }

  /**
   * Method used by the Admin GUI.
   *
   * @param alias alias
   * @return string
   */
  public String getCMPDefaultCA(final String alias) {
    String key = alias + "." + CONFIG_DEFAULTCA;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param defCA CA
   */
  public void setCMPDefaultCA(final String alias, final String defCA) {
    String key = alias + "." + CONFIG_DEFAULTCA;
    setValue(key, defCA, alias);
  }

  /**
   * @param alias Alias
   * @return Protect
   */
  public String getResponseProtection(final String alias) {
    String key = alias + "." + CONFIG_RESPONSEPROTECTION;
    String result = getValue(key, alias);
    if (result == null) {
      setResponseProtection(alias, DEFAULT_RESPONSE_PROTECTION);
      return DEFAULT_RESPONSE_PROTECTION;
    } else {
      return result;
    }
  }

  /**
   * @param alias Alias
   * @param protection Protect
   */
  public void setResponseProtection(
      final String alias, final String protection) {
    String key = alias + "." + CONFIG_RESPONSEPROTECTION;
    setValue(key, protection, alias);
  }

  // Any value that is not "ra" or "RA" will be client mode, no matter what it
  // is
  /**
   * @param alias Alias
   * @return Mode
   */
  public boolean getRAMode(final String alias) {
    String key = alias + "." + CONFIG_OPERATIONMODE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "ra");
  }

  /**
   * @param alias Alias
   * @param ramode Mode
   */
  public void setRAMode(final String alias, final boolean ramode) {
    String key = alias + "." + CONFIG_OPERATIONMODE;
    setValue(key, ramode ? "ra" : "client", alias);
  }

  /**
 * @param alias Alias
 * @param mode  Mode
   */
  public void setRAMode(final String alias, final String mode) {
    setRAMode(alias, StringUtils.equalsIgnoreCase(mode, "ra"));
  }

  /**
   * @param alias Alias
   * @return Module
   */
  public String getAuthenticationModule(final String alias) {
    String key = alias + "." + CONFIG_AUTHENTICATIONMODULE;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param authModule Module
   */
  public void setAuthenticationModule(
      final String alias, final String authModule) {
    String key = alias + "." + CONFIG_AUTHENTICATIONMODULE;
    setValue(key, authModule, alias);
  }

  /**
   * @param alias Alias
   * @param authmodules Modules
   * @param authparams Params
   */
  public void setAuthenticationProperties(
      final String alias,
      final ArrayList<String> authmodules,
      final ArrayList<String> authparams) {
    if (authmodules.isEmpty()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Did not update CMP Authentication modules or parameters because"
                + " no Authentication module was specified");
      }
      return;
    }

    if (authmodules.size() != authparams.size()) {
      LOG.info(
          "Did not update CMP Authentication settings because the number of"
              + " authentication parameters is not the same as the number of"
              + " authentication modules");
      return;
    }

    String authmodule = "";
    String authparam = "";
    for (int i = 0; i < authmodules.size(); i++) {
      authmodule += ";" + authmodules.get(i);
      authparam += ";" + authparams.get(i);
    }
    authmodule = authmodule.substring(1);
    authparam = authparam.substring(1);
    setAuthenticationModule(alias, authmodule);
    setAuthenticationParameters(alias, authparams);
  }

  /**
   * @param alias Alias
   * @return Params
   */
  public String getAuthenticationParameters(final String alias) {
    String key = alias + "." + CONFIG_AUTHENTICATIONPARAMETERS;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param authParams Params
   */
  public void setAuthenticationParameters(
      final String alias, final String authParams) {
    String key = alias + "." + CONFIG_AUTHENTICATIONPARAMETERS;
    setValue(key, authParams, alias);
  }

  /**
   * @param alias Alias
   * @param authparameters params
   */
  public void setAuthenticationParameters(
      final String alias, final ArrayList<String> authparameters) {
    String authparam = "";
    for (String p : authparameters) {
      authparam += ";" + p;
    }
    authparam = authparam.substring(1);
    setAuthenticationParameters(alias, authparam);
  }

  /**
   * @param authModule Module
   * @param alias Alias
   * @return Param
   */
  public String getAuthenticationParameter(
      final String authModule, final String alias) {

    if (StringUtils.isNotEmpty(alias)) {
      String confModule = getAuthenticationModule(alias);
      String confParams = getAuthenticationParameters(alias);

      String[] modules = confModule.split(";");
      String[] params = confParams.split(";");

      if (modules.length > params.length) {
        LOG.info(
            "There are not as many authentication parameters as authentication"
                + " modules. "
                + modules.length
                + " modules but "
                + params.length
                + " parameters. Returning an empty String");
        return "";
      }

      for (int i = 0; i < modules.length; i++) {
        if (StringUtils.equals(modules[i].trim(), authModule)) {
          return params[i];
        }
      }
      return "";
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No CMP alias was specified. Returning an empty String");
      }
      return "";
    }
  }

  /**
   * @param alias Alias
   * @param authmodule Module
   * @return Bool
   */
  public boolean isInAuthModule(final String alias, final String authmodule) {
    String authmodules = getAuthenticationModule(alias);
    String[] modules = authmodules.split(";");
    for (String m : modules) {
      if (StringUtils.equals(authmodule, m)) {
        return true;
      }
    }
    return false;
  }

  /**
   * @param alias Alias
   * @return Component
   */
  public String getExtractUsernameComponent(final String alias) {
    String key = alias + "." + CONFIG_EXTRACTUSERNAMECOMPONENT;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param extractComponent Component
   */
  public void setExtractUsernameComponent(
      final String alias, final String extractComponent) {
    String key = alias + "." + CONFIG_EXTRACTUSERNAMECOMPONENT;
    setValue(key, extractComponent, alias);
  }

  /**
   * @param alias Alias
   * @return Bool
   */
  public boolean getVendorMode(final String alias) {
    String key = alias + "." + CONFIG_VENDORCERTIFICATEMODE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias Alias
   * @param vendormode bool
   */
  public void setVendorMode(final String alias, final boolean vendormode) {
    String key = alias + "." + CONFIG_VENDORCERTIFICATEMODE;
    setValue(key, Boolean.toString(vendormode), alias);
  }

  /**
   * @param alias ALias
   * @return CA
   */
  public String getVendorCA(final String alias) {
    String key = alias + "." + CONFIG_VENDORCA;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param vendorCA CA
   */
  public void setVendorCA(final String alias, final String vendorCA) {
    String key = alias + "." + CONFIG_VENDORCA;
    setValue(key, vendorCA, alias);
  }

  /**
   * Gets the semicolon separated list of CA IDs, to add the CA certificates to
   * CMP response 'caPubs' field.
   *
   * @param alias the CMP configuration alias.
   * @return the semicolon separated list of CA IDs.
   */
  public String getResponseCaPubsCA(final String alias) {
    String key = alias + "." + CONFIG_RESPONSE_CAPUBS_CA;
    return getValue(key, alias);
  }

  /**
   * Sets the semicolon separated list of CA IDs, to add the CA certificates to
   * CMP response 'caPubs' field.
   *
   * <p>There are no checks performed, if the CAs for that IDs exist.
   *
   * @param alias the CMP configuration alias.
   * @param caIdString the semicolon separated list of CA IDs.
   */
  public void setResponseCaPubsCA(final String alias, final String caIdString) {
    String key = alias + "." + CONFIG_RESPONSE_CAPUBS_CA;
    setValue(key, caIdString, alias);
  }

  /**
   * Sets the semicolon separated list of CA IDs, to add the CA certificates to
   * CMP PKI message response 'extraCerts' field.
   *
   * @param alias the CMP configuration alias.
   * @return the semicolon separated list of CA IDs.
   */
  public String getResponseExtraCertsCA(final String alias) {
    String key = alias + "." + CONFIG_RESPONSE_EXTRACERTS_CA;
    return getValue(key, alias);
  }

  /**
   * Sets the semicolon separated list of CA IDs, to add the CA certificates to
   * CMP PKI message response 'extraCerts' field.
   *
   * <p>There are no checks performed, if the CAs for that IDs exist.
   *
   * @param alias the CMP configuration alias.
   * @param caIdString the semicolon separated list of CA IDs.
   */
  public void setResponseExtraCertsCA(
      final String alias, final String caIdString) {
    String key = alias + "." + CONFIG_RESPONSE_EXTRACERTS_CA;
    setValue(key, caIdString, alias);
  }

  /**
   * @param alias Alias
   * @return Bool
   */
  public boolean getAllowRAVerifyPOPO(final String alias) {
    String key = alias + "." + CONFIG_ALLOWRAVERIFYPOPO;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias Alias
   * @param raVerifyPopo Bool
   */
  public void setAllowRAVerifyPOPO(
      final String alias, final boolean raVerifyPopo) {
    String key = alias + "." + CONFIG_ALLOWRAVERIFYPOPO;
    setValue(key, Boolean.toString(raVerifyPopo), alias);
  }

  /**
   * @param alias Alias
   * @return Scheme
   */
  public String getRANameGenScheme(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param scheme Scheme
   */
  public void setRANameGenScheme(final String alias, final String scheme) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
    setValue(key, scheme, alias);
  }

  /**
   * @param alias Alias
   * @return Params
   */
  public String getRANameGenParams(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param params Params
   */
  public void setRANameGenParams(final String alias, final String params) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
    setValue(key, params, alias);
  }

  /**
   * @param alias Alias
   * @return Prefix
   */
  public String getRANameGenPrefix(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param prefix Prefix
   */
  public void setRANameGenPrefix(final String alias, final String prefix) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
    setValue(key, prefix, alias);
  }

  /**
   * @param alias Alias
   * @return Postfix
   */
  public String getRANameGenPostfix(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param postfix Pastfix
   */
  public void setRANameGenPostfix(final String alias, final String postfix) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
    setValue(key, postfix, alias);
  }

  /**
   * @param alias Alias
   * @return Params
   */
  public String getRAPwdGenParams(final String alias) {
    String key = alias + "." + CONFIG_RA_PASSWORDGENPARAMS;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param params Params
   */
  public void setRAPwdGenParams(final String alias, final String params) {
    String key = alias + "." + CONFIG_RA_PASSWORDGENPARAMS;
    setValue(key, params, alias);
  }

  /**
   * @param alias Alias
   * @return Bool
   */
  public boolean getAllowRACustomSerno(final String alias) {
    String key = alias + "." + CONFIG_RA_ALLOWCUSTOMCERTSERNO;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias alias
   * @param allowCustomSerno bool
   */
  public void setAllowRACustomSerno(
      final String alias, final boolean allowCustomSerno) {
    String key = alias + "." + CONFIG_RA_ALLOWCUSTOMCERTSERNO;
    setValue(key, Boolean.toString(allowCustomSerno), alias);
  }

  /**
   * @param alias alias
   * @return the end entity profile ID
   */
  public String getRAEEProfile(final String alias) {
    String key = alias + "." + CONFIG_RA_ENDENTITYPROFILEID;
    return getValue(key, alias);
  }

  /**
   * @param alias the CMP alias
   * @param eep the end entity profile ID, or the value KeyId
   * @throws NumberFormatException if the end entity profile ID is not an
   *     integer or KeyId
   */
  public void setRAEEProfile(final String alias, final String eep)
      throws NumberFormatException {

    // Check the the value actually is an int. Throws NumberFormatException
    if (!StringUtils.equals(CmpConfiguration.PROFILE_USE_KEYID, eep)) {
      Integer.parseInt(eep);
    }

    String key = alias + "." + CONFIG_RA_ENDENTITYPROFILEID;
    if (!data.containsKey(key)) {
      // Lazy initialization for upgrade
      data.put(key, DEFAULT_RA_EEPROFILE);
    }
    setValue(key, eep, alias);
  }

  /**
 * @param alias Alias
 * @return  Profile */
  public String getRACertProfile(final String alias) {
    String key = alias + "." + CONFIG_RA_CERTIFICATEPROFILE;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param certp profile
   */
  public void setRACertProfile(final String alias, final String certp) {
    String key = alias + "." + CONFIG_RA_CERTIFICATEPROFILE;
    setValue(key, certp, alias);
  }

  /**
   * @param alias Alias
   * @return Name
   */
  public String getRACAName(final String alias) {
    String key = alias + "." + CONFIG_RACANAME;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param caname Name
   */
  public void setRACAName(final String alias, final String caname) {
    String key = alias + "." + CONFIG_RACANAME;
    setValue(key, caname, alias);
  }

  /**
   * @param alias Alias
   * @return Path
   */
  public String getRACertPath(final String alias) {
    String key = alias + "." + CONFIG_RACERT_PATH;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param certpath Path
   */
  public void setRACertPath(final String alias, final String certpath) {
    String key = alias + "." + CONFIG_RACERT_PATH;
    setValue(key, certpath, alias);
  }

  /**
   * @param alias alias
   * @return bool
   */
  public boolean getOmitVerificationsInEEC(final String alias) {
    String key = alias + "." + CONFIG_RA_OMITVERIFICATIONSINEEC;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias Alias
   * @param omit bool
   */
  public void setOmitVerificationsInECC(
      final String alias, final boolean omit) {
    String key = alias + "." + CONFIG_RA_OMITVERIFICATIONSINEEC;
    setValue(key, Boolean.toString(omit), alias);
  }

  /**
   * @param alias alias
   * @return bool
   */
  public boolean getKurAllowAutomaticUpdate(final String alias) {
    String key = alias + "." + CONFIG_ALLOWAUTOMATICKEYUPDATE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias alias
   * @param allowAutomaticUpdate bool
   */
  public void setKurAllowAutomaticUpdate(
      final String alias, final boolean allowAutomaticUpdate) {
    String key = alias + "." + CONFIG_ALLOWAUTOMATICKEYUPDATE;
    setValue(key, Boolean.toString(allowAutomaticUpdate), alias);
  }

  /**
   * @param alias alias
   * @return bool
   */
  public boolean getAllowServerGeneratedKeys(final String alias) {
    String key = alias + "." + CONFIG_ALLOWSERVERGENERATEDKEYS;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias alias
   * @param allowSrvGenKeys bool
   */
  public void setAllowServerGeneratedKeys(
      final String alias, final boolean allowSrvGenKeys) {
    String key = alias + "." + CONFIG_ALLOWSERVERGENERATEDKEYS;
    setValue(key, Boolean.toString(allowSrvGenKeys), alias);
  }

  /**
   * @param alias alias
   * @return bool
   */
  public boolean getKurAllowSameKey(final String alias) {
    String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias alias
   * @param allowSameKey key
   */
  public void setKurAllowSameKey(
      final String alias, final boolean allowSameKey) {
    String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
    setValue(key, Boolean.toString(allowSameKey), alias);
  }

  /**
   * @param alias alisa
   * @return class
   */
  public String getCertReqHandlerClass(final String alias) {
    String key = alias + "." + CONFIG_CERTREQHANDLER_CLASS;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param certReqClass Class
   */
  public void setCertReqHandlerClass(
      final String alias, final String certReqClass) {
    String key = alias + "." + CONFIG_CERTREQHANDLER_CLASS;
    setValue(key, certReqClass, alias);
  }

  /**
   * @param key Key
   * @param alias Alias
   * @return Value
   */
  public String getValue(final String key, final String alias) {
    if (aliasExists(alias)) {
      if (data.containsKey(key)) {
        return (String) data.get(key);
      } else {
        LOG.info(
            "Could not find key '" + key + "' in the CMP configuration data");
      }
    } else {
      LOG.error("CMP alias '" + alias + "' does not exist");
    }
    return null;
  }

  /**
   * @param key Key
   * @param value Value
   * @param alias Alias
   */
  public void setValue(
      final String key, final String value, final String alias) {
    if (aliasExists(alias)) {
      if (data.containsKey(key)) {
        data.put(key, value);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Edited '"
                  + key
                  + "="
                  + value
                  + "' in the CMP configuration data");
        }
      } else {
        data.put(key, value);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Added '"
                  + key
                  + "="
                  + value
                  + "' to the CMP configuration data");
        }
      }
    } else {
      LOG.error("CMP alias '" + alias + "' does not exist");
    }
  }

  /**
   * @param ramode mode
   * @return response
   */
  public Collection<String> getCmpResponseProtectionList(final boolean ramode) {
    ArrayList<String> pl = new ArrayList<>();
    pl.add("signature");
    if (ramode) {
      pl.add("pbe");
    }
    return pl;
  }

  /**
   * set list of aliases. Use LinkedHashSet to maintain order, which is
   * important for consistent databaseprotection
   *
   * @param aliaslist LinkedHashSet of aliases,
   */
  public void setAliasList(final LinkedHashSet<String> aliaslist) {
    data.put(aliasList, aliaslist);
  }

  /**
   * @return Aliases
   */
  public Set<String> getAliasList() {
    @SuppressWarnings("unchecked")
    Set<String> ret = (Set<String>) data.get(aliasList);

    return (ret == null ? DEFAULT_ALIAS_LIST : ret);
  }

  /**
   * @return Aliases
   */
  public List<String> getSortedAliasList() {
    List<String> result = new ArrayList<>(getAliasList());
    Collections.sort(
        result,
        new Comparator<String>() {
          @Override
          public int compare(final String o1, final String o2) {
            return o1.compareToIgnoreCase(o2);
          }
        });
    return result;
  }

  /**
   * @param alias alias
   * @return bool
   */
  public boolean aliasExists(final String alias) {
    if (StringUtils.isNotEmpty(alias)) {
      Set<String> aliases = getAliasList();
      return aliases.contains(alias);
    }
    return false;
  }

  /**
   * @param alias alias
   */
  public void addAlias(final String alias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Adding CMP alias: " + alias);
    }

    if (StringUtils.isEmpty(alias)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No alias is added because no alias was provided.");
      }
      return;
    }

    Set<String> aliases = getAliasList();
    if (aliases.contains(alias)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("CMP alias '" + alias + "' already exists.");
      }
      return;
    }

    initialize(alias);
    aliases.add(alias);
    data.put(aliasList, aliases);
  }

  /**
   * @param alias alias
   */
  public void removeAlias(final String alias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Removing CMP alias: " + alias);
    }

    if (StringUtils.isEmpty(alias)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No alias is removed because no alias was provided.");
      }
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(alias)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("CMP alias '" + alias + "' does not exist");
      }
      return;
    }

    for (String key : getAllAliasKeys(alias)) {
      data.remove(key);
    }
    // remove old keys from previous versions of EJBCA
    data.remove(CONFIG_UNIDDATASOURCE);
    aliases.remove(alias);
    data.put(aliasList, aliases);
  }

  /**
   * @param oldAlias old
   * @param newAlias new
   */
  public void renameAlias(final String oldAlias, final String newAlias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Renaming CMP alias '" + oldAlias + "' to '" + newAlias + "'");
    }

    if (StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
      LOG.info(
          "No alias is renamed because one or both aliases were not provided.");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(oldAlias)) {
      LOG.info("Cannot rename. CMP alias '" + oldAlias + "' does not exists.");
      return;
    }

    if (aliases.contains(newAlias)) {
      LOG.info("Cannot rename. CMP alias '" + newAlias + "' already exists.");
      return;
    }

    Set<String> oldKeys = getAllAliasKeys(oldAlias);
    Iterator<String> itr = oldKeys.iterator();
    while (itr.hasNext()) {
      String oldkey = itr.next();
      String newkey = oldkey;
      newkey = StringUtils.replace(newkey, oldAlias, newAlias);
      Object value = data.get(oldkey);
      data.put(newkey, value);
    }
    removeAlias(oldAlias);
    aliases.remove(oldAlias);
    aliases.add(newAlias);
    data.put(aliasList, aliases);
  }

  /**
   * @param originAlias Old
   * @param cloneAlias New
   */
  public void cloneAlias(final String originAlias, final String cloneAlias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Cloning CMP alias '" + originAlias + "' to '" + cloneAlias + "'");
    }

    if (StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
      LOG.info(
          "No alias is cloned because one or both aliased were not provided");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(originAlias)) {
      LOG.info("Cannot clone. CMP alias '" + originAlias + "' does not exist.");
      return;
    }

    if (aliases.contains(cloneAlias)) {
      LOG.info("Cannot clone. CMP alias '" + cloneAlias + "' already exists.");
      return;
    }

    Iterator<String> itr = getAllAliasKeys(originAlias).iterator();
    while (itr.hasNext()) {
      String originalKey = itr.next();
      String cloneKey = originalKey;
      cloneKey = StringUtils.replace(cloneKey, originAlias, cloneAlias);
      Object value = data.get(originalKey);
      data.put(cloneKey, value);
    }
    aliases.add(cloneAlias);
    data.put(aliasList, aliases);
  }

  /** @return the configuration as a regular Properties object */
  public Properties getAsProperties() {
    final Properties properties = new Properties();
    Set<String> aliases = getAliasList();
    Iterator<String> itr = aliases.iterator();
    while (itr.hasNext()) {
      String alias = itr.next();
      Properties aliasp = getAsProperties(alias);
      properties.putAll(aliasp);
    }
    return properties;
  }

  /**
   * @param alias Alias
   * @return props
   */
  public Properties getAsProperties(final String alias) {
    if (aliasExists(alias)) {
      final Properties properties = new Properties();
      final Iterator<String> i = getAllAliasKeys(alias).iterator();
      while (i.hasNext()) {
        final String key = i.next();
        final Object value = data.get(key);
        properties.setProperty(key, value == null ? "" : value.toString());
      }
      return properties;
    }
    return null;
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion. */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      LOG.info(
          "Upgrading CMP Configuration with version "
              + Float.valueOf(getVersion()));
      // v4
      Set<String> aliases = getAliasList();
      for (String alias : aliases) {
        data.put(
            alias + "." + CONFIG_ALLOWSERVERGENERATEDKEYS,
            DEFAULT_ALLOW_SERVERGENERATED_KEYS);

        if (data.get(alias + "." + CONFIG_RESPONSE_CAPUBS_CA) == null) {
          data.put(
              alias + "." + CONFIG_RESPONSE_CAPUBS_CA,
              DEFAULT_RESPONSE_CAPUBS_CA);
        }
        if (data.get(alias + "." + CONFIG_RESPONSE_EXTRACERTS_CA) == null) {
          data.put(
              alias + "." + CONFIG_RESPONSE_EXTRACERTS_CA,
              DEFAULT_RESPONSE_EXTRACERTS_CA);
        }
      }
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  @Override
  public String getConfigurationId() {
    return CMP_CONFIGURATION_ID;
  }
}
