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

  private static final Logger log = Logger.getLogger(CmpConfiguration.class);

  // Constants: Authentication modules
  public static final String AUTHMODULE_REG_TOKEN_PWD = "RegTokenPwd";
  public static final String AUTHMODULE_DN_PART_PWD = "DnPartPwd";
  public static final String AUTHMODULE_HMAC = "HMAC";
  public static final String AUTHMODULE_ENDENTITY_CERTIFICATE =
      "EndEntityCertificate";

  // Constants: Configuration keys
  public static final String CONFIG_DEFAULTCA = "defaultca";
  public static final String CONFIG_ALLOWRAVERIFYPOPO = "allowraverifypopo";
  public static final String CONFIG_OPERATIONMODE = "operationmode";
  public static final String CONFIG_AUTHENTICATIONMODULE =
      "authenticationmodule";
  public static final String CONFIG_AUTHENTICATIONPARAMETERS =
      "authenticationparameters";
  public static final String CONFIG_EXTRACTUSERNAMECOMPONENT =
      "extractusernamecomponent";
  public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO =
      "ra.allowcustomcertserno";
  public static final String CONFIG_RA_NAMEGENERATIONSCHEME =
      "ra.namegenerationscheme";
  public static final String CONFIG_RA_NAMEGENERATIONPARAMS =
      "ra.namegenerationparameters";
  public static final String CONFIG_RA_NAMEGENERATIONPREFIX =
      "ra.namegenerationprefix";
  public static final String CONFIG_RA_NAMEGENERATIONPOSTFIX =
      "ra.namegenerationpostfix";
  public static final String CONFIG_RA_PASSWORDGENPARAMS =
      "ra.passwordgenparams";
  /**
   * @deprecated since 6.5.1, but remains to allow 100% uptime during upgrade.
   *     Use CONFIG_RA_ENDENTITYPROFILEID instead
   */
  @Deprecated
  public static final String CONFIG_RA_ENDENTITYPROFILE = "ra.endentityprofile";

  public static final String CONFIG_RA_ENDENTITYPROFILEID =
      "ra.endentityprofileid";
  public static final String CONFIG_RA_CERTIFICATEPROFILE =
      "ra.certificateprofile";
  public static final String CONFIG_RESPONSEPROTECTION = "responseprotection";
  public static final String CONFIG_RACANAME = "ra.caname";
  public static final String CONFIG_VENDORCERTIFICATEMODE =
      "vendorcertificatemode";
  public static final String CONFIG_VENDORCA = "vendorca";
  public static final String CONFIG_RESPONSE_CAPUBS_CA = "response.capubsca";
  public static final String CONFIG_RESPONSE_EXTRACERTS_CA =
      "response.extracertsca";
  public static final String CONFIG_RA_OMITVERIFICATIONSINEEC =
      "ra.endentitycertificate.omitverifications";
  public static final String CONFIG_RACERT_PATH = "racertificatepath";
  public static final String CONFIG_ALLOWAUTOMATICKEYUPDATE =
      "allowautomatickeyupdate";
  public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY =
      "allowupdatewithsamekey";
  public static final String CONFIG_ALLOWSERVERGENERATEDKEYS =
      "allowservergenkeys";
  public static final String CONFIG_CERTREQHANDLER_CLASS =
      "certreqhandler.class";
  /**
   * @deprecated since 6.12.0. No longer used, and can no longer be set. The
   *     datasource is now hard-coded to be UnidDS
   */
  @Deprecated
  public static final String CONFIG_UNIDDATASOURCE = "uniddatasource";

  public static final String PROFILE_USE_KEYID = "KeyId";
  public static final String PROFILE_DEFAULT = "ProfileDefault";

  // This List is used in the command line handling of updating a config value
  // to ensure a correct value.
  public static final List<String> CMP_BOOLEAN_KEYS =
      Arrays.asList(
          CONFIG_VENDORCERTIFICATEMODE,
          CONFIG_ALLOWRAVERIFYPOPO,
          CONFIG_RA_ALLOWCUSTOMCERTSERNO,
          CONFIG_ALLOWAUTOMATICKEYUPDATE,
          CONFIG_ALLOWUPDATEWITHSAMEKEY,
          CONFIG_ALLOWSERVERGENERATEDKEYS);

  private final String ALIAS_LIST = "aliaslist";
  public static final String CMP_CONFIGURATION_ID = "1";

  // Default Values
  public static final float LATEST_VERSION = 8f;
  public static final String EJBCA_VERSION =
      InternalConfiguration.getAppVersion();

  // Default values
  private static final Set<String> DEFAULT_ALIAS_LIST = new LinkedHashSet<>();
  private static final String DEFAULT_DEFAULTCA = "";
  private static final String DEFAULT_OPERATION_MODE = "client";
  private static final String DEFAULT_EXTRACT_USERNAME_COMPONENT = "DN";
  private static final String DEFAULT_VENDOR_MODE = "false";
  private static final String DEFAULT_VENDOR_CA = "";
  private static final String DEFAULT_RESPONSE_CAPUBS_CA = "";
  private static final String DEFAULT_RESPONSE_EXTRACERTS_CA = "";
  private static final String DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE = "false";
  private static final String DEFAULT_ALLOW_SERVERGENERATED_KEYS = "false";
  private static final String DEFAULT_KUR_ALLOW_SAME_KEY = "true";
  private static final String DEFAULT_RESPONSE_PROTECTION = "signature";
  private static final String DEFAULT_ALLOW_RA_VERIFY_POPO = "false";
  private static final String DEFAULT_RA_USERNAME_GENERATION_SCHEME = "DN";
  private static final String DEFAULT_RA_USERNAME_GENERATION_PARAMS = "CN";
  private static final String DEFAULT_RA_USERNAME_GENERATION_PREFIX = "";
  private static final String DEFAULT_RA_USERNAME_GENERATION_POSTFIX = "";
  private static final String DEFAULT_RA_PASSWORD_GENERARION_PARAMS = "random";
  private static final String DEFAULT_RA_ALLOW_CUSTOM_SERNO = "false";
  public static final String DEFAULT_RA_EEPROFILE = "1";
  private static final String DEFAULT_RA_CERTPROFILE = "ENDUSER";
  private static final String DEFAULT_RA_CANAME = "ManagementCA";
  private static final String DEFAULT_CLIENT_AUTHENTICATION_MODULE =
      CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD
          + ";"
          + CmpConfiguration.AUTHMODULE_HMAC;
  private static final String DEFAULT_CLIENT_AUTHENTICATION_PARAMS = "-;-";
  private static final String DEFAULT_RA_OMITVERIFICATIONSINEEC = "false";
  private static final String DEFAULT_RACERT_PATH = "";
  private static final String DEFAULT_CERTREQHANDLER =
      ""; // "org.ejbca.core.protocol.unid.UnidFnrHandler";

  /** Creates a new instance of CmpConfiguration */
  public CmpConfiguration() {
    super();
  }

  public CmpConfiguration(final Serializable dataobj) {
    @SuppressWarnings("unchecked")
    LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
    data = d;
  }

  /**
   * Copy constructor for {@link CmpConfiguration}
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
   * @param alias alias
   */
  public void initialize(String alias) {
    if (StringUtils.isNotEmpty(alias)) {
      alias = alias + ".";
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

  // return all the key with an alias
  public static Set<String> getAllAliasKeys(String alias) {
    alias = alias + ".";
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

  public void setCMPDefaultCA(final String alias, final String defCA) {
    String key = alias + "." + CONFIG_DEFAULTCA;
    setValue(key, defCA, alias);
  }

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

  public void setResponseProtection(
      final String alias, final String protection) {
    String key = alias + "." + CONFIG_RESPONSEPROTECTION;
    setValue(key, protection, alias);
  }

  // Any value that is not "ra" or "RA" will be client mode, no matter what it
  // is
  public boolean getRAMode(final String alias) {
    String key = alias + "." + CONFIG_OPERATIONMODE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "ra");
  }

  public void setRAMode(final String alias, final boolean ramode) {
    String key = alias + "." + CONFIG_OPERATIONMODE;
    setValue(key, ramode ? "ra" : "client", alias);
  }

  public void setRAMode(final String alias, final String mode) {
    setRAMode(alias, StringUtils.equalsIgnoreCase(mode, "ra"));
  }

  public String getAuthenticationModule(final String alias) {
    String key = alias + "." + CONFIG_AUTHENTICATIONMODULE;
    return getValue(key, alias);
  }

  public void setAuthenticationModule(
      final String alias, final String authModule) {
    String key = alias + "." + CONFIG_AUTHENTICATIONMODULE;
    setValue(key, authModule, alias);
  }

  public void setAuthenticationProperties(
      final String alias,
      final ArrayList<String> authmodules,
      final ArrayList<String> authparams) {
    if (authmodules.isEmpty()) {
      if (log.isDebugEnabled()) {
        log.debug(
            "Did not update CMP Authentication modules or parameters because"
                + " no Authentication module was specified");
      }
      return;
    }

    if (authmodules.size() != authparams.size()) {
      log.info(
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

  public String getAuthenticationParameters(final String alias) {
    String key = alias + "." + CONFIG_AUTHENTICATIONPARAMETERS;
    return getValue(key, alias);
  }

  public void setAuthenticationParameters(
      final String alias, final String authParams) {
    String key = alias + "." + CONFIG_AUTHENTICATIONPARAMETERS;
    setValue(key, authParams, alias);
  }

  public void setAuthenticationParameters(
      final String alias, final ArrayList<String> authparameters) {
    String authparam = "";
    for (String p : authparameters) {
      authparam += ";" + p;
    }
    authparam = authparam.substring(1);
    setAuthenticationParameters(alias, authparam);
  }

  public String getAuthenticationParameter(
      final String authModule, final String alias) {

    if (StringUtils.isNotEmpty(alias)) {
      String confModule = getAuthenticationModule(alias);
      String confParams = getAuthenticationParameters(alias);

      String modules[] = confModule.split(";");
      String params[] = confParams.split(";");

      if (modules.length > params.length) {
        log.info(
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
      if (log.isDebugEnabled()) {
        log.debug("No CMP alias was specified. Returning an empty String");
      }
      return "";
    }
  }

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

  public String getExtractUsernameComponent(final String alias) {
    String key = alias + "." + CONFIG_EXTRACTUSERNAMECOMPONENT;
    return getValue(key, alias);
  }

  public void setExtractUsernameComponent(
      final String alias, final String extractComponent) {
    String key = alias + "." + CONFIG_EXTRACTUSERNAMECOMPONENT;
    setValue(key, extractComponent, alias);
  }

  public boolean getVendorMode(final String alias) {
    String key = alias + "." + CONFIG_VENDORCERTIFICATEMODE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  public void setVendorMode(final String alias, final boolean vendormode) {
    String key = alias + "." + CONFIG_VENDORCERTIFICATEMODE;
    setValue(key, Boolean.toString(vendormode), alias);
  }

  public String getVendorCA(final String alias) {
    String key = alias + "." + CONFIG_VENDORCA;
    return getValue(key, alias);
  }

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

  public boolean getAllowRAVerifyPOPO(final String alias) {
    String key = alias + "." + CONFIG_ALLOWRAVERIFYPOPO;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  public void setAllowRAVerifyPOPO(
      final String alias, final boolean raVerifyPopo) {
    String key = alias + "." + CONFIG_ALLOWRAVERIFYPOPO;
    setValue(key, Boolean.toString(raVerifyPopo), alias);
  }

  public String getRANameGenScheme(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
    return getValue(key, alias);
  }

  public void setRANameGenScheme(final String alias, final String scheme) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
    setValue(key, scheme, alias);
  }

  public String getRANameGenParams(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
    return getValue(key, alias);
  }

  public void setRANameGenParams(final String alias, final String params) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
    setValue(key, params, alias);
  }

  public String getRANameGenPrefix(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
    return getValue(key, alias);
  }

  public void setRANameGenPrefix(final String alias, final String prefix) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
    setValue(key, prefix, alias);
  }

  public String getRANameGenPostfix(final String alias) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
    return getValue(key, alias);
  }

  public void setRANameGenPostfix(final String alias, final String postfix) {
    String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
    setValue(key, postfix, alias);
  }

  public String getRAPwdGenParams(final String alias) {
    String key = alias + "." + CONFIG_RA_PASSWORDGENPARAMS;
    return getValue(key, alias);
  }

  public void setRAPwdGenParams(final String alias, final String params) {
    String key = alias + "." + CONFIG_RA_PASSWORDGENPARAMS;
    setValue(key, params, alias);
  }

  public boolean getAllowRACustomSerno(final String alias) {
    String key = alias + "." + CONFIG_RA_ALLOWCUSTOMCERTSERNO;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

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

  public String getRACertProfile(final String alias) {
    String key = alias + "." + CONFIG_RA_CERTIFICATEPROFILE;
    return getValue(key, alias);
  }

  public void setRACertProfile(final String alias, final String certp) {
    String key = alias + "." + CONFIG_RA_CERTIFICATEPROFILE;
    setValue(key, certp, alias);
  }

  public String getRACAName(final String alias) {
    String key = alias + "." + CONFIG_RACANAME;
    return getValue(key, alias);
  }

  public void setRACAName(final String alias, final String caname) {
    String key = alias + "." + CONFIG_RACANAME;
    setValue(key, caname, alias);
  }

  public String getRACertPath(final String alias) {
    String key = alias + "." + CONFIG_RACERT_PATH;
    return getValue(key, alias);
  }

  public void setRACertPath(final String alias, final String certpath) {
    String key = alias + "." + CONFIG_RACERT_PATH;
    setValue(key, certpath, alias);
  }

  public boolean getOmitVerificationsInEEC(final String alias) {
    String key = alias + "." + CONFIG_RA_OMITVERIFICATIONSINEEC;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  public void setOmitVerificationsInECC(
      final String alias, final boolean omit) {
    String key = alias + "." + CONFIG_RA_OMITVERIFICATIONSINEEC;
    setValue(key, Boolean.toString(omit), alias);
  }

  public boolean getKurAllowAutomaticUpdate(final String alias) {
    String key = alias + "." + CONFIG_ALLOWAUTOMATICKEYUPDATE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  public void setKurAllowAutomaticUpdate(
      final String alias, final boolean allowAutomaticUpdate) {
    String key = alias + "." + CONFIG_ALLOWAUTOMATICKEYUPDATE;
    setValue(key, Boolean.toString(allowAutomaticUpdate), alias);
  }

  public boolean getAllowServerGeneratedKeys(final String alias) {
    String key = alias + "." + CONFIG_ALLOWSERVERGENERATEDKEYS;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  public void setAllowServerGeneratedKeys(
      final String alias, final boolean allowSrvGenKeys) {
    String key = alias + "." + CONFIG_ALLOWSERVERGENERATEDKEYS;
    setValue(key, Boolean.toString(allowSrvGenKeys), alias);
  }

  public boolean getKurAllowSameKey(final String alias) {
    String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  public void setKurAllowSameKey(
      final String alias, final boolean allowSameKey) {
    String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
    setValue(key, Boolean.toString(allowSameKey), alias);
  }

  public String getCertReqHandlerClass(final String alias) {
    String key = alias + "." + CONFIG_CERTREQHANDLER_CLASS;
    return getValue(key, alias);
  }

  public void setCertReqHandlerClass(
      final String alias, final String certReqClass) {
    String key = alias + "." + CONFIG_CERTREQHANDLER_CLASS;
    setValue(key, certReqClass, alias);
  }

  public String getValue(final String key, final String alias) {
    if (aliasExists(alias)) {
      if (data.containsKey(key)) {
        return (String) data.get(key);
      } else {
        log.info(
            "Could not find key '" + key + "' in the CMP configuration data");
      }
    } else {
      log.error("CMP alias '" + alias + "' does not exist");
    }
    return null;
  }

  public void setValue(
      final String key, final String value, final String alias) {
    if (aliasExists(alias)) {
      if (data.containsKey(key)) {
        data.put(key, value);
        if (log.isDebugEnabled()) {
          log.debug(
              "Edited '"
                  + key
                  + "="
                  + value
                  + "' in the CMP configuration data");
        }
      } else {
        data.put(key, value);
        if (log.isDebugEnabled()) {
          log.debug(
              "Added '"
                  + key
                  + "="
                  + value
                  + "' to the CMP configuration data");
        }
      }
    } else {
      log.error("CMP alias '" + alias + "' does not exist");
    }
  }

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
    data.put(ALIAS_LIST, aliaslist);
  }

  public Set<String> getAliasList() {
    @SuppressWarnings("unchecked")
    Set<String> ret = (Set<String>) data.get(ALIAS_LIST);

    return (ret == null ? DEFAULT_ALIAS_LIST : ret);
  }

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

  public boolean aliasExists(final String alias) {
    if (StringUtils.isNotEmpty(alias)) {
      Set<String> aliases = getAliasList();
      return aliases.contains(alias);
    }
    return false;
  }

  public void addAlias(final String alias) {
    if (log.isDebugEnabled()) {
      log.debug("Adding CMP alias: " + alias);
    }

    if (StringUtils.isEmpty(alias)) {
      if (log.isDebugEnabled()) {
        log.debug("No alias is added because no alias was provided.");
      }
      return;
    }

    Set<String> aliases = getAliasList();
    if (aliases.contains(alias)) {
      if (log.isDebugEnabled()) {
        log.debug("CMP alias '" + alias + "' already exists.");
      }
      return;
    }

    initialize(alias);
    aliases.add(alias);
    data.put(ALIAS_LIST, aliases);
  }

  public void removeAlias(final String alias) {
    if (log.isDebugEnabled()) {
      log.debug("Removing CMP alias: " + alias);
    }

    if (StringUtils.isEmpty(alias)) {
      if (log.isDebugEnabled()) {
        log.debug("No alias is removed because no alias was provided.");
      }
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(alias)) {
      if (log.isDebugEnabled()) {
        log.debug("CMP alias '" + alias + "' does not exist");
      }
      return;
    }

    for (String key : getAllAliasKeys(alias)) {
      data.remove(key);
    }
    // remove old keys from previous versions of EJBCA
    data.remove(CONFIG_UNIDDATASOURCE);
    aliases.remove(alias);
    data.put(ALIAS_LIST, aliases);
  }

  public void renameAlias(final String oldAlias, final String newAlias) {
    if (log.isDebugEnabled()) {
      log.debug("Renaming CMP alias '" + oldAlias + "' to '" + newAlias + "'");
    }

    if (StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
      log.info(
          "No alias is renamed because one or both aliases were not provided.");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(oldAlias)) {
      log.info("Cannot rename. CMP alias '" + oldAlias + "' does not exists.");
      return;
    }

    if (aliases.contains(newAlias)) {
      log.info("Cannot rename. CMP alias '" + newAlias + "' already exists.");
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
    data.put(ALIAS_LIST, aliases);
  }

  public void cloneAlias(final String originAlias, final String cloneAlias) {
    if (log.isDebugEnabled()) {
      log.debug(
          "Cloning CMP alias '" + originAlias + "' to '" + cloneAlias + "'");
    }

    if (StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
      log.info(
          "No alias is cloned because one or both aliased were not provided");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(originAlias)) {
      log.info("Cannot clone. CMP alias '" + originAlias + "' does not exist.");
      return;
    }

    if (aliases.contains(cloneAlias)) {
      log.info("Cannot clone. CMP alias '" + cloneAlias + "' already exists.");
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
    data.put(ALIAS_LIST, aliases);
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

  /** Implementation of UpgradableDataHashMap function getLatestVersion */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade
      log.info(
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
