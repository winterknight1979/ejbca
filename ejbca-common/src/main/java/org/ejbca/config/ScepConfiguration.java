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
import java.util.Arrays;
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
 * @version $Id: ScepConfiguration.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class ScepConfiguration extends ConfigurationBase
    implements Serializable {

  private static final long serialVersionUID = -2051789798029184421L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(ScepConfiguration.class);

  public enum Mode {
      /** CA. */
    CA("CA"),
    /** RA. */
    RA("RA");

      /** resource. */
    private final String resource;

    Mode(final String aresource) {
      this.resource = aresource;
    }

    /**
     * @return resource
     */
    public String getResource() {
      return resource;
    }

    @Override
    public String toString() {
      return resource;
    }
  }

  // Constants: Configuration keys
  /** Config. */
  public static final String SCEP_PREFIX = "scep.";
  /** Config. */
  public static final String SCEP_RAMODE_OLD = "ra.createOrEditUser";
  /** Config. */
  public static final String SCEP_OPERATIONMODE = "operationmode";
  /** Config. */
  public static final String SCEP_INCLUDE_CA = "includeca";
  /** Config. */
  public static final String SCEP_RA_CERTPROFILE = "ra.certificateProfile";
  /** Config. */
  public static final String SCEP_RA_ENTITYPROFILE = "ra.entityProfile";
  /** Config. */
  public static final String SCEP_RA_AUTHPWD = "ra.authPwd";
  /** Config. */
  public static final String SCEP_RA_DEFAULTCA = "ra.defaultCA";
  /** Config. */
  public static final String SCEP_RA_NAME_GENERATION_SCHEME =
      "ra.namegenerationscheme";
  /** Config. */
  public static final String SCEP_RA_NAME_GENERATION_PARAMETERS =
      "ra.namegenerationparameters";
  /** Config. */
  public static final String SCEP_RA_NAME_GENERATION_PREFIX =
      "ra.namegenerationprefix";
  /** Config. */
  public static final String SCEP_RA_NAME_GENERATION_POSTFIX =
      "ra.namegenerationpostfix";
  /** Config. */
  public static final String SCEP_CLIENT_CERTIFICATE_RENEWAL =
      "clientCertificateRenewal";
  /** Config. */
  public static final String SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY =
      "clientCertificateRenewalWithOldKey";

  /** This List is used in the command line handling of updating a config value
   * to insure a correct value. */
  public static final List<String> SCEP_BOOLEAN_KEYS =
      Arrays.asList(SCEP_INCLUDE_CA);

  /** Config. */
  public static final String SCEP_CONFIGURATION_ID = "2";

  /** Config. */
  private final String aliasList = "aliaslist";

  // Default Values
  /** Config. */
  public static final float LATEST_VERSION = 3f;
  /** Config. */
  public static final String EJBCA_VERSION =
      InternalConfiguration.getAppVersion();

  /** Config. */
  public static final Set<String> DEFAULT_ALIAS_LIST =
      new LinkedHashSet<String>();
  /** Config. */
  public static final String DEFAULT_OPERATION_MODE = Mode.CA.getResource();
  /** Config. */
  public static final String DEFAULT_INCLUDE_CA = Boolean.TRUE.toString();
  /** Config. */
  public static final String DEFAULT_CLIENT_CERTIFICATE_RENEWAL =
      Boolean.FALSE.toString();
  /** Config. */
  public static final String
      DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY =
          Boolean.FALSE.toString();
  /** Config. */
  public static final String DEFAULT_RA_CERTPROFILE = "ENDUSER";
  /** Config. */
  public static final String DEFAULT_RA_ENTITYPROFILE = "EMPTY";
  /** Config. */
  public static final String DEFAULT_RA_DEFAULTCA = "";
  /** Config. */
  public static final String DEFAULT_RA_AUTHPWD = "";
  /** Config. */
  public static final String DEFAULT_RA_NAME_GENERATION_SCHEME = "DN";
  /** Config. */
  public static final String DEFAULT_RA_NAME_GENERATION_PARAMETERS = "CN";
  /** Config. */
  public static final String DEFAULT_RA_NAME_GENERATION_PREFIX = "";
  /** Config. */
  public static final String DEFAULT_RA_NAME_GENERATION_POSTFIX = "";

  /** Creates a new instance of ScepConfiguration. */
  public ScepConfiguration() {
    super();
  }

  /**
   * @param dataobj object
   */
  public ScepConfiguration(final Serializable dataobj) {
    @SuppressWarnings("unchecked")
    LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
    data = d;
  }

  /**
   * Initializes a new scep configuration with default values.
   *
   * @param oalias Alias
   */
  public void initialize(final String oalias) {
    String alias = oalias + ".";
    if (StringUtils.isNotEmpty(alias)) {
      data.put(alias + SCEP_OPERATIONMODE, DEFAULT_OPERATION_MODE);
      data.put(alias + SCEP_INCLUDE_CA, DEFAULT_INCLUDE_CA);
      data.put(alias + SCEP_RA_CERTPROFILE, DEFAULT_RA_CERTPROFILE);
      data.put(alias + SCEP_RA_ENTITYPROFILE, DEFAULT_RA_ENTITYPROFILE);
      data.put(alias + SCEP_RA_DEFAULTCA, DEFAULT_RA_DEFAULTCA);
      data.put(alias + SCEP_RA_AUTHPWD, DEFAULT_RA_AUTHPWD);
      data.put(
          alias + SCEP_RA_NAME_GENERATION_SCHEME,
          DEFAULT_RA_NAME_GENERATION_SCHEME);
      data.put(
          alias + SCEP_RA_NAME_GENERATION_PARAMETERS,
          DEFAULT_RA_NAME_GENERATION_PARAMETERS);
      data.put(
          alias + SCEP_RA_NAME_GENERATION_PREFIX,
          DEFAULT_RA_NAME_GENERATION_PREFIX);
      data.put(
          alias + SCEP_RA_NAME_GENERATION_POSTFIX,
          DEFAULT_RA_NAME_GENERATION_POSTFIX);
      data.put(
          alias + SCEP_CLIENT_CERTIFICATE_RENEWAL,
          DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
      data.put(
          alias + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY,
          DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
    }
  }

  /**return all the key with an alias.
   *
   * @param oalias alias
   * @return keys
   */
  public static Set<String> getAllAliasKeys(final String oalias) {
    String alias =  oalias + ".";
    Set<String> keys = new LinkedHashSet<String>();
    keys.add(alias + SCEP_OPERATIONMODE);
    keys.add(alias + SCEP_INCLUDE_CA);
    keys.add(alias + SCEP_RA_CERTPROFILE);
    keys.add(alias + SCEP_RA_ENTITYPROFILE);
    keys.add(alias + SCEP_RA_DEFAULTCA);
    keys.add(alias + SCEP_RA_AUTHPWD);
    keys.add(alias + SCEP_RA_NAME_GENERATION_SCHEME);
    keys.add(alias + SCEP_RA_NAME_GENERATION_PARAMETERS);
    keys.add(alias + SCEP_RA_NAME_GENERATION_PREFIX);
    keys.add(alias + SCEP_RA_NAME_GENERATION_POSTFIX);
    keys.add(alias + SCEP_CLIENT_CERTIFICATE_RENEWAL);
    keys.add(alias + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
    return keys;
  }

  /**
   * Client Certificate Renewal is defined in the SCEP draft as the capability
   * of a certificate enrollment request to be interpreted as a certificate
   * renewal request if the previous certificate has passed half its validity.
   *
   * @param alias A SCEP configuration alias
   * @return true of SCEP Client Certificate Renewal is enabled
   */
  public boolean getClientCertificateRenewal(final String alias) {
    String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL;
    String value = getValue(key, alias);
    // Lazy initialization for SCEP configurations older than 6.3.1
    if (value == null) {
      data.put(
          alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL,
          DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
      return Boolean.getBoolean(DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
    }
    return Boolean.valueOf(value);
  }
  /**
   * @see ScepConfiguration#getClientCertificateRenewal(String)
   * @param alias A SCEP configuration alias
   * @param clientCertificateRenewal true of Client Certificate Renewal is to be
   *     enabled
   */
  public void setClientCertificateRenewal(
      final String alias, final boolean clientCertificateRenewal) {
    String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL;
    setValue(key, Boolean.toString(clientCertificateRenewal), alias);
  }

  /**
   * @see ScepConfiguration#getClientCertificateRenewal(String) for information
   *     about Client Certificate Renewal
   *     <p>The SCEP draft makes it optional whether or not old keys may be
   *     reused during Client Certificate Renewal
   * @param alias A SCEP configuration alias
   * @return true of old keys are allowed Client Certificate Renewal
   */
  public boolean getAllowClientCertificateRenewalWithOldKey(
      final String alias) {
    String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY;
    String value = getValue(key, alias);
    // Lazy initialization for SCEP configurations older than 6.3.1
    if (value == null) {
      data.put(
          alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY,
          DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
      return Boolean.getBoolean(
          DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
    }
    return Boolean.valueOf(value);
  }

  /**
   * @see ScepConfiguration#getAllowClientCertificateRenewalWithOldKey(String)
   * @param alias A SCEP configuration alias
   * @param allowClientCertificateRenewalWithOldKey set true to allow Client
   *     Certificate Renewal using old keys
   */
  public void setAllowClientCertificateRenewalWithOldKey(
      final String alias,
      final boolean allowClientCertificateRenewalWithOldKey) {
    String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY;
    setValue(
        key, Boolean.toString(allowClientCertificateRenewalWithOldKey), alias);
  }

  /**
   * Method used by the Admin GUI.
   *
   * @param alias Alias
   * @return Mode
   */
  public boolean getRAMode(final String alias) {
    String key = alias + "." + SCEP_OPERATIONMODE;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, Mode.RA.getResource());
  }

  /**
   * @param alias alias
   * @param ramode bool
   */
  public void setRAMode(final String alias, final boolean ramode) {
    String key = alias + "." + SCEP_OPERATIONMODE;
    setValue(
        key, ramode ? Mode.RA.getResource() : Mode.CA.getResource(), alias);
  }

  /**
   * @param alias alias
   * @return bool
   */
  public boolean getIncludeCA(final String alias) {
    String key = alias + "." + SCEP_INCLUDE_CA;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias alias
   * @param includeca bool
   */
  public void setIncludeCA(final String alias, final boolean includeca) {
    String key = alias + "." + SCEP_INCLUDE_CA;
    setValue(key, Boolean.toString(includeca), alias);
  }

  /**
   * @param alias alias
   * @return profile
   */
  public String getRACertProfile(final String alias) {
    String key = alias + "." + SCEP_RA_CERTPROFILE;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param cp profile
   */
  public void setRACertProfile(final String alias, final String cp) {
    String key = alias + "." + SCEP_RA_CERTPROFILE;
    setValue(key, cp, alias);
  }

  /**
   * @param alias alias
   * @return profile
   */
  public String getRAEndEntityProfile(final String alias) {
    String key = alias + "." + SCEP_RA_ENTITYPROFILE;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param eep Profile
   */
  public void setRAEndEntityProfile(final String alias, final String eep) {
    String key = alias + "." + SCEP_RA_ENTITYPROFILE;
    setValue(key, eep, alias);
  }

  /**
   * @param alias Alias
   * @return CA
   */
  public String getRADefaultCA(final String alias) {
    String key = alias + "." + SCEP_RA_DEFAULTCA;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param ca CA
   */
  public void setRADefaultCA(final String alias, final String ca) {
    String key = alias + "." + SCEP_RA_DEFAULTCA;
    setValue(key, ca, alias);
  }

  /**
   * @param alias alias
   * @return password
   */
  public String getRAAuthPassword(final String alias) {
    String key = alias + "." + SCEP_RA_AUTHPWD;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param pwd password
   */
  public void setRAAuthpassword(final String alias, final String pwd) {
    String key = alias + "." + SCEP_RA_AUTHPWD;
    setValue(key, pwd, alias);
  }

  /**
   * @param alias alias
   * @return scheme
   */
  public String getRANameGenerationScheme(final String alias) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_SCHEME;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param scheme scheme
   */
  public void setRANameGenerationScheme(
      final String alias, final String scheme) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_SCHEME;
    setValue(key, scheme, alias);
  }

  /**
   * @param alias alias
   * @return params
   */
  public String getRANameGenerationParameters(final String alias) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_PARAMETERS;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param parameters params
   */
  public void setRANameGenerationParameters(
      final String alias, final String parameters) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_PARAMETERS;
    setValue(key, parameters, alias);
  }

  /**
   * @param alias alias
   * @return prefix
   */
  public String getRANameGenerationPrefix(final String alias) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_PREFIX;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param prefix prefix
   */
  public void setRANameGenerationPrefix(
      final String alias, final String prefix) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_PREFIX;
    setValue(key, prefix, alias);
  }

  /**
   * @param alias alias
   * @return postfix
   */
  public String getRANameGenerationPostfix(final String alias) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_POSTFIX;
    return getValue(key, alias);
  }

  /**
   * @param alias alias
   * @param postfix postfic
   */
  public void setRANameGenerationPostfix(
      final String alias, final String postfix) {
    String key = alias + "." + SCEP_RA_NAME_GENERATION_POSTFIX;
    setValue(key, postfix, alias);
  }

  /**
   * @param key key
   * @param alias alias
   * @return value
   */
  public String getValue(final String key, final String alias) {
    if (aliasExists(alias)) {
      if (data.containsKey(key)) {
        return (String) data.get(key);
      } else {
        LOG.error(
            "Could not find key '" + key + "' in the SCEP configuration data");
      }
    } else {
      LOG.error("SCEP alias '" + alias + "' does not exist");
    }
    return null;
  }

  /**
   * @param key key
   * @param value value
   * @param alias alias
   */
  public void setValue(
      final String key, final String value, final String alias) {
    if (aliasExists(alias)) {
      if (data.containsKey(key)) {
        data.put(key, value);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Added '"
                  + key
                  + "="
                  + value
                  + "' to the SCEP configuration data");
        }
      } else {
        LOG.error(
            "Key '" + key + "' does not exist in the SCEP configuration data");
      }
    } else {
      LOG.error("SCEP alias '" + alias + "' does not exist");
    }
  }

  /**
   * @param aliaslist aliases
   */
  public void setAliasList(final Set<String> aliaslist) {
    data.put(aliasList, aliaslist);
  }

  /**
   * @return aiases
   */
  public Set<String> getAliasList() {
    @SuppressWarnings("unchecked")
    Set<String> ret = (Set<String>) data.get(aliasList);
    return (ret == null ? DEFAULT_ALIAS_LIST : ret);
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
      LOG.debug("Adding SCEP alias: " + alias);
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
        LOG.debug("SCEP alias '" + alias + "' already exists.");
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
      LOG.debug("Removing SCEP alias: " + alias);
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
        LOG.debug("SCEP alias '" + alias + "' does not exist");
      }
      return;
    }

    Set<String> removeKeys = getAllAliasKeys(alias);
    Iterator<String> itr = removeKeys.iterator();
    while (itr.hasNext()) {
      String key = itr.next();
      data.remove(key);
    }
    aliases.remove(alias);
    data.put(aliasList, aliases);
  }

  /**
   * @param oldAlias old
   * @param newAlias new
   */
  public void renameAlias(final String oldAlias, final String newAlias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Renaming SCEP alias '" + oldAlias + "' to '" + newAlias + "'");
    }

    if (StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
      LOG.info(
          "No alias is renamed because one or both aliases were not provided.");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(oldAlias)) {
      LOG.info("Cannot rename. SCEP alias '" + oldAlias + "' does not exists.");
      return;
    }

    if (aliases.contains(newAlias)) {
      LOG.info("Cannot rename. SCEP alias '" + newAlias + "' already exists.");
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
   * @param originAlias old
   * @param cloneAlias new
   */
  public void cloneAlias(final String originAlias, final String cloneAlias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Cloning SCEP alias '" + originAlias + "' to '" + cloneAlias + "'");
    }

    if (StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
      LOG.info(
          "No alias is cloned because one or both aliased were not provided");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(originAlias)) {
      LOG.info(
          "Cannot clone. SCEP alias '" + originAlias + "' does not exist.");
      return;
    }

    if (aliases.contains(cloneAlias)) {
      LOG.info("Cannot clone. SCEP alias '" + cloneAlias + "' already exists.");
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
   * @return Props
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

  /** Implementation of UpgradableDataHashMap function getLatestVersion.
   * @return version*/
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implemtation of UpgradableDataHashMap function upgrade. */
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  @Override
  public String getConfigurationId() {
    return SCEP_CONFIGURATION_ID;
  }
}
