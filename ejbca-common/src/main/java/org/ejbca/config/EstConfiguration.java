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
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.ConfigurationBase;

/**
 * This is a class containing EST configuration parameters.
 *
 * @version $Id: EstConfiguration.java 28048 2018-01-22 09:04:54Z anatom $
 */
public class EstConfiguration extends ConfigurationBase
    implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(EstConfiguration.class);

  // Constants: Configuration keys
  /** Config. */
  public static final String CONFIG_DEFAULTCA = "defaultca";
  /** Config. */
  public static final String CONFIG_CERTPROFILE = "certprofile";
  /** Config. */
  public static final String CONFIG_EEPROFILE = "eeprofile";
  /** Config. */
  public static final String CONFIG_REQCERT = "requirecert";
  /** Config. */
  public static final String CONFIG_REQUSERNAME = "requsername";
  /** Config. */
  public static final String CONFIG_REQPASSWORD = "reqpassword";
  /** Config. */
  public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY =
      "allowupdatewithsamekey";

  /** Config. */
  private static final String ALIAS_LIST = "aliaslist";
  /** Config. */
  public static final String EST_CONFIGURATION_ID = "4";

  // Default Values
  /** Config. */
  public static final float LATEST_VERSION = 3f;
  /** Config. */
  public static final String EJBCA_VERSION =
      InternalConfiguration.getAppVersion();

  // Default values
  /** Config. */
  private static final Set<String> DEFAULT_ALIAS_LIST = new LinkedHashSet<>();
  /** Config. */
  private static final String DEFAULT_DEFAULTCA = "";
  /** Config. */
  public static final String DEFAULT_EEPROFILE =
      String.valueOf(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
  /** Config. */
  private static final String DEFAULT_CERTPROFILE =
      String.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
  /** Config. */
  private static final String DEFAULT_REQCERT = "true";
  /** Config. */
  private static final String DEFAULT_REQUSERNAME = "";
  /** Config. */
  private static final String DEFAULT_REQPASSWORD = "";
  /** Config. */
  private static final String DEFAULT_ALLOWUPDATEWITHSAMEKEY = "true";

  /** This List is used in the command line handling of updating a config value
   to ensure a correct value. */
  public static final List<String> EST_BOOLEAN_KEYS =
      Arrays.asList(CONFIG_REQCERT, CONFIG_ALLOWUPDATEWITHSAMEKEY);

  /** Creates a new instance of EstConfiguration. */
  public EstConfiguration() {
    super();
  }

  /**
   * @param dataobj Object
   */
  public EstConfiguration(final Serializable dataobj) {
    @SuppressWarnings("unchecked")
    LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
    data = d;
  }

  /**
   * Copy constructor for {@link EstConfiguration}.
   *
   * @param estConfiguration Config
   */
  public EstConfiguration(final EstConfiguration estConfiguration) {
    super();
    setAliasList(new LinkedHashSet<String>());
    for (String alias : estConfiguration.getAliasList()) {
      addAlias(alias);
      for (String key : getAllAliasKeys(alias)) {
        String value = estConfiguration.getValue(key, alias);
        setValue(key, value, alias);
      }
    }
  }

  /**
   * Initializes a new cmp configuration with default values.
   *
   * @param oalias Alias
   */
  public void initialize(final String oalias) {
    if (StringUtils.isNotEmpty(oalias)) {
      String alias = oalias + ".";
      data.put(alias + CONFIG_DEFAULTCA, DEFAULT_DEFAULTCA);
      data.put(alias + CONFIG_CERTPROFILE, DEFAULT_CERTPROFILE);
      data.put(alias + CONFIG_EEPROFILE, DEFAULT_EEPROFILE);
      data.put(alias + CONFIG_REQCERT, DEFAULT_REQCERT);
      data.put(alias + CONFIG_REQUSERNAME, DEFAULT_REQUSERNAME);
      data.put(alias + CONFIG_REQPASSWORD, DEFAULT_REQPASSWORD);
      data.put(
          alias + CONFIG_ALLOWUPDATEWITHSAMEKEY,
          DEFAULT_ALLOWUPDATEWITHSAMEKEY);
    }
  }

  /** @param oalias Alias
 * @return all the key with an alias */
  public static Set<String> getAllAliasKeys(final String oalias) {
    String alias = oalias + ".";
    Set<String> keys = new LinkedHashSet<>();
    keys.add(alias + CONFIG_DEFAULTCA);
    keys.add(alias + CONFIG_CERTPROFILE);
    keys.add(alias + CONFIG_EEPROFILE);
    keys.add(alias + CONFIG_REQCERT);
    keys.add(alias + CONFIG_REQUSERNAME);
    keys.add(alias + CONFIG_REQPASSWORD);
    keys.add(alias + CONFIG_ALLOWUPDATEWITHSAMEKEY);
    return keys;
  }

  /**
   * @param alias the EST alias to get value from
   * @return CA ID in String format, String format to be backwards compatible
   *     with EJBCA 6.11 when it was stored as CA Name instead of ID
   */
  public String getDefaultCAID(final String alias) {
    String key = alias + "." + CONFIG_DEFAULTCA;
    return getValue(key, alias);
  }

  /**
   * @param alias ALias
   * @param defaultCAID CA
   */
  public void setDefaultCAID(final String alias, final int defaultCAID) {
    String key = alias + "." + CONFIG_DEFAULTCA;
    setValue(key, String.valueOf(defaultCAID), alias);
  }

  /**
   * @param alias the EST alias to get value from
   * @return Certificate Profile ID in String format, String format to be
   *     backwards compatible with EJBCA 6.11 when it was stored as CP Name
   *     instead of ID
   */
  public String getCertProfileID(final String alias) {
    String key = alias + "." + CONFIG_CERTPROFILE;
    return getValue(key, alias);
  }
  /**
   * @param alias the EST alias to edit
   * @param cprofileID Certificate Profile ID
   */
  public void setCertProfileID(final String alias, final int cprofileID) {
    String key = alias + "." + CONFIG_CERTPROFILE;
    setValue(key, String.valueOf(cprofileID), alias);
  }

  /**
   * @param alias Alias
   * @return ID
   */
  public int getEndEntityProfileID(final String alias) {
    String key = alias + "." + CONFIG_EEPROFILE;
    try {
      Integer id = Integer.valueOf(getValue(key, alias));
      return id;
    } catch (NumberFormatException e) {
      LOG.error(
          "Invalid End Entity Profile ID stored in EST alias, returning 0: "
              + alias,
          e);
      return 0;
    }
  }
  /**
   * @param alias the EST alias to edit
   * @param eeprofileID End Entity Profile ID
   */
  public void setEndEntityProfileID(final String alias, final int eeprofileID) {
    String key = alias + "." + CONFIG_EEPROFILE;
    setValue(key, String.valueOf(eeprofileID), alias);
  }

  /**
   * @param alias the alias to check for
   * @return true if we require a certificate for authentication
   */
  public boolean getCert(final String alias) {
    String key = alias + "." + CONFIG_REQCERT;
    return StringUtils.equalsIgnoreCase(getValue(key, alias), "true");
  }

  /**
   * @param alias ALias
   * @param reqCert Cert
   */
  public void setCert(final String alias, final boolean reqCert) {
    String key = alias + "." + CONFIG_REQCERT;
    setValue(key, Boolean.toString(reqCert), alias);
  }

  /**
   * @param alias the alias to check for
   * @return username if any, or null if none
   */
  public String getUsername(final String alias) {
    String key = alias + "." + CONFIG_REQUSERNAME;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param username User
   */
  public void setUsername(final String alias, final String username) {
    String key = alias + "." + CONFIG_REQUSERNAME;
    setValue(key, username, alias);
  }

  /**
   * @param alias the alias to check for
   * @return password if any, or null if none
   */
  public String getPassword(final String alias) {
    String key = alias + "." + CONFIG_REQPASSWORD;
    return getValue(key, alias);
  }

  /**
   * @param alias Alias
   * @param password PWD
   */
  public void setPassword(final String alias, final String password) {
    String key = alias + "." + CONFIG_REQPASSWORD;
    setValue(key, password, alias);
  }

  /**
   * @param alias the alias to check for
   * @return true if allowed to reenroll with the same key
   */
  public boolean getKurAllowSameKey(final String alias) {
    String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
    String value = getValue(key, alias);
    return StringUtils.equalsIgnoreCase(value, "true");
  }

  /**
   * @param alias Alias
   * @param allowSameKey Bool
   */
  public void setKurAllowSameKey(
      final String alias, final boolean allowSameKey) {
    String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
    setValue(key, Boolean.toString(allowSameKey), alias);
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
            "Could not find key '" + key + "' in the EST configuration data");
      }
    } else {
      LOG.info("EST alias '" + alias + "' does not exist");
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
              "Added '"
                  + key
                  + "="
                  + value
                  + "' to the EST configuration data");
        }
      } else {
        data.put(key, value);
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Key '"
                  + key
                  + "' does not exist in the EST configuration data, adding"
                  + " it");
        }
      }
    } else {
      LOG.info("EST alias '" + alias + "' does not exist");
    }
  }

  /**
   * @param aliaslist Aliases
   */
  public void setAliasList(final Set<String> aliaslist) {
    data.put(ALIAS_LIST, aliaslist);
  }

  /**
   * @return Aliases
   */
  public Set<String> getAliasList() {
    @SuppressWarnings("unchecked")
    Set<String> ret = (Set<String>) data.get(ALIAS_LIST);

    return (ret == null ? DEFAULT_ALIAS_LIST : ret);
  }

  /**
   * @return List
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
   * @param alias Alias
   * @return Bool
   */
  public boolean aliasExists(final String alias) {
    if (StringUtils.isNotEmpty(alias)) {
      Set<String> aliases = getAliasList();
      return aliases.contains(alias);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("EST alias '" + alias + "' does not exist.");
    }
    return false;
  }

  /**
   * @param alias Alias
   */
  public void addAlias(final String alias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Adding EST alias: " + alias);
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
        LOG.debug("EST alias '" + alias + "' already exists.");
      }
      return;
    }
    initialize(alias);
    aliases.add(alias);
    data.put(ALIAS_LIST, aliases);
  }

  /**
   * @param alias Alias
   */
  public void removeAlias(final String alias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Removing EST alias: " + alias);
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
        LOG.debug("EST alias '" + alias + "' does not exist");
      }
      return;
    }

    for (String key : getAllAliasKeys(alias)) {
      data.remove(key);
    }
    aliases.remove(alias);
    data.put(ALIAS_LIST, aliases);
  }

  /**
   * @param oldAlias Old
   * @param newAlias New
   */
  public void renameAlias(final String oldAlias, final String newAlias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Renaming EST alias '" + oldAlias + "' to '" + newAlias + "'");
    }

    if (StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
      LOG.info(
          "No alias is renamed because one or both aliases were not provided.");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(oldAlias)) {
      LOG.info("Cannot rename. EST alias '" + oldAlias + "' does not exists.");
      return;
    }

    if (aliases.contains(newAlias)) {
      LOG.info("Cannot rename. EST alias '" + newAlias + "' already exists.");
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

  /**
   * @param originAlias Old
   * @param cloneAlias New
   */
  public void cloneAlias(final String originAlias, final String cloneAlias) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Cloning EST alias '" + originAlias + "' to '" + cloneAlias + "'");
    }

    if (StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
      LOG.info(
          "No alias is cloned because one or both aliased were not provided");
      return;
    }

    Set<String> aliases = getAliasList();
    if (!aliases.contains(originAlias)) {
      LOG.info("Cannot clone. EST alias '" + originAlias + "' does not exist.");
      return;
    }

    if (aliases.contains(cloneAlias)) {
      LOG.info("Cannot clone. EST alias '" + cloneAlias + "' already exists.");
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

  /** Implementation of UpgradableDataHashMap function getLatestVersion. */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  @Override
  public String getConfigurationId() {
    return EST_CONFIGURATION_ID;
  }
}
