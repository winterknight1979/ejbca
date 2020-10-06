/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.certextensions;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;

/**
 * This file handles configuration of available Custom Certificate Extensions.
 *
 * @version $Id: AvailableCustomCertificateExtensionsConfiguration.java 30583
 *     2018-11-22 17:32:11Z samuellb $
 */
public class AvailableCustomCertificateExtensionsConfiguration
    extends ConfigurationBase implements Serializable {

  private static final long serialVersionUID = 7798273820046510706L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AvailableCustomCertificateExtensionsConfiguration.class);

  /** ID. */
  public static final String CONFIGURATION_ID =
      "AVAILABLE_CUSTOM_CERT_EXTENSIONS";

  /** Constructor. */
  public AvailableCustomCertificateExtensionsConfiguration() {
    super();
    if (!isConfigurationInitialized()) {
      addAvailableCustomCertExtensionsFromFile();
    }
  }

  /**
   * @param dataobj Object
   */
  public AvailableCustomCertificateExtensionsConfiguration(
      final Serializable dataobj) {
    @SuppressWarnings("unchecked")
    LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
    data = d;
  }

  @Override
  public String getConfigurationId() {
    return CONFIGURATION_ID;
  }

  /**
   * @return true if there is at least one supported Custom Certificate
   *     Extension. False otherwize
   */
  public boolean isConfigurationInitialized() {
    return data.size() > 1;
  }

  /** @param id ID
   * @return boolean */
  public boolean isCustomCertExtensionSupported(final int id) {
    return data.containsKey(id);
  }

  /** @param id ID
 * @return  CE*/
  public CustomCertificateExtension getCustomCertificateExtension(
          final int id) {
    return (CustomCertificateExtension) data.get(id);
  }

  /** @param ce Extension  */
  public void addCustomCertExtension(final CertificateExtension ce) {
    data.put(ce.getId(), ce);
  }

  /**
   * @param id ID
   * @param oid OID
   * @param displayName Name
   * @param classPath Classpath
   * @param critical true if Critical
   * @param required reue if required
   * @param properties Properties
   * @throws CertificateExtentionConfigurationException on error
   */
  public void addCustomCertExtension(
      final int id,
      final String oid,
      final String displayName,
      final String classPath,
      final boolean critical,
      final boolean required,
      final Properties properties)
      throws CertificateExtentionConfigurationException {
    try {
      Class<?> implClass = Class.forName(classPath);
      CertificateExtension certificateExtension =
          (CertificateExtension) implClass.getConstructor().newInstance();
      certificateExtension.init(
          id, oid.trim(), displayName, critical, required, properties);
      data.put(id, certificateExtension);
    } catch (ClassNotFoundException e) {
      throw new CertificateExtentionConfigurationException(
          "Cannot add custom certificate extension. "
              + e.getLocalizedMessage());
    } catch (InstantiationException e) {
      throw new CertificateExtentionConfigurationException(
          "Cannot add custom certificate extension. "
              + e.getLocalizedMessage());
    } catch (IllegalAccessException e) {
      throw new CertificateExtentionConfigurationException(
          "Cannot add custom certificate extension. "
              + e.getLocalizedMessage());
    } catch (InvocationTargetException e) {
      throw new CertificateExtentionConfigurationException(
          "Cannot add custom certificate extension. "
              + e.getLocalizedMessage());
    } catch (NoSuchMethodException e) {
      throw new CertificateExtentionConfigurationException(
          "Cannot add custom certificate extension. "
              + e.getLocalizedMessage());
    }
  }

  /**
   * @param id ID
   */
  public void removeCustomCertExtension(final int id) {
    data.remove(id);
  }
  /**
   * @return extensions
   */
  public List<CertificateExtension>
      getAllAvailableCustomCertificateExtensions() {
    List<CertificateExtension> ret = new ArrayList<CertificateExtension>();
    for (Entry<Object, Object> entry : data.entrySet()) {
      Object value = entry.getValue();
      if (value instanceof CertificateExtension) {
        CertificateExtension ext = (CertificateExtension) value;
        ret.add(ext);
      }
    }
    return ret;
  }

  /**
   * Returns a list of the available CertificateExtensions as Properties. Each
   * property contains the extension OID as its 'key' and the extension's label
   * as its 'value'
   *
   * @return Properties
   */
  public Properties getAsProperties() {
    Properties properties = new Properties();
    for (Entry<Object, Object> entry : data.entrySet()) {
      if (entry.getValue() instanceof CertificateExtension) {
        CertificateExtension ce = (CertificateExtension) entry.getValue();
        properties.setProperty(
            Integer.toString(ce.getId()), ce.getDisplayName());
      }
    }
    return properties;
  }

  /**
   * Returns a new AvailableCustomCertificateExtensionsConfiguration
   * object containing only extensions from the properties
   * file certextensions.properties
   *
   * This method is called only when upgrading CertificateProfile to
   *  EJBCA 6.4.0 where the CustomCertExtensions are
   * redefined to be referenced by their OIDs instead of IDs.
   *
   * TODO Remove this method when support for EJBCA 6.4.0 is dropped.
 * @return congig
   */
  @Deprecated
  public static AvailableCustomCertificateExtensionsConfiguration
      getAvailableCustomCertExtensionsFromFile() {
    return new AvailableCustomCertificateExtensionsConfiguration();
  }

  /**
   * Imports CustomCertExtensions from certextensions.properties
   * into the database.
   *
   * TODO Remove this method when support for EJBCA 6.4.0 is dropped.
   */
  @Deprecated
  private void addAvailableCustomCertExtensionsFromFile() {
    // If the file has already been removed, no need to go further
    InputStream is =
        CertificateExtensionFactory.class.getResourceAsStream(
            "/certextensions.properties");
    if (is == null) {
      return;
    }

    try {
      Properties props = new Properties();
      try {
        props.load(is);
      } finally {
        is.close();
      }

      int count = 0;
      for (int i = 1; i < 255; i++) {
        if (props.get("id" + i + ".oid") != null) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("found " + props.get("id" + i + ".oid"));
          }
          CertificateExtension ce = getCertificateExtensionFromFile(i, props);
          addCustomCertExtension(ce);
          count++;
        }
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Nr of read Custom Certificate Extensions from file: " + count);
      }
    } catch (IOException e) {
      LOG.error("Error parsing the 'certextensions.properties' file.", e);
    } catch (CertificateExtentionConfigurationException e) {
      LOG.error(e.getMessage(), e);
    }
  }

  /**
   * Used for upgrading from old certextensions.properties files.
   * Package-internal to allow for testing.
   *
   * @param id ID
   * @param propertiesInFile Properties
   * @return Certificate extension
   * @throws CertificateExtentionConfigurationException on fail
   */
  static CertificateExtension getCertificateExtensionFromFile(
      final int id, final Properties propertiesInFile)
      throws CertificateExtentionConfigurationException {
    String propertyId = "id";
    String propertyOid = ".oid";
    String propertyClassPath = ".classpath";
    String propertyDisplayName = ".displayname";
    String propertyUsed = ".used";
    String propertyTranslatable = ".translatable";
    String propertyCritical = ".critical";

    try {
      String oid =
          StringUtils.trim(
              propertiesInFile.getProperty(propertyId + id + propertyOid));
      String classPath =
          StringUtils.trim(
              propertiesInFile.getProperty(
                  propertyId + id + propertyClassPath));
      String displayName =
          StringUtils.trim(
              propertiesInFile.getProperty(
                  propertyId + id + propertyDisplayName));
      LOG.debug(
          propertyId
              + id
              + propertyUsed
              + ":"
              + propertiesInFile.getProperty(propertyId + id + propertyUsed));
      boolean used =
          propertiesInFile
              .getProperty(propertyId + id + propertyUsed)
              .trim()
              .equalsIgnoreCase("TRUE");
      boolean translatable =
          propertiesInFile
              .getProperty(propertyId + id + propertyTranslatable)
              .trim()
              .equalsIgnoreCase("TRUE");
      boolean critical =
          propertiesInFile
              .getProperty(propertyId + id + propertyCritical)
              .trim()
              .equalsIgnoreCase("TRUE");
      LOG.debug(
          id
              + ", "
              + used
              + ", "
              + oid
              + ", "
              + critical
              + ", "
              + translatable
              + ", "
              + displayName);
      if (used) {
        if (oid != null && classPath != null && displayName != null) {
          Class<?> implClass = Class.forName(classPath);
          CertificateExtension certificateExtension =
              (CertificateExtension) implClass.getConstructor().newInstance();
          Properties extensionProperties =
              getExtensionProperties(id, propertiesInFile);
          if (translatable) {
            extensionProperties.put("translatable", true);
          }
          certificateExtension.init(
              id,
              oid.trim(),
              displayName,
              critical,
              /*required=*/ true,
              extensionProperties);
          return certificateExtension;

        } else {
          throw new CertificateExtentionConfigurationException(
              "Certificate Extension "
                  + Integer.valueOf(id)
                  + " seems to be misconfigured in the"
                  + " certextensions.properties");
        }
      }

    } catch (Exception e) {
      throw new CertificateExtentionConfigurationException(
          "Certificate Extension "
              + Integer.valueOf(id)
              + " seems to be misconfigured in the certextensions.properties",
          e);
    }
    return null;
  }

  private static Properties getExtensionProperties(
      final int id, final Properties propertiesInFile) {
    Properties extProps = new Properties();
    Iterator<Object> keyIter = propertiesInFile.keySet().iterator();
    String matchString = "id" + id + ".property.";
    while (keyIter.hasNext()) {
      String nextKey = (String) keyIter.next();
      if (nextKey.startsWith(matchString)) {
        if (nextKey.length() > matchString.length()) {
          extProps.put(
              nextKey.substring(matchString.length()),
              propertiesInFile.get(nextKey));
        }
      }
    }
    return extProps;
  }

  @Override
  public void upgrade() { }
}
