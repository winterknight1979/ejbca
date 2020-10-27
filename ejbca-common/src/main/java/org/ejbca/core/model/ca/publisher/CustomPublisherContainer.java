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

package org.ejbca.core.model.ca.publisher;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.StringTools;

/**
 * CustomPublisherContainer is a class handling a custom publisher. It is used
 * to store and retrieve custom publisher configuration to database.
 *
 * @version $Id: CustomPublisherContainer.java 34192 2020-01-07 15:10:21Z aminkh
 *     $
 */
public class CustomPublisherContainer extends BasePublisher {
  private static final long serialVersionUID = -7060678968358301488L;

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CustomPublisherContainer.class);

  /** Publisher. */
  private ICustomPublisher custompublisher = null;

  /** Config. */
  public static final float LATEST_VERSION = 1;

  // Default Values

  /** Config. */
  public static final String CLASSPATH = "classpath";
  /** Config. */
  protected static final String PROPERTYDATA = "propertydata";

  /** Constructor. */
  public CustomPublisherContainer() {
    super();
    data.put(
        TYPE, Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER));
    setClassPath("");
    try {
      setPropertyData("");
    } catch (PublisherException e) {
      throw new IllegalStateException();
    }
  }

  /**
   * Copy constructor taking a BasePublisher returning a
   * CustomPublisherContainer based on its values.
   *
   * @param basePublisher publisher
   */
  public CustomPublisherContainer(final BasePublisher basePublisher) {
    super(basePublisher);
    data.put(
        TYPE, Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER));
    setClassPath("");
    try {
      setPropertyData("");
    } catch (PublisherException e) {
      throw new IllegalStateException();
    }
  }

  // Public Methods
  /**
   * Returns the class path of custom publisher used.
   *
   * @return path
   */
  public String getClassPath() {
    return (String) data.get(CLASSPATH);
  }

  /**
   * Sets the class path of custom publisher used.
   *
   * @param classpath Path
   */
  public void setClassPath(final String classpath) {
    data.put(CLASSPATH, classpath);
  }

  /**
   * Returns the propertydata used to configure this custom publisher.
   *
   * @return Data
   */
  public String getPropertyData() {
    return (String) data.get(PROPERTYDATA);
  }

  /**
   * Sets the propertydata used to configure this custom publisher.
   *
   * @param propertydata data
   * @throws PublisherException on fail
   */
  public void setPropertyData(final String propertydata)
      throws PublisherException {
    if (isCustomUiRenderingSupported()) {
      CustomPublisherUiSupport publisher =
          (CustomPublisherUiSupport) getCustomPublisher();
      // Check if any fields are passwords, and encrypt those
      Properties properties = new Properties();
      try {
        properties.load(new ByteArrayInputStream(propertydata.getBytes()));
      } catch (IOException e) {
        throw new IllegalArgumentException(
            "Properties could not be loaded.", e);
      }
      StringBuilder encryptedProperties = new StringBuilder();
      for (Object key : properties.keySet()) {
        String value;
        int propertyType = publisher.getPropertyType((String) key);
        if (propertyType == CustomPublisherProperty.UI_TEXTINPUT_PASSWORD) {
          // Property is of a type that shouldn't be written in clear text to
          // disk. Encrypt!
          try {
            value =
                StringTools.pbeEncryptStringWithSha256Aes192(
                    properties.getProperty((String) key));
          } catch (InvalidKeyException
              | InvalidAlgorithmParameterException
              | IllegalBlockSizeException
              | BadPaddingException
              | InvalidKeySpecException e) {
            throw new IllegalStateException(
                "Could not encrypt private key password!", e);
          }
        } else if ((propertyType == CustomPublisherProperty.UI_TEXTINPUT)
            && "dataSource".equals((String) key)) {
          value = properties.getProperty((String) key);
          validateDataSource(value);
        } else {
          value = properties.getProperty((String) key);
        }
        encryptedProperties.append(key + "=" + value + "\n");
      }
      data.put(PROPERTYDATA, encryptedProperties.toString());
    } else {
      data.put(PROPERTYDATA, propertydata);
    }
  }

  /**
   * @return bool.
   */
  public boolean isCustomAccessRulesSupported() {
    return getCustomPublisher() instanceof CustomPublisherAccessRulesSupport;
  }

  /**
   * @param authenticationToken token
   * @return bool
   */
  public boolean isAuthorizedToPublisher(
      final AuthenticationToken authenticationToken) {
    if (getCustomPublisher() instanceof CustomPublisherAccessRulesSupport) {
      return ((CustomPublisherAccessRulesSupport) getCustomPublisher())
          .isAuthorizedToPublisher(authenticationToken);
    }
    return true;
  }

  /**
   * @return bool
   */
  public boolean isCustomUiRenderingSupported() {
    return getCustomPublisher() instanceof CustomPublisherUiSupport;
  }

  /**
   * @param authenticationToken token
   * @return props
   */
  public List<CustomPublisherProperty> getCustomUiPropertyList(
      final AuthenticationToken authenticationToken) {
    if (getCustomPublisher() instanceof CustomPublisherUiSupport) {
      return ((CustomPublisherUiSupport) getCustomPublisher())
          .getCustomUiPropertyList(authenticationToken);
    }
    return new ArrayList<>();
  }

  /**
   * @return List
   */
  private List<String> getCustomUiPropertyNames() {
    if (getCustomPublisher() instanceof CustomPublisherUiSupport) {
      return ((CustomPublisherUiSupport) getCustomPublisher())
          .getCustomUiPropertyNames();
    }
    return new ArrayList<>();
  }

  /**
   * @return Props
   */
  public Properties getProperties() {
    final Properties properties = new Properties();
    final String propertyData = getPropertyData();
    // Re-Factor: Here the strings are escaped: \\ -> \; \n -> new line, etc.
    if (propertyData != null) {
      try {
        properties.load(new ByteArrayInputStream(propertyData.getBytes()));
      } catch (IOException e) {
        throw new IllegalStateException(
            "Could not retrieve properties from database", e);
      }
    }
    /*
     * The below code is only to be able to handle the change
     * of our EnterpriseValidationAuthorityPublisher from
     * built in to custom type.
     *
     * Since the built in type had its properties in XML
     *  we need to provide a one time upgrade path.
     * The old settings will still be present in the XML,
     *  but can be removed in a future version with a
     * deterministic upgrade gate version to ensure that
     * all installation data looks the same.
     *
     * Note that for example get/setDescription belongs to the
     * BasePublisher and not the ICustomPublisher instance.
     * TODO This is just one of many small things that needs to be
     * corrected in a major version rewrite.
     */
    for (final String key : getCustomUiPropertyNames()) {
      if (!properties.containsKey(key) && data.get(key) != null) {
        // If this is a publisher that used to have it's specific properties in
        // the "data", we need to provide an upgrade conversion path ONCE
        properties.setProperty(key, String.valueOf(data.get(key)));
      }
    }
    return properties;
  }

  @Override
  public boolean isFullEntityPublishingSupported() {
    return getCustomPublisher() instanceof FullEntityPublisher
        && ((FullEntityPublisher) getCustomPublisher())
            .isFullEntityPublishingSupported();
  }

  @Override
  public boolean storeCertificate(
      final AuthenticationToken authenticationToken,
      final CertificateData certificateData,
      final Base64CertData base64CertData)
      throws PublisherException {
    if (isFullEntityPublishingSupported()) {
      return ((FullEntityPublisher) this.getCustomPublisher())
          .storeCertificate(
              authenticationToken, certificateData, base64CertData);
    } else {
      return super.storeCertificate(
          authenticationToken, certificateData, base64CertData);
    }
  }

  /** @see org.ejbca.core.model.ca.publisher.BasePublisher */
  @Override
  public boolean storeCertificate(
      final AuthenticationToken admin,
      final Certificate incert,
      final String username,
      final String password,
      final String userDN,
      final String cafp,
      final int status,
      final int type,
      final long revocationDate,
      final int revocationReason,
      final String tag,
      final int certificateProfileId,
      final long lastUpdate,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    return this.getCustomPublisher()
        .storeCertificate(
            admin,
            incert,
            username,
            password,
            userDN,
            cafp,
            status,
            type,
            revocationDate,
            revocationReason,
            tag,
            certificateProfileId,
            lastUpdate,
            extendedinformation);
  }

  /**
   * @param admin admin
   * @param incrl crl
   * @param cafp CA
   * @param number SN
   * @param userDN DN
   * @return bool
   * @throws PublisherException fail
   * @see org.ejbca.core.model.ca.publisher.BasePublisher */
  public boolean storeCRL(
      final AuthenticationToken admin,
      final byte[] incrl,
      final String cafp,
      final int number,
      final String userDN)
      throws PublisherException {
    return this.getCustomPublisher()
        .storeCRL(admin, incrl, cafp, number, userDN);
  }

  /** @see org.ejbca.core.model.ca.publisher.BasePublisher */
  public void testConnection() throws PublisherConnectionException {
    this.getCustomPublisher().testConnection();
  }

  /**
   * The ICustomPublisher is the custom implementation used for the actual
   * publishing work.
   *
   * <p>Note that this class can only be queried about its specific settings
   * (and not common base settings like publisher description or queue
   * settings).
   *
   * @return the custom publisher wrapped by this class, null if none is
   *     defined.
   */
  public ICustomPublisher getCustomPublisher() {
    if (custompublisher == null) {
      final String classPath = getClassPath();
      if (classPath == null || classPath.isEmpty()) {
        return null;
      }
      try {
        @SuppressWarnings("unchecked")
        Class<? extends ICustomPublisher> implClass =
            (Class<? extends ICustomPublisher>) Class.forName(classPath);
        this.custompublisher = implClass.getConstructor().newInstance();
        this.custompublisher.init(getProperties());
      } catch (ClassNotFoundException e) {
        // Probably means that we have not built in our custom publisher here in
        // EJBCA, or it's an Enterprise only
        // publisher configured (Peer publisher for example)
        LOG.info(
            "Publisher class "
                + classPath
                + " is not available in this version/build of EJBCA.");
        return null;
      } catch (IllegalAccessException
          | InstantiationException
          | NoSuchMethodException
          | InvocationTargetException iae) {
        throw new IllegalStateException(iae);
      }
    }

    return custompublisher;
  }

  /**
   * @return clone
   * @throws CloneNotSupportedException fail
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone() */
  @SuppressWarnings({"rawtypes", "unchecked"})
  public Object clone() throws CloneNotSupportedException {
    CustomPublisherContainer clone = new CustomPublisherContainer();
    HashMap clonedata = (HashMap) clone.saveData();

    Iterator i = (data.keySet()).iterator();
    while (i.hasNext()) {
      Object key = i.next();
      clonedata.put(key, data.get(key));
    }

    clone.loadData(clonedata);
    return clone;
  }

  /**
   * @return version
   * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
   */
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /**
   * Resets the current custom publisher.
   *
   * @return data
   * @see org.cesecore.internal.UpgradeableDataHashMap#saveData()
   */
  public Object saveData() {
    this.custompublisher = null;
    return super.saveData();
  }

  @Override
  public boolean willPublishCertificate(
      final int status, final int revocationReason) {
    return getCustomPublisher()
        .willPublishCertificate(status, revocationReason);
  }

  @Override
  public void validateDataSource(final String dataSource)
      throws PublisherException {
    if (StringUtils.isNotBlank(dataSource)) {
      final Pattern dataSourcePattern = Pattern.compile("^(java):/.*$");
      final Matcher dataSrouceMatcher = dataSourcePattern.matcher(dataSource);
      if (dataSrouceMatcher.find()) {
        return;
      }
    }
    throw new PublisherException("Invalid data source!");
  }
}
