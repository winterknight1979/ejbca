/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;

/**
 * Holder class for preserving the data remaining from the old community VA
 * Publisher.
 *
 * @version $Id: LegacyValidationAuthorityPublisher.java 34192 2020-01-07
 *     15:10:21Z aminkh $
 */
public class LegacyValidationAuthorityPublisher extends CustomPublisherUiBase
    implements CustomPublisherUiSupport {
    /** Config. */
  public static final String OLD_VA_PUBLISHER_QUALIFIED_NAME =
      "org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher";

  private static final long serialVersionUID = 9013538677462519302L;

  /** Config. */
  private static final String DATASOURCE = "dataSource";
  /** Config. */
  private static final String PROTECT = "protect";
  /** Config. */
  private static final String STORECERT = "storeCert";
  /** Config. */
  private static final String STORECRL = "storeCRL";
  /** Config. */
  private static final String ONLYPUBLISHREVOKED = "onlyPublishRevoked";
  /** Config. */
  private static final String DEFAULT_DATASOURCE = "java:/OcspDS";

  /** constructor. */
  public LegacyValidationAuthorityPublisher() {
    super();
    setClassPath(this.getClass().getName());
  }

  /**
   * A copy constructor, in order to create a {@link
   * LegacyValidationAuthorityPublisher} from the data payload from another
   * publisher.
   *
   * @param newData a map containing publisher data.
   */
  public LegacyValidationAuthorityPublisher(final Map<Object, Object> newData) {
    super();
    this.data = new LinkedHashMap<Object, Object>(newData);
    setClassPath(this.getClass().getName());
    this.data.put(
        TYPE, Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER));
  }

  @Override
  public void init(final Properties properties) {
    // Set all existing props
    for (Object key : properties.keySet()) {
      this.data.put(key, properties.get(key));
    }
    // Overwrite these props whatever the case may be:
    setClassPath(this.getClass().getName());
    this.data.put(
        TYPE, Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER));
    // Then set defaults if any were missing.
    if (StringUtils.isEmpty(properties.getProperty(DATASOURCE))) {
      try {
        setDataSource(DEFAULT_DATASOURCE);
      } catch (PublisherException e) {
        throw new IllegalStateException();
      }
    }
    if (StringUtils.isEmpty(properties.getProperty(PROTECT))) {
      setProtect(false);
    }
    if (StringUtils.isEmpty(properties.getProperty(STORECERT))) {
      setStoreCert(true);
    }
    if (StringUtils.isEmpty(properties.getProperty(ONLYPUBLISHREVOKED))) {
      setOnlyPublishRevoked(false);
    }
    addProperty(
        new CustomPublisherProperty(
            DESCRIPTION,
            CustomPublisherProperty.UI_TEXTINPUT,
            getDescription()));
    addProperty(
        new CustomPublisherProperty(
            DATASOURCE, CustomPublisherProperty.UI_TEXTINPUT, getDataSource()));
    addProperty(
        new CustomPublisherProperty(
            STORECERT,
            CustomPublisherProperty.UI_BOOLEAN,
            Boolean.toString(getStoreCert())));
    addProperty(
        new CustomPublisherProperty(
            ONLYPUBLISHREVOKED,
            CustomPublisherProperty.UI_BOOLEAN,
            Boolean.toString(getOnlyPublishRevoked())));
    addProperty(
        new CustomPublisherProperty(
            STORECRL,
            CustomPublisherProperty.UI_BOOLEAN,
            Boolean.toString(getStoreCRL())));
  }

  /** @return The value of the property data source */
  public String getDataSource() {
    return (String) this.data.get(DATASOURCE);
  }

  /**
   * Sets the data source property for the publisher.
   *
   * @param dataSource Source
   * @throws PublisherException Fail
   */
  public void setDataSource(final String dataSource) throws PublisherException {
    validateDataSource(dataSource);
    this.data.put(DATASOURCE, dataSource);
  }

  /** @return The value of the property protect */
  public boolean getProtect() {
    return ((Boolean) this.data.get(PROTECT)).booleanValue();
  }

  /** @param protect Sets the property protect for the publisher. */
  public void setProtect(final boolean protect) {
    this.data.put(PROTECT, Boolean.valueOf(protect));
  }

  /**
   * @param storecert Set to false if the certificate should not be published.
   */
  public void setStoreCert(final boolean storecert) {
    this.data.put(STORECERT, Boolean.valueOf(storecert));
  }

  /** @return Should the certificate be published */
  public boolean getStoreCert() {
    final Object o = this.data.get(STORECERT);
    if (o == null) {
      return true; // default value is true
    }
    if (o instanceof String) {
      return Boolean.valueOf((String) o);
    }
    return ((Boolean) o).booleanValue();
  }

  /** @return Should the CRL be published. */
  public boolean getStoreCRL() {
    final Object o = this.data.get(STORECRL);
    if (o == null) {
      return false; // default value is false
    }
    if (o instanceof String) {
      return Boolean.valueOf((String) o);
    }
    return ((Boolean) o).booleanValue();
  }

  /** @param storecert Set to true if the CRL should be published. */
  public void setStoreCRL(final boolean storecert) {
    this.data.put(STORECRL, Boolean.valueOf(storecert));
  }

  /** @return Should only revoked certificates be published? */
  public boolean getOnlyPublishRevoked() {
    final Object o = this.data.get(ONLYPUBLISHREVOKED);
    if (o == null) {
      return false; // default value is false
    }
    if (o instanceof String) {
      return Boolean.valueOf((String) o);
    }
    return ((Boolean) o).booleanValue();
  }

  /**
   * @param publishRevoked Set to true if only revoked certificates should be
   *     published.
   */
  public void setOnlyPublishRevoked(final boolean publishRevoked) {
    this.data.put(ONLYPUBLISHREVOKED, Boolean.valueOf(publishRevoked));
  }

  @Override
  public boolean isReadOnly() {
    return true;
  }

  @Override
  public void validateDataSource(final String dataSource)
      throws PublisherException {
    super.validateDataSource(dataSource);
  }
}
