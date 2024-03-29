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
package org.ejbca.core.model;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.InternalResources;

/**
 * Class managing internal localization of texts such as notification messages
 * and log comments.
 *
 * <p>If fetched the resource files from the src/intresources directory and is
 * included in the file ejbca-properties.jar
 *
 * @version $Id: InternalEjbcaResources.java 26158 2017-07-18 05:46:19Z
 *     mikekushner $
 */
public class InternalEjbcaResources extends InternalResources {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(InternalEjbcaResources.class);

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = -1001L;

  /** Config. */
  public static final String PREFEREDINTERNALRESOURCES =
      CesecoreConfigurationHelper.getInternalResourcesPreferredLanguage();
  /** Config. */
  public static final String SECONDARYINTERNALRESOURCES =
      CesecoreConfigurationHelper.getInternalResourcesSecondaryLanguage();

  /** Config. */
  protected static InternalEjbcaResources instance = null;

  /** Config. */
  protected Properties primaryEjbcaResource = new Properties();
  /** Config. */
  protected Properties secondaryEjbcaResource = new Properties();

  /** Config. */
  private static final String RESOURCE_PATH = "/intresources";
  /** Config. */
  private static final String RESOURCE_NAME = "/ejbcaresources.";
  /** Config. */
  private static final String RESOURCE_LOCATION = RESOURCE_PATH + RESOURCE_NAME;

  /** Method used to setup the Internal Resource management. */
  protected InternalEjbcaResources() {
    super();
    setupResources(RESOURCE_LOCATION);
  }

  protected InternalEjbcaResources(final String resPath) {
    super(resPath);
    setupResources(resPath + RESOURCE_NAME);
  }

  private void setupResources(final String resLocation) {
    final String primaryLanguage =
        PREFEREDINTERNALRESOURCES.toLowerCase(Locale.ENGLISH);
    final String secondaryLanguage =
        SECONDARYINTERNALRESOURCES.toLowerCase(Locale.ENGLISH);
    // The test flag is defined when called from test code (junit)
    InputStream primaryStream = null;
    InputStream secondaryStream = null;
    try {
      // We first check for presence of the file in the classpath, if it does
      // not exist we also allow to have the
      // the file in the filesystem
      primaryStream =
          InternalEjbcaResources.class.getResourceAsStream(
              resLocation + primaryLanguage + ".properties");
      if (primaryStream == null) {
        try {
          primaryStream =
              new FileInputStream(
                  resLocation + primaryLanguage + ".properties");
        } catch (FileNotFoundException e) {
          LOG.error(
              "Localization files not found in InternalEjbcaResources: "
                  + e.getMessage());
        }
      }
      secondaryStream =
          InternalEjbcaResources.class.getResourceAsStream(
              resLocation + secondaryLanguage + ".properties");
      if (secondaryStream == null) {
        try {
          secondaryStream =
              new FileInputStream(
                  resLocation + secondaryLanguage + ".properties");
        } catch (FileNotFoundException e) {
          LOG.error(
              "Localization files not found in InternalEjbcaResources: "
                  + e.getMessage());
        }
      }

      try {
        if (primaryStream != null) {
          primaryEjbcaResource.load(primaryStream);
        } else {
          LOG.error("primaryResourse == null");
        }
        if (secondaryStream != null) {
          secondaryEjbcaResource.load(secondaryStream);
        } else {
          LOG.error("secondaryResource == null");
        }
      } catch (IOException e) {
        LOG.error("Error reading internal resourcefile", e);
      }
    } finally {
      try {
        if (primaryStream != null) {
          primaryStream.close();
        }
        if (secondaryStream != null) {
          secondaryStream.close();
        }
      } catch (IOException e) {
        LOG.error("Error closing internal resources language streams: ", e);
      }
    }
  }

  /** @return an instance of the InternalEjbcaResources. */
  public static synchronized InternalEjbcaResources getInstance() {
    if (instance == null) {
      instance = new InternalEjbcaResources();
    }
    return instance;
  }

  @Override
  public String getLocalizedMessage(final String key, final Object... params) {
    return getLocalizedMessageCs(key, params).toString();
  }

  @Override
  protected CharSequence getLocalizedMessageCs(
      final String key, final Object... params) {
    final StringBuilder sb = new StringBuilder();
    if (primaryEjbcaResource.containsKey(key)) {
      sb.append(primaryEjbcaResource.getProperty(key));
    } else if (secondaryEjbcaResource.containsKey(key)) {
      sb.append(secondaryEjbcaResource.getProperty(key));
    }
    return getLocalizedMessageInternal(sb, key, params);
  }
}
