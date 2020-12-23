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
package org.ejbca.ui.cli.batch;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Class used to manage the batch tool property file.
 *
 * @version $Id: BatchToolProperties.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class BatchToolProperties {

  private static final String PROPERTY_KEYSPEC = "keys.spec";
  private static final String PROPERTY_KEYALG = "keys.alg";

  Properties batchToolProperties = new Properties();
  private static final Logger log = Logger.getLogger(BatchToolProperties.class);

  private final Logger logger;

  public BatchToolProperties(final Logger logger) {
    this.logger = logger;
    load();
  }

  /**
   * Returns the configured keysize Default is 2048
   *
   * @return spec
   */
  public String getKeySpec() {
    return batchToolProperties.getProperty(PROPERTY_KEYSPEC, "2048");
  }

  /**
   * Returns the configured key algorithm Default is RSA, can be ECDSA
   *
   * @return Alg
   */
  public String getKeyAlg() {
    return batchToolProperties.getProperty(PROPERTY_KEYALG, "RSA");
  }

  private boolean tryLoadFile(final String filename) throws IOException {
    File file = new File(filename);
    if (file.exists()) {
      FileInputStream fis = new FileInputStream(file);
      batchToolProperties.load(fis);
      logger.info(
          InternalEjbcaResources.getInstance()
              .getLocalizedMessage("batch.loadingconfig", filename));
      return true;
    } else {
      return false;
    }
  }

  /**
   * Method that tries to read the property file 'batchtool.properties' in the
   * home directory then in the current directory and finally in the
   * conf/batchtool.properties.
   *
   * <p>It will also try the old location in bin/ and print a deprecation
   * warning if it exists there.
   */
  private void load() {
    try {
      if (!tryLoadFile(
              System.getProperty("user.home") + "/batchtool.properties")
          && !tryLoadFile("batchtool.properties")
          && !tryLoadFile("conf/batchtool.properties")) {
        // Not found
        if (tryLoadFile("bin/batchtool.properties")) {
          log.info(
              "The batchtool.properties file exists in bin/. It should be"
                  + " moved to conf/");
        } else {
          log.debug(
              "Could not find any batchtool property file, default values will"
                  + " be used.");
          logger.info(
              InternalEjbcaResources.getInstance()
                  .getLocalizedMessage("batch.loadingconfig", "defaults"));
        }
      }
    } catch (IOException e) {
      log.error("Error reading batchtool property file ");
      log.debug(e);
    }
  }
}
