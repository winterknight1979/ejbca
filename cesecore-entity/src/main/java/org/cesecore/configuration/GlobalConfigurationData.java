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

package org.cesecore.configuration;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Properties;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.config.RaStyleInfo.RaCssInfo;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.LookAheadObjectInputStream;

/**
 * Entity Bean for database persisted configurations.
 *
 * @version $Id: GlobalConfigurationData.java 34415 2020-01-30 12:29:30Z aminkh
 *     $
 */
@Entity
@Table(name = "GlobalConfigurationData")
public class GlobalConfigurationData extends ProtectedData
    implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(GlobalConfigurationData.class);
  /**Accepted classes. */
  private static final HashSet<Class<? extends Serializable>>
      ACCEPTED_SERIALIZATION_CLASSES_SET =
          new HashSet<>(
              Arrays.asList(
                  ArrayList.class,
                  Base64GetHashMap.class,
                  BasicCertificateExtension.class,
                  CertificateExtension.class,
                  CTLogInfo.class,
                  Enum.class,
                  GoogleCtPolicy.class,
                  HashMap.class,
                  HashSet.class,
                  Hashtable.class,
                  LinkedHashMap.class,
                  LinkedHashSet.class,
                  OcspKeyBinding.ResponderIdType.class,
                  Properties.class,
                  RaCssInfo.class,
                  RaStyleInfo.class));

  /** Unique ID defined by respective configuration object. */
  private String configurationId;

  /** Param. */
  private byte[] data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity holding data of admin's configuration. Create by sending in the id
   * and string representation of global configuration
   *
   * @param aConfigurationId the unique id of global configuration.
   * @param aConfiguration is the serialized string representation of the global
   *     configuration.
   */
  public GlobalConfigurationData(
      final String aConfigurationId, final ConfigurationBase aConfiguration) {
    setConfigurationId(aConfigurationId);
    setConfiguration(aConfiguration);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created configuration " + aConfigurationId);
    }
  }

  /** Null constructor. */
  public GlobalConfigurationData() { }

  /**
   * @return ID
   */
  // @Id @Column
  public String getConfigurationId() {
    return configurationId;
  }

  /**
   * @param aConfigurationId ID
   */
  public void setConfigurationId(final String aConfigurationId) {
    this.configurationId = aConfigurationId;
  }

  /**
   * @return data
   */
  // @Column @Lob
  // Gets the data on raw bytes from the database
  public byte[] getDataUnsafe() {
    return data;
  }
  /**
   * DO NOT USE! Stick with setData(HashMap data) instead.
   *
   * @param theData data
   */
  public void setDataUnsafe(final byte[] theData) {
    this.data = theData;
  }

  /**
   * Gets the serialized object that was stored, as a byte array, in the
   * database. Deserializes the byte array from the database.
   *
   * @return Object, typically a LinkedHashMap
   */
  @Transient
  public Serializable getObjectUnsafe() {
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(getDataUnsafe())); ) {
      laois.setEnabledMaxObjects(false);
      laois.setAcceptedClasses(ACCEPTED_SERIALIZATION_CLASSES_SET);
      laois.setEnabledSubclassing(true, "org.cesecore");
      return (Serializable) laois.readObject();
    } catch (IOException e) {
      LOG.error("Failed to load Global Configuration as byte[].", e);
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
    return null;
  }

  /**
   * @param theData Data
   */
  public void setObjectUnsafe(final Serializable theData) {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
         ObjectOutputStream oos = new ObjectOutputStream(baos); ) {
      oos.writeObject(theData);
      setDataUnsafe(baos.toByteArray());
    } catch (IOException e) {
      LOG.warn("Failed to save Global Configuration as byte[].", e);
    }
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  /**
   * @return data
   */
  @SuppressWarnings("rawtypes")
  @Transient
  public HashMap getData() {
    final Serializable map = getObjectUnsafe();
    if (map instanceof LinkedHashMap<?, ?>) {
      return (LinkedHashMap<?, ?>) map;
    } else {
      return new LinkedHashMap<>((Map<?, ?>) map);
    }
  }

  @SuppressWarnings("rawtypes")
  private void setData(final HashMap theData) {
    setObjectUnsafe(theData);
  }

  /**
   * Method that saves the global configuration to database.
   *
   * @param configuration config
   */
  @SuppressWarnings("rawtypes")
  public void setConfiguration(final ConfigurationBase configuration) {
    setData((HashMap) configuration.saveData());
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking so we will not include that in the
    // database protection
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    if (version >= 2) {
      // From v2 we use a SHA256 hash of the actually serialized data (raw
      // bytes) as stored in the database
      // This avoids any problems of the getData() object that does not have a
      // good, stable, toString() representation
      final String dataHash =
          CertTools.getSHA256FingerprintAsString(getDataUnsafe());
      build.append(getConfigurationId()).append(dataHash);
    } else {
      build.append(getConfigurationId()).append(getData());
    }
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 2;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return getConfigurationId();
  }

  //
  // End Database integrity protection methods
  //

}
