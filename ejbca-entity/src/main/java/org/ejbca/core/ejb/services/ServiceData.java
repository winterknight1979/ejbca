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

package org.ejbca.core.ejb.services;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * Representation of a service configuration used by the monitoring services
 * framework.
 *
 * @version $Id: ServiceData.java 34163 2020-01-02 15:00:17Z samuellb $
 */
@Entity
@Table(name = "ServiceData")
public class ServiceData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(ServiceData.class);

  /** Param. */
  private int id;
  /** Param. */
  private String name;
  /** Param. */
  private long runTimeStamp;
  /** Param. */
  private long nextRunTimeStamp;
  /** Param. */
  private String data;
  /** Param. */
  private int rowVersion = 0;
  /** Param. */
  private String rowProtection;

  /**
   * Entity Bean holding data of a service configuration.
   *
   * @param iand ID
   * @param aname Name
   * @param serviceConfiguration Config
   */
  public ServiceData(
      final int iand,
      final String aname,
      final ServiceConfiguration serviceConfiguration) {
    setId(iand);
    setName(aname);
    setNextRunTimeStamp(0); // defaults to 0 until we activate the service
    setRunTimeStamp(0); // when created the service has never run yet
    if (serviceConfiguration != null) {
      setServiceConfiguration(serviceConfiguration);
    }
    LOG.debug("Created Service Configuration " + aname);
  }

  /** Empty. */
  public ServiceData() { }

  /**
   * Primary key.
   *
   * @return ID
   */
  // @Id @Column
  public int getId() {
    return id;
  }

  /**
   * @param anid ID
   */
  public void setId(final int anid) {
    this.id = anid;
  }

  /**
   * Name of the service.
   *
   * @return Name
   */
  // @Column
  public String getName() {
    return name;
  }

  /**
   * @param aname name
   */
  public void setName(final String aname) {
    this.name = aname;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime()).
   *
   * @return runTimeStamp the time the was running last time
   */
  // @Column
  public long getRunTimeStamp() {
    return runTimeStamp;
  }

  /**
   * @param arunTimeStamp time
   */
  public void setRunTimeStamp(final long arunTimeStamp) {
    this.runTimeStamp = arunTimeStamp;
  }

  /**
   * Date formated as seconds since 1970 (== Date.getTime()).
   *
   * @return nextRunTimeStamp the time the service will run next time
   */
  // @Column
  public long getNextRunTimeStamp() {
    return nextRunTimeStamp;
  }

  /**
   * @param anextRunTimeStamp time
   */
  public void setNextRunTimeStamp(final long anextRunTimeStamp) {
    this.nextRunTimeStamp = anextRunTimeStamp;
  }

  /**
   * Data saved concerning the service.
   *
   * @return Data
   */
  // @Column @Lob
  public String getData() {
    return data;
  }

  /**
   * @param thedata data
   */
  public void setData(final String thedata) {
    this.data = thedata;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String arowProtection) {
    this.rowProtection = arowProtection;
  }

  /**
   * Method that returns the service configuration data and updates it if
   * necessary.
   *
   * @return config
   */
  @Transient
  public ServiceConfiguration getServiceConfiguration() {
    final HashMap<?, ?> h;
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new ByteArrayInputStream(
                getData().getBytes(StandardCharsets.UTF_8)))) {
      h = (HashMap<?, ?>) decoder.readObject();
    } catch (IOException e) {
      final String msg =
          "Failed to parse ServiceData data map in database: " + e.getMessage();
      if (LOG.isDebugEnabled()) {
        LOG.debug(msg + ". Data:\n" + getData());
      }
      throw new IllegalStateException(msg, e);
    }
    // Handle Base64 encoded string values
    HashMap<?, ?> thedata = new Base64GetHashMap(h);
    float oldversion =
        ((Float) thedata.get(UpgradeableDataHashMap.VERSION)).floatValue();
    ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
    serviceConfiguration.loadData(thedata);
    if (Float.compare(oldversion, serviceConfiguration.getVersion()) != 0) {
      // Upgrade in version 4 of ServiceConfiguration. If we do not have
      // nextRunTimeStamp and runTimeStamp set in
      // the database, but we have them in serviceConfiguration, we will simply
      // copy the values over.
      // After this we will not use the values in ServiceConfiguration any more
      final String lnextRunTimeStamp = "NEXTRUNTIMESTAMP";
      final String oldRunTimeStamp = "OLDRUNTIMESTAMP";
      if ((getNextRunTimeStamp() == 0)
          && (thedata.get(lnextRunTimeStamp) != null)) {
        final long nextRunTs =
                ((Long) thedata.get(lnextRunTimeStamp)).longValue();
        LOG.debug("Upgrading nextRunTimeStamp to " + nextRunTs);
        setNextRunTimeStamp(nextRunTs);
      }
      if ((getRunTimeStamp() == 0) && (thedata.get(oldRunTimeStamp) != null)) {
        final long runTs = ((Long) thedata.get(oldRunTimeStamp)).longValue();
        LOG.debug("Upgrading runTimeStamp to " + runTs);
        setRunTimeStamp(runTs);
      }
      setServiceConfiguration(serviceConfiguration);
    }
    return serviceConfiguration;
  }

  /**
   * Method that saves the service configuration data to database.
   *
   * @param serviceConfiguration config
   */
  @SuppressWarnings("unchecked")
  public void setServiceConfiguration(
      final ServiceConfiguration serviceConfiguration) {
    // We must base64 encode string for UTF safety
    HashMap<Object, Object> a = new Base64PutHashMap();
    a.putAll((HashMap<Object, Object>) serviceConfiguration.saveData());
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    try (XMLEncoder encoder = new XMLEncoder(baos)) {
      encoder.writeObject(a);
    }
    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Service data: \n" + baos.toString("UTF8"));
      }
      setData(baos.toString("UTF8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getId()).append(getName()).append(getData());
    // runTimeStamp and nextRunTimeStamp are deliberately excluded from this so
    // that they can be updated
    // efficiently in method updateTimestamps below.
    // This causes a slight security risk of denial of service, since the
    // runtimestamp can be modified to manipulate
    // how services run. The EJB timer itself is not stored here though, and
    // with other monitoring that the system/CRLs etc
    // are working it should not be seen as a great security risk. No security
    // vital parts can be modified by altering these values.
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 1;
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
    return String.valueOf(getId());
  }

  //
  // End Database integrity protection methods
  //

  /**
   * @param entityManager EM
   * @param id ID
   * @param oldRunTimeStamp Time
   * @param oldNextRunTimeStamp Next time
   * @param newRunTimeStamp Time
   * @param newNextRunTimeStamp Next time
   * @return true if a service with the old timestamps existed
   *     (a.runTimeStamp=:oldRunTimeStamp AND
   *     a.nextRunTimeStamp=:oldNextRunTimeStamp) and was updated
   */
  public static boolean updateTimestamps(
      final EntityManager entityManager,
      final Integer id,
      final long oldRunTimeStamp,
      final long oldNextRunTimeStamp,
      final long newRunTimeStamp,
      final long newNextRunTimeStamp) {
    Query query =
        entityManager.createQuery(
            "UPDATE ServiceData a SET a.runTimeStamp=:newRunTimeStamp,"
                + " a.nextRunTimeStamp=:newNextRunTimeStamp WHERE a.id=:id AND"
                + " a.runTimeStamp=:oldRunTimeStamp AND"
                + " a.nextRunTimeStamp=:oldNextRunTimeStamp");
    query.setParameter("newRunTimeStamp", newRunTimeStamp);
    query.setParameter("newNextRunTimeStamp", newNextRunTimeStamp);
    query.setParameter("id", id);
    query.setParameter("oldRunTimeStamp", oldRunTimeStamp);
    query.setParameter("oldNextRunTimeStamp", oldNextRunTimeStamp);
    return query.executeUpdate() == 1;
  }
}
