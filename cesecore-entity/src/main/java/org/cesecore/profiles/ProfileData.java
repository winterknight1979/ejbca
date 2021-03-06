/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.profiles;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;

/**
 * Implementation of the "ProfileData" table in the database.
 *
 * @version $Id: ProfileData.java 34163 2020-01-02 15:00:17Z samuellb $
 */
@Entity
@Table(name = "ProfileData")
public class ProfileData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG = Logger.getLogger(ProfileData.class);

  /** param. */
  private int id;
  /** param. */
  private String profileName;
  /** param. */
  private String profileType;
  /** param. */
  private String rawData;
  /** param. */
  private int rowVersion = 0;
  /** param. */
  private String rowProtection;

  /** Null constructor. */
  public ProfileData() { }

  /**
   * Entity holding data of an approval profile.
   *
   * @param anid ID
   * @param profile profile
   */
  public ProfileData(final int anid, final Profile profile) {
    setId(anid);
    profile.setProfileId(
        anid); // ID in the data map should be same as in database column
    setProfileName(profile.getProfileName());
    setProfileType(profile.getProfileType());
    setDataMap(profile.getDataMap());
  }

  /**
   * Loads the values of the submitted profile implementation into this entity
   * object.
   *
   * @param profile a profile
   */
  @Transient
  public void setProfile(final Profile profile) {
    setProfileName(profile.getProfileName());
    setProfileType(profile.getProfileType());
    setDataMap(profile.getDataMap());
  }

  /**
   * @return ID
   */
  public int getId() {
    return id;
  }

  /**
   * @param anId ID
   */
  public void setId(final int anId) {
    this.id = anId;
  }

  /**
   * @return name
   */
  public String getProfileName() {
    return profileName;
  }

  /**
   * @param aProfileName name
   */
  public void setProfileName(final String aProfileName) {
    this.profileName = aProfileName;
  }

  /**
   * @return type
   */
  public String getProfileType() {
    return profileType;
  }

  /**
   * @param aProfileType type
   */
  public void setProfileType(final String aProfileType) {
    this.profileType = aProfileType;
  }

  /**
   * Should not be invoked directly. Use getDataMap() instead.
   *
   * @return data
   */
  public String getRawData() {
    return rawData;
  }
  /**
   * Should not be invoked directly. Use setDataMap(..) instead.
   *
   * @param theRawData data
   */
  public void setRawData(final String theRawData) {
    this.rawData = theRawData;
  }

  /**
   * @return map
   */
  @Transient
  @SuppressWarnings("unchecked")
  public LinkedHashMap<Object, Object> getDataMap() {
    try (SecureXMLDecoder decoder =
        new SecureXMLDecoder(
            new ByteArrayInputStream(
                getRawData().getBytes(StandardCharsets.UTF_8)))) {
      final Map<?, ?> h = (Map<?, ?>) decoder.readObject();
      // Handle Base64 encoded string values
      final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
      return dataMap;
    } catch (IOException e) {
      final String msg =
          "Failed to parse data map for "
              + profileType
              + " '"
              + profileName
              + "': "
              + e.getMessage();
      if (LOG.isDebugEnabled()) {
        LOG.debug(msg + ". Data:\n" + getRawData());
      }
      throw new IllegalStateException(msg, e);
    }
  }

  /**
   * @param dataMap map
   */
  @Transient
  @SuppressWarnings({"rawtypes", "unchecked"})
  public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
    try {
      // We must base64 encode string for UTF safety
      final LinkedHashMap<?, ?> a = new Base64PutHashMap();
      a.putAll((LinkedHashMap) dataMap);
      final ByteArrayOutputStream baos = new ByteArrayOutputStream();
      final XMLEncoder encoder = new XMLEncoder(baos);
      encoder.writeObject(a);
      encoder.close();
      final String data = baos.toString("UTF8");
      setRawData(data);
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  //
  // Start Database integrity protection methods
  //
  @Transient
  @Override
  public String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build.append(getId()).append(getProfileName()).append(getDataMap());
    return build.toString();
  }

  /**
   * @return version
   */
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 1;
  }

  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  @Override
  @Transient
  protected String getRowId() {
    return String.valueOf(getId());
  }

  /** @return the value object representation of this database row */
  @SuppressWarnings("unchecked")
  @Transient
  public Profile getProfile() {
    LinkedHashMap<Object, Object> datamap =
        (LinkedHashMap<Object, Object>) getDataMap();
    Class<? extends Profile> implementationClass =
        (Class<? extends Profile>) datamap.get(Profile.PROFILE_TYPE);
    if (implementationClass == null) {
      throw new IllegalStateException(
          "No implementation class available for profile '"
              + profileName
              + "'");
    }
    Profile returnValue;
    try {
      returnValue = implementationClass.getConstructor().newInstance();
    } catch (InstantiationException
        | IllegalAccessException
        | NoSuchMethodException
        | InvocationTargetException e) {
      throw new IllegalStateException(
          "Could not instansiate class of type "
              + implementationClass.getCanonicalName()
              + " for profile '"
              + profileName
              + "'",
          e);
    }
    returnValue.setProfileName(profileName);
    returnValue.setProfileId(id);
    returnValue.setDataMap(datamap);
    return returnValue;
  }
}
