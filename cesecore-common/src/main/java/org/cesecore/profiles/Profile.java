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
package org.cesecore.profiles;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Base interface for all Profile objects.
 *
 * @version $Id: Profile.java 26117 2017-07-03 13:56:15Z mikekushner $
 */
public interface Profile extends Serializable {

  /**
   * Designator for the base type, in this case a Class which extends
   * ProfileBase.
   */
  String PROFILE_TYPE = "profile.type";

  /** @return the name of this particular profile type instance */
  String getProfileName();

  /**
   * @param profileName Name
   */
  void setProfileName(String profileName);

  /**
   * @return the database ID value of this profile. May be null if the profile
   *     has not yet been persisted.
   */
  Integer getProfileId();

  /**
   * @param profileId ID
   */
  void setProfileId(Integer profileId);

  /**
   * @return a string identifier for identifying this profile type in the
   *     database
   */
  String getProfileType();

  /**
   * @return the complete data map for this implementation, primarily used to
   *     persist it.
   */
  LinkedHashMap<Object, Object> getDataMap();

  /**
   * @param dataMap Data
   */
  void setDataMap(LinkedHashMap<Object, Object> dataMap);

  /** @return the implementing class */
  Class<? extends Profile> getType();

  /**
   * This method only needs to be called by the factory method (and some unit
   * tests), because it sets a ton of boilerplate stuff which isn't required by
   * already initialized profiles.
   */
  void initialize();

  /**
   * Create a Map with the differences between the current object and the
   * parameter object. Puts the result in a new Map with keys:
   *
   * <pre>
   * changed:key, changedvalue
   * remove:key, removedvalue
   * added:key, addedvalue
   * </pre>
   *
   * @param newobj The "changed" object for which we want to get the changes
   *     compared to this object
   * @return Map object with difference as described above
   */
  Map<Object, Object> diff(Profile newobj);
}
