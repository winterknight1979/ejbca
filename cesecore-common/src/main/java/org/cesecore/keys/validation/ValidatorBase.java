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

package org.cesecore.keys.validation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.profiles.ProfileBase;

/**
 * BaseKeyValidator is a basic class that should be inherited by all types of
 * key validator in the system.
 *
 * @version $Id: ValidatorBase.java 28140 2018-01-30 12:40:30Z andresjakobs $
 */
public abstract class ValidatorBase extends ProfileBase
    implements Serializable, Cloneable, Validator {

  private static final long serialVersionUID = -335459158399850925L;

  /** Class logger. */
  private static final Logger LOG = Logger.getLogger(ValidatorBase.class);

  /** Resource. */
  protected static final InternalResources INTRES =
      InternalResources.getInstance();

  /** List of applicable issuance phases (see {@link IssuancePhase}). */
  protected static List<Integer> applicablePhases;

  /** List of applicable CA types (see {@link #getApplicableCaTypes()}. */
  protected static List<Integer> applicableCaTypes;
 /** API version. */
  public static final float LATEST_VERSION = 7F;
 /** Type. */
  public static final String TYPE = "type";
  /** Template. */
  public static final String SETTINGS_TEMPLATE = "settingsTemplate";
  /** Phase. */
  protected static final String PHASE = "phase";
  /** Desc. */
  protected static final String DESCRIPTION = "description";
  /** Date. */
  protected static final String NOT_BEFORE = "notBefore";
  /** Condition. */
  protected static final String NOT_BEFORE_CONDITION = "notBeforeCondition";
  /** Date. */
  protected static final String NOT_AFTER = "notAfter";
  /** Condition. */
  protected static final String NOT_AFTER_CONDITION = "notAfterCondition";
  /** IDs. */
  protected static final String ALL_CERTIFICATE_PROFILE_IDS =
      "allCertificateProfileIds";
  /** IDs. */
  protected static final String CERTIFICATE_PROFILE_IDS =
      "certificateProfileIds";
  /** failed. */
  protected static final String FAILED_ACTION = "failedAction";
  /** not applicable. */
  protected static final String NOT_APPLICABLE_ACTION = "notApplicableAction";

  static {
    applicablePhases = new ArrayList<Integer>();
    applicablePhases.add(IssuancePhase.DATA_VALIDATION.getIndex());
    applicablePhases.add(IssuancePhase.PRE_CERTIFICATE_VALIDATION.getIndex());
    applicablePhases.add(IssuancePhase.CERTIFICATE_VALIDATION.getIndex());

    applicableCaTypes = new ArrayList<Integer>();
    applicableCaTypes.add(CAInfo.CATYPE_X509);
    applicableCaTypes.add(CAInfo.CATYPE_CVC);
  }

  // Values used for lookup that are not stored in the data hash map.
  /** ID. */
  private int id;

  /** Public constructor needed for deserialization. */
  public ValidatorBase() {
    super();
    init();
  }

  /**
   * Creates a new instance.
   *
   * @param name name
   */
  public ValidatorBase(final String name) {
    super(name);
    init();
  }

  @Override
  public List<Integer> getApplicableCaTypes() {
    return applicableCaTypes;
  }

  @Override
  public String getProfileType() {
    return Validator.TYPE_NAME;
  }

  /** Initializes uninitialized data fields. */
  public void init() {
    super.initialize();
    if (null == data.get(VERSION)) {
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
    if (null == data.get(PHASE)) {
      setPhase(getApplicablePhases().get(0));
    }
    if (null == data.get(SETTINGS_TEMPLATE)) {
      setSettingsTemplate(
          KeyValidatorSettingsTemplate.USE_CERTIFICATE_PROFILE_SETTINGS
              .getOption());
    }
    if (null == data.get(DESCRIPTION)) {
      setDescription(StringUtils.EMPTY);
    }
    if (null == data.get(FAILED_ACTION)) {
      setFailedAction(
          KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex());
    }
    if (null == data.get(NOT_APPLICABLE_ACTION)) {
      setNotApplicableAction(
          KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex());
    }
    setIds();
  }

/**
 *
 */
private void setIds() {
    if (null == data.get(CERTIFICATE_PROFILE_IDS)) {
        setCertificateProfileIds(new ArrayList<Integer>());
      }
    // Added in v2
    if (null == data.get(ALL_CERTIFICATE_PROFILE_IDS)) {
      setAllCertificateProfileIds(true);
    }
}

  @Override
  public List<Integer> getApplicablePhases() {
    return applicablePhases;
  }

  @Override
  public int getPhase() {
    return ((Integer) data.get(PHASE)).intValue();
  }

  @Override
  public void setPhase(final int index) {
    data.put(PHASE, index);
  }

  @Override
  public void setKeyValidatorSettingsTemplate(
      final KeyValidatorSettingsTemplate template) {  // NOPMD: no-op
  }

  @Override
  public Integer getSettingsTemplate() {
    return (Integer) data.get(SETTINGS_TEMPLATE);
  }

  @Override
  public void setSettingsTemplate(final Integer option) {
    data.put(SETTINGS_TEMPLATE, option);
  }

  @Override
  public String getDescription() {
    return (String) data.get(DESCRIPTION);
  }

  @Override
  public void setDescription(final String description) {
    data.put(DESCRIPTION, description);
  }

  @Override
  public boolean isAllCertificateProfileIds() {
    return ((Boolean) data.get(ALL_CERTIFICATE_PROFILE_IDS)).booleanValue();
  }

  @Override
  public void setAllCertificateProfileIds(final boolean isAll) {
    data.put(ALL_CERTIFICATE_PROFILE_IDS, Boolean.valueOf(isAll));
  }

  @Override
  public List<Integer> getCertificateProfileIds() {
    final String value = (String) data.get(CERTIFICATE_PROFILE_IDS);
    final List<Integer> result = new ArrayList<Integer>();
    // Can be empty String here.
    if (StringUtils.isNotBlank(value)) {
      final String[] tokens = value.trim().split(LIST_SEPARATOR);
      for (int i = 0, j = tokens.length; i < j; i++) {
        result.add(Integer.valueOf(tokens[i]));
      }
    }
    return result;
  }

  @Override
  public void setCertificateProfileIds(final Collection<Integer> ids) {
    final StringBuilder builder = new StringBuilder();
    for (Integer lid : ids) {
      if (builder.length() == 0) {
        builder.append(lid);
      } else {
        builder.append(LIST_SEPARATOR).append(lid);
      }
    }
    data.put(CERTIFICATE_PROFILE_IDS, builder.toString());
  }

  @Override
  public void setFailedAction(final int index) {
    data.put(FAILED_ACTION, index);
  }

  @Override
  public int getFailedAction() {
    return ((Integer) data.get(FAILED_ACTION)).intValue();
  }

  @Override
  public void setNotApplicableAction(final int index) {
    data.put(NOT_APPLICABLE_ACTION, index);
  }

  @Override
  public int getNotApplicableAction() {
    return ((Integer) data.get(NOT_APPLICABLE_ACTION)).intValue();
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion. */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  @Override
  public void upgrade() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
    }
    super.upgrade();
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // New version of the class, upgrade.
      LOG.info(
          INTRES.getLocalizedMessage(
              "validator.upgrade", Float.valueOf(getVersion())));
      init();
      // Finished upgrade, set new version
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  @Override
  public String toDisplayString() {
    final StringBuilder result = new StringBuilder();
    result
        .append("BaseKeyValidator [id=")
        .append(id)
        .append(", name=")
        .append(getProfileName())
        .append(", applicableCertificateProfileIds=")
        .append(data.get(CERTIFICATE_PROFILE_IDS))
        .append(", notBefore=")
        .append(data.get(NOT_BEFORE))
        .append(", notBeforeCondition=")
        .append(data.get(NOT_BEFORE_CONDITION))
        .append(", notAfter=")
        .append(data.get(NOT_AFTER))
        .append(", notAfterCondition=")
        .append(data.get(NOT_AFTER_CONDITION))
        .append(", failedAction=")
        .append(data.get(FAILED_ACTION));
    return result.toString();
  }

  @Override
  public Validator clone() {
    getType();
    Validator clone;
    try {
      clone = (Validator) getType().getConstructor().newInstance();
    } catch (InstantiationException
        | IllegalAccessException
        | NoSuchMethodException
        | InvocationTargetException e) {
      throw new IllegalStateException(
          "Could not instansiate class of type "
              + getType().getCanonicalName());
    }
    clone.setProfileName(getProfileName());
    clone.setProfileId(getProfileId());

    // We need to make a deep copy of the hashmap here
    LinkedHashMap<Object, Object> dataMap = new LinkedHashMap<>(data.size());
    for (final Entry<Object, Object> entry : data.entrySet()) {
      Object value = entry.getValue();
      if (value instanceof ArrayList<?>) {
        // We need to make a clone of this object, but the stored immutables can
        // still be referenced
        value = ((ArrayList<?>) value).clone();
      }
      dataMap.put(entry.getKey(), value);
    }
    clone.setDataMap(dataMap);
    return clone;
  }

  @Override
  protected void saveTransientObjects() { // NOPMD: no-op
  }

  @Override
  protected void loadTransientObjects() { // NOPMD: no-op
  }

  @Override
  public UpgradeableDataHashMap getUpgradableHashmap() {
    return this;
  }
}
