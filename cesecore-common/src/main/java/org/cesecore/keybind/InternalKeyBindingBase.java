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
package org.cesecore.keybind;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Holder of general InternalKeyBinding relevant properties.
 *
 * @version $Id: InternalKeyBindingBase.java 30208 2018-10-26 09:04:57Z samuellb
 *     $
 */
public abstract class InternalKeyBindingBase extends UpgradeableDataHashMap
    implements InternalKeyBinding {

  private static final long serialVersionUID = 1L;
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(InternalKeyBindingBase.class);
  /** Property. */
  private static final String PROP_NEXT_KEY_PAIR_ALIAS = "nextKeyPairAlias";
  /** Property. */
  private static final String PROP_TRUSTED_CERTIFICATE_REFERENCES =
      "trustedCertificateReferences";
  /** Property. */
  private static final String PROP_SIGNATURE_ALGORITHM = "signatureAlgorithm";
  /** Extensions. */
  private static final String PROP_OCSP_EXTENSION = "ocspExtensions";
  /** Prefix. */
  private static final String BASECLASS_PREFIX = "BASECLASS_";
  /** Prefix. */
  public static final String SUBCLASS_PREFIX = "SUBCLASS_";
  /** ID. */
  private int internalKeyBindingId;
  /** Name. */
  private String name;
  /** Status. */
  private InternalKeyBindingStatus status;
  /** Status. */
  private InternalKeyBindingOperationalStatus operationalStatus;
  /** ID. */
  private String certificateId;
  /** ID. */
  private int cryptoTokenId;
  /** Alias. */
  private String keyPairAlias;
  /** Refs.  */
  private List<InternalKeyBindingTrustEntry> trustedCertificateReferences;
  /** extensions. */
  private List<String> ocspExtensions;
  /** Algo. */
  private String signatureAlgorithm;

  /** Format. */
  private static final SimpleDateFormat DATE_FORMAT_MS =
      new SimpleDateFormat("yyyyMMddHHmmssSSS");
  /** Format. */
  private static final Pattern DATE_FORMAT_PATTERN =
      Pattern.compile("_\\d{8}\\d{6}$");
  /** Format. */
  private static final Pattern DATE_FORMAT_PATTERN_MS =
      Pattern.compile("_\\d{8}\\d{9}$");


  /**
   * Map.
   */
  private final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>>
      propertyTemplates = new LinkedHashMap<>();

  /**
   * @param property property
   */
  protected void addProperty(
      final DynamicUiProperty<? extends Serializable> property) {
    propertyTemplates.put(property.getName(), property);
  }

  @Override
  public Map<String, DynamicUiProperty<? extends Serializable>>
      getCopyOfProperties() {
    final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> ret =
        new LinkedHashMap<>();
    for (String key : propertyTemplates.keySet()) {
      DynamicUiProperty<? extends Serializable> current =
          propertyTemplates.get(key);
      final DynamicUiProperty<? extends Serializable> clone = current.clone();
      clone.setValueGeneric(getProperty(clone.getName()).getValue());
      ret.put(key, clone);
    }
    return ret;
  }

  @Override
  public DynamicUiProperty<? extends Serializable> getProperty(
      final String aName) {
    DynamicUiProperty<? extends Serializable> property =
        propertyTemplates.get(aName);
    property = new DynamicUiProperty<>(property);
    property.setValueGeneric(getData(aName, property.getDefaultValue()));
    return property;
  }

  @Override
  public void setProperty(final String aName, final Serializable value) {
    putData(aName, value);
  }

  @Override
  public void init(
      final int aInternalKeyBindingId,
      final String aName,
      final InternalKeyBindingStatus aStatus,
      final String aCertificateId,
      final int aCryptoTokenId,
      final String aKeyPairAlias,
      final LinkedHashMap<Object, Object> aDataMap) {
    this.internalKeyBindingId = aInternalKeyBindingId;
    setName(aName);
    setStatus(aStatus);
    setCertificateId(aCertificateId);
    setCryptoTokenId(aCryptoTokenId);
    setKeyPairAlias(aKeyPairAlias);
    if (aDataMap.get(VERSION) == null) {
      // If we are creating a new object we need a version
      aDataMap.put(VERSION, Float.valueOf(getLatestVersion()));
    }
    loadData(aDataMap);
  }

  @Override
  public int getId() {
    return internalKeyBindingId;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public void setName(final String aName) {
    this.name = aName;
  }

  @Override
  public InternalKeyBindingStatus getStatus() {
    if (status == null) {
      status = InternalKeyBindingStatus.DISABLED;
    }
    return status;
  }

  @Override
  public void setStatus(final InternalKeyBindingStatus aStatus) {
    if (aStatus == null) {
      this.status = InternalKeyBindingStatus.DISABLED;
    } else {
      this.status = aStatus;
    }
  }

  @Override
  public InternalKeyBindingOperationalStatus getOperationalStatus() {
    if (operationalStatus == null) {
      operationalStatus = InternalKeyBindingOperationalStatus.OFFLINE;
    }
    return operationalStatus;
  }

  @Override
  public void setOperationalStatus(
      final InternalKeyBindingOperationalStatus aOperationalStatus) {
    if (aOperationalStatus == null) {
      this.operationalStatus = InternalKeyBindingOperationalStatus.OFFLINE;
    } else {
      this.operationalStatus = aOperationalStatus;
    }
  }

  @Override
  public String getCertificateId() {
    return certificateId;
  }

  @Override
  public void setCertificateId(final String aCertificateId) {
    this.certificateId = aCertificateId;
  }

  @Override
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }

  @Override
  public void setCryptoTokenId(final int aCryptoTokenId) {
    this.cryptoTokenId = aCryptoTokenId;
  }

  @Override
  public String getKeyPairAlias() {
    return keyPairAlias;
  }

  @Override
  public void setKeyPairAlias(final String aKeyPairAlias) {
    this.keyPairAlias = aKeyPairAlias;
  }

  @Override
  public String getNextKeyPairAlias() {
    return getData(PROP_NEXT_KEY_PAIR_ALIAS, (String) null);
  }

  @Override
  public void setNextKeyPairAlias(final String aNextKeyPairAlias) {
    putData(PROP_NEXT_KEY_PAIR_ALIAS, aNextKeyPairAlias);
  }

  @Override
  public void updateCertificateIdAndCurrentKeyAlias(
          final String aCertificateId) {
    setCertificateId(aCertificateId);
    setKeyPairAlias(getNextKeyPairAlias());
    setNextKeyPairAlias(null);
  }

  /**
   * Replace existing postfix or generate add a new one (using current time with
   * millisecond granularity).
   *
   * @param oldAlias alias
   * @return new alias
   */
  private String getNewAlias(final String oldAlias) {
    final Matcher matcherMs = DATE_FORMAT_PATTERN_MS.matcher(oldAlias);
    final String newPostFix = "_" + DATE_FORMAT_MS.format(new Date());
    // Check if the key alias postfix is in EJBCA 6.2.4+ format
    if (matcherMs.find()) {
      // Replace postfix in millisecond format
      return matcherMs.replaceAll(newPostFix);
    } else {
      final Matcher matcher = DATE_FORMAT_PATTERN.matcher(oldAlias);
      // Check if the key alias postfix is in EJBCA 6.2.3- format
      if (matcher.find()) {
        // Replace postfix with millisecond format
        return matcher.replaceAll(newPostFix);
      } else {
        // No postfix, add one
        return oldAlias + newPostFix;
      }
    }
  }

  @Override
  public void generateNextKeyPairAlias() {
    final String currentKeyPairAlias = getKeyPairAlias();
    final String nextKeyPairAlias = getNewAlias(currentKeyPairAlias);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "nextKeyPairAlias for internalKeyBinding "
              + internalKeyBindingId
              + " will be "
              + nextKeyPairAlias);
    }
    setNextKeyPairAlias(nextKeyPairAlias);
  }

  @Override
  public List<InternalKeyBindingTrustEntry> getTrustedCertificateReferences() {
    if (trustedCertificateReferences == null) {
      trustedCertificateReferences =
          getDataInternal(
              PROP_TRUSTED_CERTIFICATE_REFERENCES,
              new ArrayList<InternalKeyBindingTrustEntry>());
    }
    // Return a shallow copy of the list
    final ArrayList<InternalKeyBindingTrustEntry>
        aTrustedCertificateReferences =
            new ArrayList<InternalKeyBindingTrustEntry>();
    aTrustedCertificateReferences.addAll(this.trustedCertificateReferences);
    return aTrustedCertificateReferences;
  }

  @Override
  public void setTrustedCertificateReferences(
      final List<InternalKeyBindingTrustEntry> aTrustedCertificateReferences) {
    this.trustedCertificateReferences = aTrustedCertificateReferences;
    // Always save it as an ArrayList that we know is Serializable
    final ArrayList<InternalKeyBindingTrustEntry> arrayList =
        new ArrayList<InternalKeyBindingTrustEntry>(
            aTrustedCertificateReferences.size());
    arrayList.addAll(aTrustedCertificateReferences);
    putDataInternal(PROP_TRUSTED_CERTIFICATE_REFERENCES, arrayList);
  }

  @Override
  public List<String> getOcspExtensions() {
    if (ocspExtensions == null) {
      ocspExtensions =
          getDataInternal(PROP_OCSP_EXTENSION, new ArrayList<String>());
    }
    final ArrayList<String> ocspExensions = new ArrayList<>();
    ocspExensions.addAll(this.ocspExtensions);
    return ocspExtensions;
  }

  @Override
  public void setOcspExtensions(final List<String> aOcspExtensions) {
    this.ocspExtensions = aOcspExtensions;
    final ArrayList<String> arrayList = new ArrayList<>();
    arrayList.addAll(aOcspExtensions);
    putDataInternal(PROP_OCSP_EXTENSION, arrayList);
  }

  @Override
  public String getSignatureAlgorithm() {
    if (signatureAlgorithm == null) {
      signatureAlgorithm = getDataInternal(PROP_SIGNATURE_ALGORITHM, null);
    }
    return signatureAlgorithm;
  }

  @Override
  public void setSignatureAlgorithm(final String aSignatureAlgorithm) {
    this.signatureAlgorithm = aSignatureAlgorithm;
    putDataInternal(PROP_SIGNATURE_ALGORITHM, aSignatureAlgorithm);
  }

  @Override
  @SuppressWarnings("unchecked")
  public LinkedHashMap<Object, Object> getDataMapToPersist() {
    return (LinkedHashMap<Object, Object>) saveData();
  }

  @Override
  public abstract float getLatestVersion();

  @Override
  public abstract void assertCertificateCompatability(
      Certificate certificate,
      AvailableExtendedKeyUsagesConfiguration ekuConfig)
      throws CertificateImportException;

  @Override
  public void upgrade() {
    // TODO: Here we can to upgrades of base properties when needed.. we do not
    // to store a version for this as well tough..
    upgrade(getLatestVersion(), getVersion());
  }

  /**
   * Invoked after the all data has been loaded in init(...).
   *
   * @param latestVersion new version
   * @param currentVersion old version
   */
  protected abstract void upgrade(
      float latestVersion, float currentVersion);

  /**
   * Store data in the underlying map. Encourages use of String valued keys.
   *
   * @param key key
   * @param value value
   */
  private void putData(final String key, final Object value) {
    data.put(SUBCLASS_PREFIX + key, value);
  }

  /**
   * @param key key
   * @param defaultValue value
   * @param <T> type
   * @return data from the underlying map. Encourages use of String valued keys.
   */
  @SuppressWarnings("unchecked")
  private <T> T getData(final String key, final T defaultValue) {
    final T ret = (T) data.get(SUBCLASS_PREFIX + key);
    return ret == null ? defaultValue : ret;
  }

  /**
   * Store data in the underlying map. Encourages use of String valued keys.
   *
   * @param key key
   * @param value value
   */
  private void putDataInternal(final String key, final Object value) {
    data.put(BASECLASS_PREFIX + key, value);
  }

  /**
   * @param key key
   * @param defaultValue value
   * @param <T> type
   * @return data from the underlying map. Encourages use of String valued keys.
   */
  @SuppressWarnings("unchecked")
  private <T> T getDataInternal(final String key, final T defaultValue) {
    final T ret = (T) data.get(BASECLASS_PREFIX + key);
    return ret == null ? defaultValue : ret;
  }
}
