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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Interface for the InternalKeyBindings.
 *
 * @version $Id: InternalKeyBinding.java 28496 2018-03-16 12:13:55Z henriks $
 */
public interface InternalKeyBinding extends Serializable {

  /**
   * Called directly after implementation instantiation status.
   *
   * @param id ID
   * @param name Name
   * @param status Status
   * @param certificateId ID of certificate
   * @param cryptoTokenId ID of Crypto token
   * @param keyPairAlias Key pair
   * @param dataMapToLoad Map
   */
  void init(
      int id,
      String name,
      InternalKeyBindingStatus status,
      String certificateId,
      int cryptoTokenId,
      String keyPairAlias,
      LinkedHashMap<Object, Object> dataMapToLoad);

  /**
   * Called directly before object is persisted.
   *
   * @return Map
   */
  LinkedHashMap<Object, Object> getDataMapToPersist();

  /**
   * @return the non-changeable alias for this implementation. E.g.
   *     "DummyKeyBinding".
   */
  String getImplementationAlias();

  /**
   * @return the next key pair's alias to be used or null of there currently is
   *     no mapped next key
   */
  String getNextKeyPairAlias();

  /**
   * Set the next key pair's alias to be used.
   *
   * @param currentNextKeyPairAlias alias
   */
  void setNextKeyPairAlias(String currentNextKeyPairAlias);

  /**
   * Uses the next key alias as current key alias and updates the certificateId.
   *
   * @param certificateId certificate
   */
  void updateCertificateIdAndCurrentKeyAlias(String certificateId);

  /**
   * Generates a next key pair alias based on the current one using a simple
   * counter as postfix.
   */
  void generateNextKeyPairAlias();

  /**
   * IMPORTANT: The validation must be done properly to avoid unintended
   * certificate import.
   *
   * @param certificate certificate
   * @param ekuConfig config
   * @throws CertificateImportException if the provided certificate is not
   *     compatible with this type of implementation
   */
  void assertCertificateCompatability(
      Certificate certificate,
      AvailableExtendedKeyUsagesConfiguration ekuConfig)
      throws CertificateImportException;

  /** @return the non-changeable id of this instance */
  int getId();

  /** @return the current human friendly name of this instance */
  String getName();

  /**
   * Sets the current human friendly name of this instance.
   *
   * @param name name
   */
  void setName(String name);

  /** @return the current status of this instance */
  InternalKeyBindingStatus getStatus();

  /**
   * Sets the current status of this instance.
   *
   * @param status status
   */
  void setStatus(InternalKeyBindingStatus status);

  /** @return the current operational status of this instance */
  InternalKeyBindingOperationalStatus getOperationalStatus();

  /**
   * Sets the current operational status of this instance.
   *
   * @param opStatus status
   */
  void setOperationalStatus(InternalKeyBindingOperationalStatus opStatus);

  /**
   * @return the fingerprint of the certificate currently in use or null if none
   *     is referenced
   */
  String getCertificateId();

  /**
   * Sets the fingerprint of the certificate currently in use.
   *
   * @param certificateId ID
   */
  void setCertificateId(String certificateId);

  /** @return the id of the CryptoToken currently in use */
  int getCryptoTokenId();

  /**
   * Sets the id of the CryptoToken currently in use.
   *
   * @param cryptoTokenId ID
   */
  void setCryptoTokenId(int cryptoTokenId);

  /** @return the key pair alias currently in use */
  String getKeyPairAlias();

  /**
   * Sets the key pair alias currently in use.
   *
   * @param keyPairAlias alias
   */
  void setKeyPairAlias(String keyPairAlias);

  /**
   * Set an implementation specific property.
   *
   * @param name name
   * @param value value
   */
  void setProperty(String name, Serializable value);

  /**
   * @param name name
   * @return an implementation specific property or the default
   */
  DynamicUiProperty<? extends Serializable> getProperty(String name);

  /**
   * Get a defensive copy of all properties.
   *
   * @return a Map of all properties/data specific to this implementation, keyed
   *     to each property's name.
   */
  Map<String, DynamicUiProperty<? extends Serializable>> getCopyOfProperties();

  /**
   * @return a list of trusted certificates references. An undefined (null)
   *     serialnumber means ANY serialnumber.
   */
  List<InternalKeyBindingTrustEntry> getTrustedCertificateReferences();

  /**
   * Set the list of trusted certificates references. An undefined (null)
   * serialnumber means ANY serialnumber.
   *
   * @param trustedCertificateReferences references
   */
  void setTrustedCertificateReferences(
      List<InternalKeyBindingTrustEntry> trustedCertificateReferences);

  /** @return the currently used signature algorithm */
  String getSignatureAlgorithm();

  /**
   * Set the currently used signature algorithm (it is up to the caller to
   * ensure that this is compatible with the current keyspec).
   *
   * @param signatureAlgorithm algorithm
   */
  void setSignatureAlgorithm(String signatureAlgorithm);

  /**
   * @return extensions
   */
  List<String> getOcspExtensions();

  /**
   * @param ocspExtensions extensions
   */
  void setOcspExtensions(List<String> ocspExtensions);
}
