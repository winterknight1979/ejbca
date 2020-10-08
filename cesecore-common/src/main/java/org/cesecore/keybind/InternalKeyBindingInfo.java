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
import javax.naming.OperationNotSupportedException;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Value object for remote invocation from JVMs where the implementation class
 * is not available.
 *
 * @version $Id: InternalKeyBindingInfo.java 28496 2018-03-16 12:13:55Z henriks
 *     $
 */
public class InternalKeyBindingInfo implements InternalKeyBinding {

  private static final long serialVersionUID = 1L;

  /** Alias. */
  private final String implementationAlias;
  /** ID. */
  private final int id;
  /** Name. */
  private final String name;
  /** Status. */
  private final InternalKeyBindingStatus status;
  /** Status. */
  private final InternalKeyBindingOperationalStatus operationalStatus;
  /** Cert. */
  private final String certificateId;
  /** Token. */
  private final int cryptoTokenId;
  /** Alias. */
  private final String keyPairAlias;
  /** Alias. */
  private final String nextKeyPairAlias;
  /** Props. */
  private final Map<String, DynamicUiProperty<? extends Serializable>>
      properties;
  /** Refs. */
  private final List<InternalKeyBindingTrustEntry> trustedCertificateReferences;
  /** Exts. */
  private final List<String> ocspExtensions;
  /** Algo. */
  private final String signatureAlgorithm;

  /**
   * @param internalKeyBinding binding
   */
  public InternalKeyBindingInfo(final InternalKeyBinding internalKeyBinding) {
    this.implementationAlias = internalKeyBinding.getImplementationAlias();
    this.id = internalKeyBinding.getId();
    this.name = internalKeyBinding.getName();
    this.status = internalKeyBinding.getStatus();
    this.operationalStatus = internalKeyBinding.getOperationalStatus();
    this.certificateId = internalKeyBinding.getCertificateId();
    this.cryptoTokenId = internalKeyBinding.getCryptoTokenId();
    this.keyPairAlias = internalKeyBinding.getKeyPairAlias();
    this.nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
    this.properties = internalKeyBinding.getCopyOfProperties();
    this.trustedCertificateReferences =
        internalKeyBinding.getTrustedCertificateReferences();
    this.ocspExtensions = internalKeyBinding.getOcspExtensions();
    this.signatureAlgorithm = internalKeyBinding.getSignatureAlgorithm();
  }

  @Override
  public void init(
      final int aId,
      final String aName,
      final InternalKeyBindingStatus aStatus,
      final String aCertificateId,
      final int aCryptoTokenId,
      final String aKeyPairAlias,
      final LinkedHashMap<Object, Object> dataMapToLoad) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public LinkedHashMap<Object, Object> getDataMapToPersist() {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public String getImplementationAlias() {
    return implementationAlias;
  }

  @Override
  public String getNextKeyPairAlias() {
    return nextKeyPairAlias;
  }

  @Override
  public void setNextKeyPairAlias(final String aNextKeyPairAlias) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public void updateCertificateIdAndCurrentKeyAlias(
          final String aCertificateId) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public void generateNextKeyPairAlias() {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public void assertCertificateCompatability(
      final Certificate certificate,
      final AvailableExtendedKeyUsagesConfiguration ekuConfig)
      throws CertificateImportException {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public int getId() {
    return id;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public void setName(final String aName) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public InternalKeyBindingStatus getStatus() {
    return status;
  }

  @Override
  public void setStatus(final InternalKeyBindingStatus aStatus) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public InternalKeyBindingOperationalStatus getOperationalStatus() {
    return operationalStatus;
  }

  @Override
  public void setOperationalStatus(
      final InternalKeyBindingOperationalStatus opStatus) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public String getCertificateId() {
    return certificateId;
  }

  @Override
  public void setCertificateId(final String aCertificateId) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public int getCryptoTokenId() {
    return cryptoTokenId;
  }

  @Override
  public void setCryptoTokenId(final int aCryptoTokenId) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public String getKeyPairAlias() {
    return keyPairAlias;
  }

  @Override
  public void setKeyPairAlias(final String aKeyPairAlias) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public DynamicUiProperty<? extends Serializable> getProperty(
          final String aName) {
    return properties.get(aName);
  }

  @Override
  public void setProperty(
          final String aName, final Serializable value) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public Map<String, DynamicUiProperty<? extends Serializable>>
      getCopyOfProperties() {
    return properties;
  }

  @Override
  public List<InternalKeyBindingTrustEntry> getTrustedCertificateReferences() {
    return trustedCertificateReferences;
  }

  @Override
  public void setTrustedCertificateReferences(
      final List<InternalKeyBindingTrustEntry> aTrustedCertificateReferences) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  @Override
  public void setSignatureAlgorithm(final String aSignatureAlgorithm) {
    throw new RuntimeException(new OperationNotSupportedException());
  }

  @Override
  public List<String> getOcspExtensions() {
    return ocspExtensions;
  }

  @Override
  public void setOcspExtensions(final List<String> aOcspExtensions) {
    throw new RuntimeException(new OperationNotSupportedException());
  }
}
