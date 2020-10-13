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
package org.cesecore.keys.token;

import java.io.Serializable;
import java.util.Properties;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;

/**
 * Non-sensitive information about a CryptoToken.
 *
 * @version $Id: CryptoTokenInfo.java 28849 2018-05-04 12:33:49Z
 *     jekaterina_b_helmes $
 */
public class CryptoTokenInfo implements Serializable {

  private static final long serialVersionUID = 5025517840531557857L;
  /** ID. */
  private final Integer cryptoTokenId;
  /** Name. */
  private final String name;
  /** bool. */
  private final boolean active;
  /** bool. */
  private final boolean autoActivation;
  /** Type. */
  private final String type;
  /** Properties. */
  private final Properties cryptoTokenProperties;

  /**   *
   * @param aCryptoTokenId ID
   * @param aName Name
   * @param isActive Active
   * @param isAutoActivation Auto activate
   * @param aType Type
   * @param aCryptoTokenProperties Properties
   */
  public CryptoTokenInfo(
      final Integer aCryptoTokenId,
      final String aName,
      final boolean isActive,
      final boolean isAutoActivation,
      final Class<? extends CryptoToken> aType,
      final Properties aCryptoTokenProperties) {
    this.cryptoTokenId = aCryptoTokenId;
    this.name = aName;
    this.active = isActive;
    this.autoActivation = isAutoActivation;
    this.type = aType.getSimpleName();
    this.cryptoTokenProperties = aCryptoTokenProperties;
  }

  /**
   * @return id
   */
  public Integer getCryptoTokenId() {
    return cryptoTokenId;
  }

  /**
   * @return name
   */
  public String getName() {
    return name;
  }

  /**
   * @return bool
   */
  public boolean isActive() {
    return active;
  }

  /**
   * @return bool
   */
  public boolean isAutoActivation() {
    return autoActivation;
  }

  /**
   * @return type
   */
  public String getType() {
    return type;
  }

  /**
   * @return bool
   */
  public boolean isAllowExportPrivateKey() {
    return Boolean.valueOf(
        cryptoTokenProperties.getProperty(
            SoftCryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY,
            Boolean.FALSE.toString()));
  }

  /**
   * @return bool
   */
  public boolean isAllowExplicitParameters() {
    return Boolean.valueOf(
        cryptoTokenProperties.getProperty(
            SoftCryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS,
            Boolean.FALSE.toString()));
  }

  /**
   * @return library
   */
  public String getP11Library() {
    return cryptoTokenProperties.getProperty(
        PKCS11CryptoToken.SHLIB_LABEL_KEY, "");
  }

  /**
   * @return slot
   */
  public String getP11Slot() {
    return cryptoTokenProperties.getProperty(
        PKCS11CryptoToken.SLOT_LABEL_VALUE);
  }

  /**
   * @return label type
   */
  public String getP11SlotLabelType() {
    Pkcs11SlotLabelType slotLabelType =
        Pkcs11SlotLabelType.getFromKey(
            cryptoTokenProperties.getProperty(
                PKCS11CryptoToken.SLOT_LABEL_TYPE));
    if (slotLabelType != null) {
      return slotLabelType.getKey();
    } else {
      return null;
    }
  }

  /**
   * @return Label description
   */
  public String getP11SlotLabelTypeDescription() {
    Pkcs11SlotLabelType slotLabelType =
        Pkcs11SlotLabelType.getFromKey(
            cryptoTokenProperties.getProperty(
                PKCS11CryptoToken.SLOT_LABEL_TYPE));
    if (slotLabelType != null) {
      return slotLabelType.getDescription();
    } else {
      return null;
    }
  }

  /**
   * @return File
   */
  public String getP11AttributeFile() {
    return cryptoTokenProperties.getProperty(
        PKCS11CryptoToken.ATTRIB_LABEL_KEY, "");
  }

  /**
   * @return Properties
   */
  public Properties getCryptoTokenProperties() {
    return cryptoTokenProperties;
  }
}
