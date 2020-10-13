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
package org.cesecore.config;

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.util.CertTools;

/**
 * @version $Id: GlobalOcspConfiguration.java 25867 2017-05-17 16:18:06Z
 *     mikekushner $
 */
public class GlobalOcspConfiguration extends ConfigurationBase {

    /** ID. */
  public static final String OCSP_CONFIGURATION_ID = "OCSP";

  private static final long serialVersionUID = 1L;
  /** config. */
  private static final String DEFAULT_OCSP_RESPONDER_REFERENCE =
      "defaultOcspResponderReference";
  /** config. */
  private static final String OCSP_RESPONDER_ID_TYPE_REFERENCE =
      "ocspResponderIdType";
  /** config. */
  private static final String DEFAULT_NONCE_ENABLED_REFERENCE =
      "defaultNonceEnabled";

  /**
   * @return ref
   */
  public String getOcspDefaultResponderReference() {
    return CertTools.stringToBCDNString(
        (String) data.get(DEFAULT_OCSP_RESPONDER_REFERENCE));
  }

  /**
   * @param reference ref
   */
  public void setOcspDefaultResponderReference(final String reference) {
    data.put(DEFAULT_OCSP_RESPONDER_REFERENCE, reference);
  }

  /**
   * @return type
   */
  @SuppressWarnings("deprecation")
  public OcspKeyBinding.ResponderIdType getOcspResponderIdType() {
    OcspKeyBinding.ResponderIdType ocspResponderIdType =
        (ResponderIdType) data.get(OCSP_RESPONDER_ID_TYPE_REFERENCE);
    if (ocspResponderIdType == null) {
      // Lazy upgrade if running from versions prior to 6.7.0
      ocspResponderIdType =
          OcspKeyBinding.ResponderIdType.getFromNumericValue(
              OcspConfiguration.getResponderIdType());
      setOcspResponderIdType(ocspResponderIdType);
    }
    return ocspResponderIdType;
  }

  /**
   * @param ocspResponderIdType type
   */
  public void setOcspResponderIdType(
      final OcspKeyBinding.ResponderIdType ocspResponderIdType) {
    data.put(OCSP_RESPONDER_ID_TYPE_REFERENCE, ocspResponderIdType);
  }

  /**
   * @return true if CA's replying to their own OCSP requests should include
   *     NONCE's in the replies.
   */
  public boolean getNonceEnabled() {
    // Lady upgrade
    if (data.get(DEFAULT_NONCE_ENABLED_REFERENCE) == null) {
      setNonceEnabled(true);
    }
    return (Boolean) data.get(DEFAULT_NONCE_ENABLED_REFERENCE);
  }

  /**
   * @param enabled to true if CA's replying to their own OCSP requests should
   *     include NONCE's in the replies.
   */
  public void setNonceEnabled(final boolean enabled) {
    data.put(DEFAULT_NONCE_ENABLED_REFERENCE, Boolean.valueOf(enabled));
  }

  @Override
  public void upgrade() {
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
  }

  @Override
  public String getConfigurationId() {
    return OCSP_CONFIGURATION_ID;
  }
}
