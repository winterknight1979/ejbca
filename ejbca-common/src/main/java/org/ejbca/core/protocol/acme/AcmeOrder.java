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
package org.ejbca.core.protocol.acme;

import java.util.LinkedHashMap;
import java.util.List;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.protocol.acme.response.AcmeProblemResponse;

/**
 * ACME Order object.
 *
 * @version $Id: AcmeOrder.java 29784 2018-08-30 08:20:30Z tarmo_r_helmes $
 */
public interface AcmeOrder {

    /**
     * @return ID
     */
  String getOrderId();

  /**
   * @return ID
   */
  String getAccountId();

  /**
   * @return FP
   */
  String getFingerprint();

  /**
   * @param fingerprint FP
   */
  void setFingerprint(String fingerprint);

  /**
   * @return Status
   */
  String getStatus();

  /**
   * @param status status
   */
  void setStatus(String status);

  /**
   * @return fin
   */
  String getFinalize();

  /**
   * @param finalize fin
   */
  void setFinalize(String finalize);

  /**
   * @return IDs
   */
  List<AcmeIdentifier> getIdentifiers();

  /**
   * @param identifiers IDs
   */
  void setIdentifiers(List<AcmeIdentifier> identifiers);

  /**
   * @return date
   */
  long getNotBefore();

  /**
   * @return datr
   */
  long getNotAfter();

  /**
   * @return expiry
   */
  long getExpires();

  /**
   * @return Status
   */
  AcmeOrderStatus getAcmeOrderStatus();

  /**
   * @param acmeOrderStatus Status
   */
  void setAcmeOrderStatus(AcmeOrderStatus acmeOrderStatus);

  /**
   * @return ID
   */
  String getCertificateId();

  /**
   * @param certificateId ID
   */
  void setCertificateId(String certificateId);

  /**
   * @return resp
   */
  AcmeProblemResponse getError();

  /**
   * @param acmeProblemResponse resp
   */
  void setError(AcmeProblemResponse acmeProblemResponse);

  /**
   * @param endEntityInformation info.
   */
  void setEndEntityInformation(EndEntityInformation endEntityInformation);

  /**
   * @return Info.
   */
  EndEntityInformation getEndEntityInformation();

  /** @return Version. */
  float getLatestVersion();

  /** Upgrade. */
  void upgrade();

  /**
   * @return map
   */
  LinkedHashMap<Object, Object> getRawData();

  /**
   * @param isActive bool
   */
  void setIsActive(boolean isActive);

  /**
   * @return bool
   */
  boolean getIsActive();
}
