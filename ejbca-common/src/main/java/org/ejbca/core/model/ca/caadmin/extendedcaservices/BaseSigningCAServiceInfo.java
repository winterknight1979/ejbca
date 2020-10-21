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

package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.util.AlgorithmConstants;

/**
 * Base class for CAServiceInfo used by extended services that does signing.
 *
 * @version $Id: BaseSigningCAServiceInfo.java 19901 2014-09-30 14:29:38Z anatom
 *     $
 */
public abstract class BaseSigningCAServiceInfo extends ExtendedCAServiceInfo
    implements Serializable {

  private static final long serialVersionUID = -6607852949410303766L;
  /** DN. */
  private String subjectdn = null;
  /** Name. */
  private String subjectaltname = null;
  /** Spec.*/
  private String keyspec = "1024"; // Default key length
  /** Algo. */
  private String keyalgorithm =
      AlgorithmConstants.KEYALGORITHM_RSA; // Default key algo
  /** Chain. */
  private List<Certificate> certchain = null;
/** renew. */
  private boolean renew = false;

  /**
   * Used when creating new service.
   *
   * @param status Status
   * @param aSubjectdn DN
   * @param aSubjectaltname Name
   * @param aKeyspec Spec
   * @param aKeyalgorithm Algo
   */
  public BaseSigningCAServiceInfo(
      final int status,
      final String aSubjectdn,
      final String aSubjectaltname,
      final String aKeyspec,
      final String aKeyalgorithm) {
    super(status);
    this.subjectdn = aSubjectdn;
    this.subjectaltname = aSubjectaltname;
    this.keyspec = aKeyspec;
    this.keyalgorithm = aKeyalgorithm;
  }

  /**
   * Used when returning information from service.
   *
   * @param status Status
   * @param aSubjectdn DN
   * @param aSubjectaltname Name
   * @param aKeyspec Spec
   * @param aKeyalgorithm Algo
   * @param aCertpath Certs
   */
  public BaseSigningCAServiceInfo(
      final int status,
      final String aSubjectdn,
      final String aSubjectaltname,
      final String aKeyspec,
      final String aKeyalgorithm,
      final List<Certificate> aCertpath) {
    super(status);
    this.subjectdn = aSubjectdn;
    this.subjectaltname = aSubjectaltname;
    this.keyspec = aKeyspec;
    this.keyalgorithm = aKeyalgorithm;
    this.certchain = aCertpath;
  }

  /** Used when updating existing services, only status is used.
 * @param status status
 * @param isrenew  renew */
  public BaseSigningCAServiceInfo(final int status, final boolean isrenew) {
    super(status);
    this.renew = isrenew;
  }

  /**
   * @return DN
   */
  public String getSubjectDN() {
    return this.subjectdn;
  }

  /**
   * @return name
   */
  public String getSubjectAltName() {
    return this.subjectaltname;
  }

  /**
   * @return spec
   */
  public String getKeySpec() {
    return this.keyspec;
  }

  /**
   * @return algo
   */
  public String getKeyAlgorithm() {
    return this.keyalgorithm;
  }

  /**
   * @return flag
   */
  public boolean getRenewFlag() {
    return this.renew;
  }
  /**
   * @return path
   */
  public List<Certificate> getCertificatePath() {
    return this.certchain;
  }
}
