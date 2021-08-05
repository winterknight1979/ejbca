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
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypeConstants;

/**
 * Class used mostly when creating service. Also used when info about the
 * services is needed
 *
 * @version $Id: CmsCAServiceInfo.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class CmsCAServiceInfo extends BaseSigningCAServiceInfo
    implements Serializable {

  private static final long serialVersionUID = 7556251008892332034L;

  /**
   * Used when creating new service.
   *
   * @param status Status
   * @param subjectdn DN
   * @param subjectaltname Name
   * @param keyspec Spec
   * @param keyalgorithm Algo
   */
  public CmsCAServiceInfo(
      final int status,
      final String subjectdn,
      final String subjectaltname,
      final String keyspec,
      final String keyalgorithm) {
    super(status, subjectdn, subjectaltname, keyspec, keyalgorithm);
  }

  /**
   * Used when returning information from service.
   *
   * @param status Status
   * @param subjectdn DN
   * @param subjectaltname Name
   * @param keyspec Spec
   * @param keyalgorithm Algo
   * @param certchain Certs
   */
  public CmsCAServiceInfo(
      final int status,
      final String subjectdn,
      final String subjectaltname,
      final String keyspec,
      final String keyalgorithm,
      final List<Certificate> certchain) {
    super(status, subjectdn, subjectaltname, keyspec, keyalgorithm, certchain);
  }

  /** Used when updating existing services, only status is used.
 * @param status Status
 * @param renew Renew */
  public CmsCAServiceInfo(final int status, final boolean renew) {
    super(status, renew);
  }

  @Override
  public String getImplClass() {
    return CmsCAService.class.getName();
  }

  @Override
  public int getType() {
    return ExtendedCAServiceTypeConstants.TYPE_CMSEXTENDEDSERVICE;
  }
}
