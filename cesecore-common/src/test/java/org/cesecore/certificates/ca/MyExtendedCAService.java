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
package org.cesecore.certificates.ca;

import java.util.HashMap;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.keys.token.CryptoToken;

/**
 * @version $Id: MyExtendedCAService.java 22147 2015-11-03 16:24:00Z mikekushner
 *     $
 */
public class MyExtendedCAService extends ExtendedCAService {
/**
 * @param info info
 */
  public MyExtendedCAService(final ExtendedCAServiceInfo info) {
    super(info);
    data.put(
        ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());
  }

  /**
   * @param data data
   */
  public MyExtendedCAService(final HashMap<?, ?> data) {
    super(data);
    loadData(data);
  }

  private static final long serialVersionUID = 1L;
/** Runs. */
  private static int didrun = 0;

  @Override
  public ExtendedCAServiceResponse extendedService(
      final CryptoToken cryptoToken, final ExtendedCAServiceRequest request)
      throws ExtendedCAServiceRequestException,
          IllegalExtendedCAServiceRequestException,
          ExtendedCAServiceNotActiveException {
    didrun++;
    return new MyExtendedCAServiceResponse();
  }

  @Override
  public ExtendedCAServiceInfo getExtendedCAServiceInfo() {
    return new MyExtendedCAServiceInfo(0);
  }

  @Override
  public float getLatestVersion() {
    return 0;
  }

  @Override
  public void upgrade() { }

  @Override
  public void init(
      final CryptoToken cryptoToken,
      final CA ca,
      final AvailableCustomCertificateExtensionsConfiguration cceConfig)
      throws Exception { }

  @Override
  public void update(
      final CryptoToken cryptoToken,
      final ExtendedCAServiceInfo info,
      final CA ca,
      final AvailableCustomCertificateExtensionsConfiguration cceConfig) { }

/**
 * @return the didrun
 */
public static int getDidrun() {
    return didrun;
}


}
