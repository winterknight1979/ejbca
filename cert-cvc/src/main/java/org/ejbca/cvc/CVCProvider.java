/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import java.security.Provider;

/**
 * This is our own Security Provider for CVC.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class CVCProvider extends Provider {

  private static final long serialVersionUID = 1L;
  /** Param. */
  public static final double VERSION = 1.0;
  // TODO: Text OK?
  /** Param. */
  public static final String INFO =
      "CVC Security Provider "
          + VERSION
          + " (supports Card Verifiable Certificates for ePassports)";

  /** Param. */
  public static final String PROVIDER_NAME = "CVC";

  /**
   * Constructor.
   */
  @SuppressWarnings("deprecation")
  public CVCProvider() {
    super(PROVIDER_NAME, VERSION, INFO);

    put("CertificateFactory.CVC", JDKCVCertificateFactory.class.getName());
    put("Alg.Alias.CertificateFactory.CVC", "CVC");
  }
}
