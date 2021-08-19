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

/**
 * @version $Id: CryptoTokenConstants.java 17625 2013-09-20 07:12:06Z netmackan
 *     $
 */
public final class CryptoTokenConstants {

  /** constants needed for soft crypto tokens. */
  protected static final String SIGNKEYSPEC = "SIGNKEYSPEC";
  /** Encrypt. */
  protected static final String ENCKEYSPEC = "ENCKEYSPEC";
  /** Sign. */
  protected static final String SIGNKEYALGORITHM = "SIGNKEYALGORITHM";
  /** Encrypt. */
  protected static final String ENCKEYALGORITHM = "ENCKEYALGORITHM";
  /** Store. */
  protected static final String KEYSTORE = "KEYSTORE";


  private CryptoTokenConstants() { }

}
