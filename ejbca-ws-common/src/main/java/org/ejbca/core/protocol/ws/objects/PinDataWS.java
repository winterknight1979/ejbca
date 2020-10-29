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

package org.ejbca.core.protocol.ws.objects;

/**
 * Class containing a web service representation of a PIN data such as type, PIN
 * and PUK.
 *
 * @author Philip Vendil
 * @version $Id: PinDataWS.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class PinDataWS {

      /** Param. */
  private int type = 0;
  /** Param. */
  private String initialPIN = null;
  /** Param. */
  private String puk = null;

  /** WS Constructor. */
  public PinDataWS() { }

  /**
   * Default constructor.
   *
   * @param atype pnt of the PINTYPE_ constants
   * @param aninitialPIN the initial pin of the token
   * @param apuk the puk of the token
   */
  public PinDataWS(int atype, String aninitialPIN, String apuk) {
    super();
    this.type = atype;
    this.initialPIN = aninitialPIN;
    puk = apuk;
  }

  /** @return the initial pin of the token */
  public String getInitialPIN() {
    return initialPIN;
  }

  /** @param aninitialPIN the initial pin of the token */
  public void setInitialPIN(String aninitialPIN) {
    this.initialPIN = aninitialPIN;
  }

  /** @return the puk of the token */
  public String getPUK() {
    return puk;
  }

  /** @param apuk the puk of the token */
  public void setPUK(String apuk) {
    puk = apuk;
  }

  /** @return the type of PIN one of the PINTTYPE_ constants */
  public int getType() {
    return type;
  }

  /** @param atype type of PIN one of the PINTTYPE_ constants */
  public void setType(int atype) {
    this.type = atype;
  }
}
