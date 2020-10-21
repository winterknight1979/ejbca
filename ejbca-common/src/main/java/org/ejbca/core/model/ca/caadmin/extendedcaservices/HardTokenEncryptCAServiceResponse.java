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
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;

/**
 * Class used when delivering hard token encrypt service response from a CA.
 *
 * @version $Id: HardTokenEncryptCAServiceResponse.java 19901 2014-09-30
 *     14:29:38Z anatom $
 */
public class HardTokenEncryptCAServiceResponse extends ExtendedCAServiceResponse
    implements Serializable {

  private static final long serialVersionUID = -6027721745272019615L;
  /** Config. */
  public static final int TYPE_ENCRYPTRESPONSE = 1;
  /** Config. */
  public static final int TYPE_DECRYPTRESPONSE = 1;
  /** Type. */
  private final int type;
  /** data. */
  private final byte[] data;

  /**
   * @param aType type
   * @param theData data
   */
  public HardTokenEncryptCAServiceResponse(
          final int aType, final byte[] theData) {
    this.type = aType;
    this.data = theData;
  }

  /** @return type of response, one of the TYPE_ constants. */
  public int getType() {
    return type;
  }

  /**
   * Method returning the data if the type of response.
   *
   * @return Data
   */
  public byte[] getData() {
    return data;
  }
}
