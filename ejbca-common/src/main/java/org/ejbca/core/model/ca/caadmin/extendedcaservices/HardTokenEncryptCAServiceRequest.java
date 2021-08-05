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
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypeConstants;

/**
 * Class used when requesting hard token encrypt related services from a CA.
 *
 * @version $Id: HardTokenEncryptCAServiceRequest.java 19901 2014-09-30
 *     14:29:38Z anatom $
 */
public class HardTokenEncryptCAServiceRequest extends ExtendedCAServiceRequest
    implements Serializable {

  private static final long serialVersionUID = 8081402124613587671L;
  /** Config. */
  public static final int COMMAND_ENCRYPTDATA = 1;
  /** Config. */
  public static final int COMMAND_DECRYPTDATA = 2;

  /** Cmd. */
  private final int command;
  /** Data. */
  private final byte[] data;

  /**
   * @param aCommand cmd
   * @param theData data
   */
  public HardTokenEncryptCAServiceRequest(
      final int aCommand, final byte[] theData) {
    this.command = aCommand;
    this.data = theData;
  }

  /**
   * @return Command
   */
  public int getCommand() {
    return command;
  }

  /**
   * Returns data beloning to the decrypt keys request, returns null oterwise.
   *
   * @return data
   */
  public byte[] getData() {
    return data;
  }

  @Override
  public int getServiceType() {
    return ExtendedCAServiceTypeConstants.TYPE_HARDTOKENENCEXTENDEDSERVICE;
  }
}
