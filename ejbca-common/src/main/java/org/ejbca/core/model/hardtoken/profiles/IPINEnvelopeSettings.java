/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.hardtoken.profiles;

import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Interface containing methods that need to be implemented in order to have a
 * hard token profile contain PIN Envelope settings.
 *
 * @version $Id: IPINEnvelopeSettings.java 22117 2015-10-29 10:53:42Z
 *     mikekushner $
 */
public interface IPINEnvelopeSettings {

  /** Constant indicating that no envelope should be printed. */
  int PINENVELOPETYPE_NONE = 0;
  /** Constant indicating that a general envelope type should be printed. */
  int PINENVELOPETYPE_GENERALENVELOBE = 1;

  /** @return the type of PIN envelope to print. */
  int getPINEnvelopeType();

  /**
   * sets the pin envelope type.
   *
   * @param pinenvelopetype PIN
   */
  void setPINEnvelopeType(int pinenvelopetype);

  /** @return the filename of the current PIN envelope template. */
  String getPINEnvelopeTemplateFilename();

  /** @param filename Sets the filename of the current PIN envelope template. */
  void setPINEnvelopeTemplateFilename(String filename);

  /** @return the data of the PIN Envelope template. */
  String getPINEnvelopeData();

  /** @param data Sets the data of the PIN envelope template. */
  void setPINEnvelopeData(String data);

  /**
   * @return the number of copies of this PIN Envelope that should be printed.
   */
  int getNumberOfPINEnvelopeCopies();

  /**
   * @param copies Sets the number of copies of this PIN Envelope that should be
   *     printed.
   */
  void setNumberOfPINEnvelopeCopies(int copies);

  /** @return the validity of the visual layout in days. */
  int getVisualValidity();

  /** @param validity Sets the validity of the visual layout in days. */
  void setVisualValidity(int validity);

  /**
   * Method that parses the template, replaces the userdata and returning a
   * printable byte array.
   *
   * @param userdata User
   * @param pincodes PIN
   * @param pukcodes PUK
   * @param hardtokensn SN
   * @param copyoftokensn SN copt
   * @return Envelope
   * @throws IOException IO fail
   * @throws PrinterException Printer fail
   */
  Printable printPINEnvelope(
      EndEntityInformation userdata,
      String[] pincodes,
      String[] pukcodes,
      String hardtokensn,
      String copyoftokensn)
      throws IOException, PrinterException;
}
