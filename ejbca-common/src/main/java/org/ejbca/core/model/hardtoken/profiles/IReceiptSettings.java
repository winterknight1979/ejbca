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
 * hard token profile contain a reciept that may contain policy and the users
 * hand signature.
 *
 * @version $Id: IReceiptSettings.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public interface IReceiptSettings {

  /** Constant indicating that no recepit should be printed. */
  int RECEIPTTYPE_NONE = 0;
  /**
   * Constants indicating what type of receipt that should be should be printed.
   */
  int RECEIPTTYPE_GENERAL = 1;

  /** @return the type of receipt to print. */
  int getReceiptType();

  /** @param type sets the receipt type. */
  void setReceiptType(int type);

  /** @return the filename of the current visual layout template. */
  String getReceiptTemplateFilename();

  /**
   * @param filename Sets the filename of the current visual layout template.
   */
  void setReceiptTemplateFilename(String filename);

  /** @return the image data of the receipt, should be a SVG image. */
  String getReceiptData();

  /** @param templatedata Sets the imagedata of the receipt. */
  void setReceiptData(String templatedata);

  /** @return the number of copies of this receipt that should be printed. */
  int getNumberOfReceiptCopies();

  /**
   * @param copies Sets the number of copies of this receipt that should be
   *     printed.
   */
  void setNumberOfReceiptCopies(int copies);

  /**
   * Method that parses the template, replaces the userdata and returning a
   * printable byte array.
   *
   * @param userdata User
   * @param pincodes PIN
   * @param pukcodes PUK
   * @param hardtokensn SN
   * @param copyoftokensn SN
   * @return Receipt
   * @throws IOException IO fail
   * @throws PrinterException Print fail
   */
  Printable printReceipt(
      EndEntityInformation userdata,
      String[] pincodes,
      String[] pukcodes,
      String hardtokensn,
      String copyoftokensn)
      throws IOException, PrinterException;
}
