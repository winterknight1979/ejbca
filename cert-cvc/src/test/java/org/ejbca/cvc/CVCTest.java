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

import java.text.DateFormat;
import java.text.SimpleDateFormat;

/**
 * A collection of constants.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public interface CVCTest {

      /** Param. */
  String CA_COUNTRY_CODE = "SE";
  /** Param. */
  String CA_HOLDER_MNEMONIC = "CVCA-RPS";
  /** Param. */
  String CA_SEQUENCE_NO = "00111";

  /** Param. */
  String HR_COUNTRY_CODE = "SE";
  /** Param. */
  String HR_HOLDER_MNEMONIC = "IS-ABSP08";
  /** Param. */
  String HR_SEQUENCE_NO = "SE801";

  /** Param. */
  DateFormat FORMAT_PRINTABLE = new SimpleDateFormat("yyyy-MM-dd");
}
