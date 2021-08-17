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

/**
 * Object identifiers for the CVC library.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public final class CVCObjectIdentifierConstants {

  //    From BSI Technical Guideline TR-03111:
  //    bsi-de OBJECT IDENTIFIER ::= {
  //      itu-t(0) identified-organization(4) etsi(0)
  //      reserved(127) etsi-identified-organization(0) 7
  //    }

  //    From BSI Technical Guideline TR-03110:
  //    id-TA OBJECT IDENTIFIER ::= {
  //      bsi-de protocols(2) smartcard(2) 2
  //    }
  //
      /** Param. */
  public static final String BSI_DE = "0.4.0.127.0.7";
  /** Param. */
  public static final String ID_TA = BSI_DE + ".2.2.2";
  /** Param. */
  public static final String ID_TA_RSA = ID_TA + ".1";

  /** Param. */
  public static final OIDField ID_TA_RSA_V1_5_SHA_1 =
      new OIDField(ID_TA_RSA + ".1");
  /** Param. */
  public static final OIDField ID_TA_RSA_V1_5_SHA_256 =
      new OIDField(ID_TA_RSA + ".2");
  /** Param. */
  public static final OIDField ID_TA_RSA_V1_5_SHA_512 =
      new OIDField(ID_TA_RSA + ".5");
  /** Param. */
  public static final OIDField ID_TA_RSA_PSS_SHA_1 =
      new OIDField(ID_TA_RSA + ".3");
  /** Param. */
  public static final OIDField ID_TA_RSA_PSS_SHA_256 =
      new OIDField(ID_TA_RSA + ".4");
  /** Param. */
  public static final OIDField ID_TA_RSA_PSS_SHA_512 =
      new OIDField(ID_TA_RSA + ".6");

  /** Param. */
  public static final String ID_TA_ECDSA = ID_TA + ".2";
  /** Param. */
  public static final OIDField ID_TA_ECDSA_SHA_1 =
      new OIDField(ID_TA_ECDSA + ".1");
  /** Param. */
  public static final OIDField ID_TA_ECDSA_SHA_224 =
      new OIDField(ID_TA_ECDSA + ".2");
  /** Param. */
  public static final OIDField ID_TA_ECDSA_SHA_256 =
      new OIDField(ID_TA_ECDSA + ".3");
  /** Param. */
  public static final OIDField ID_TA_ECDSA_SHA_384 =
      new OIDField(ID_TA_ECDSA + ".4");
  /** Param. */
  public static final OIDField ID_TA_ECDSA_SHA_512 =
      new OIDField(ID_TA_ECDSA + ".5");

  //  id-EAC-ePassport OBJECT IDENTIFIER ::= {
  //      bsi-de applications(3) mrtd(1) roles(2) 1
  //  }
  /** Param. */
  public static final OIDField ID_EAC_PASSPORT =
      new OIDField(BSI_DE + ".3.1.2.1");
  /** Param. */
  public static final OIDField ID_EAC_ROLES_AT =
      new OIDField(BSI_DE + ".3.1.2.2");
  /** Param. */
  public static final OIDField ID_EAC_ROLES_ST =
      new OIDField(BSI_DE + ".3.1.2.3");

  private CVCObjectIdentifierConstants() { }
}
