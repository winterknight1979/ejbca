package org.ejbca.core.protocol.cmp;

public final class CmpPKIBodyConstants {
  // Message-specific body elements from RFC 4210
      /** Param. */
  public static final int INITIALIZATIONREQUEST = 0; // Initialization Request
  /** Param. */
  public static final int INITIALIZATIONRESPONSE = 1; // Initialization Response
  /** Param. */
  public static final int CERTIFICATAIONREQUEST = 2; // Certification Request
  /** Param. */
  public static final int CERTIFICATIONRESPONSE = 3; // Certification Response
  /** Param. */
  public static final int IMPORTEDFROMPKCS10 = 4; // imported from [PKCS10]
  /** Param. */
  public static final int POPCHALLENGE = 5; // pop Challenge
  /** Param. */
  public static final int POPRESPONSE = 6; // pop Response
  /** Param. */
  public static final int KEYUPDATEREQUEST = 7; // Key Update Request
  /** Param. */
  public static final int KEYUPDATERESPONSE = 8; // Key Update Response
  /** Param. */
  public static final int KEYRECOVERYREQUEST = 9; // Key Recovery Request
  /** Param. */
  public static final int KEYRECOEVRYRESPONSE = 10; // Key Recovery Response
  /** Param. */
  public static final int REVOCATIONREQUEST = 11; // Revocation Request
  /** Param. */
  public static final int REVOCATIONRESPONSE = 12; // Revocation Response
  /** Param. */
  public static final int CROSSCERTREQUEST = 13; // Cross-Cert. Request
  /** Param. */
  public static final int CROSSCERTRESPONSE = 14; // Cross-Cert. Response
  /** Param. */
  public static final int CAKEYUPDATEANN = 15; // CA Key Update Ann.
  /** Param. */
  public static final int CERTIFICATEANN = 16; // Certificate Ann.
  /** Param. */
  public static final int REVOCATIONANN = 17; // Revocation Ann.
  /** Param. */
  public static final int CRLANNOUNCEMENT = 18; // CRL Announcement
  /** Param. */
  public static final int CONFIRMATION = 19; // Confirmation
  /** Param. */
  public static final int NESTEDMESSAGE = 20; // Nested Message
  /** Param. */
  public static final int GENERALMESSAGE = 21; // General Message
  /** Param. */
  public static final int GENERALRESPONSE = 22; // General Response
  /** Param. */
  public static final int ERRORMESSAGE = 23; // Error Message
  /** Param. */
  public static final int CERTIFICATECONFIRM = 24; // Certificate confirm
  /** Param. */
  public static final int POLLINGREQUEST = 25; // Polling request
  /** Param. */
  public static final int POLLINGRESPONSE = 26; // Polling response

  private CmpPKIBodyConstants() { }
}
