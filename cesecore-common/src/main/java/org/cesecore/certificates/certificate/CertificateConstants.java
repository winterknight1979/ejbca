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

package org.cesecore.certificates.certificate;

/**
 * Constants for users and certificates. Constants for Type of user: Type is
 * constructed as a mask since one user can be of several types. To test a user
 * type:
 *
 * <pre>
 * if (((type &amp; USER_ENDUSER) == USER_ENDUSER) &amp;&amp;
 *     ((type &amp; USER_CAADMIN) == USER_ADMINISTOR) || ...
 *    ...
 * </pre>
 *
 * Bit usage: bits 0-7 (1:st byte): user types bits 8-15 (2:nd byte): unused
 * bits 16-23 (3:rd byte): unused bits 24-30 (4:th byte): unused Constants for
 * certificates are simple integer types. Constants for Token Types Token type
 * is constructed of integer constants since only one token type can be
 * generated.
 *
 * <p>Based on EJBCA (SecConst) version: SecConst.java 9321 2010-06-30 12:49:32Z
 * jeklund
 *
 * @version $Id: CertificateConstants.java 30396 2018-11-05 17:00:50Z
 *     mikekushner $
 */
public final class CertificateConstants {

  // Certificate status representations
  /** Certificate doesn't belong to anyone. */
  public static final int CERT_UNASSIGNED = 0;
  /** Assigned, but not yet active. */
  public static final int CERT_INACTIVE = 10;
  /**
   * Certificate is a new CA certificate which will become valid in the future.
   */
  public static final int CERT_ROLLOVERPENDING = 11;
  /** Certificate is active and assigned. */
  public static final int CERT_ACTIVE = 20;
  /**
   * Certificate is still active and the user is notified that it will soon
   * expire.
   */
  public static final int CERT_NOTIFIEDABOUTEXPIRATION = 21;
  // there was previously a status 30, CERT_TEMP_REVOKED here as well, but it
  // was not used so
  // it was removed to avoid misunderstandings.
  /** Certificate is blocked (can be permanently or temporarily). */
  public static final int CERT_REVOKED = 40;
  // there was previously a status 50, EXPIRED here as well, but it was not used
  // so
  // it was removed to avoid misunderstandings.
  /** Certificate is expired and kept for archive purpose. */
  public static final int CERT_ARCHIVED = 60;

  // Constants used in certificate generation and publication.
  /** Certificate type is unknown. */
  public static final int CERTTYPE_UNKNOWN = 0x0;
  /** Certificate belongs to an end entity. */
  public static final int CERTTYPE_ENDENTITY = 0x1;
  /** Certificate belongs to a sub ca. */
  public static final int CERTTYPE_SUBCA = 0x2;
  /** Certificate belongs to a root ca. */
  public static final int CERTTYPE_ROOTCA = 0x8;
  /** Certificate belongs on a hard token. */
  public static final int CERTTYPE_HARDTOKEN = 0x16;

  // Certificate types used to create certificates
  /** Certificate used for encryption. */
  public static final int CERT_TYPE_ENCRYPTION = 0x1;
  /** Certificate used for digital signatures. */
  public static final int CERT_TYPE_SIGNATURE = 0x2;
  /** Certificate used for both encryption and signatures. */
  public static final int CERT_TYPE_ENCSIGN = 0x3;

  // Certificate request types
  /** PKCS#10. */
  public static final int CERT_REQ_TYPE_PKCS10 = 0;
  /** CMRF. */
  public static final int CERT_REQ_TYPE_CRMF = 1;
  /** SPKAC. */
  public static final int CERT_REQ_TYPE_SPKAC = 2;
  /** Public key. */
  public static final int CERT_REQ_TYPE_PUBLICKEY = 3;
  /** CVC. */
  public static final int CERT_REQ_TYPE_CVC = 4;

  // Certificate response types
  /** Single non-PKCS cert. */
  public static final int CERT_RES_TYPE_CERTIFICATE = 0;
  /** PKCS#7 single cert. */
  public static final int CERT_RES_TYPE_PKCS7 = 1;
  /** PKCS#7 Chain. */
  public static final int CERT_RES_TYPE_PKCS7WITHCHAIN = 2;

  /* KeyUsage constants */
  /** Signature. */
  public static final int DIGITALSIGNATURE = 0;
  /** Nonrepudiation. */
  public static final int NONREPUDIATION = 1;
  /** Incrypt keys. */
  public static final int KEYENCIPHERMENT = 2;
  /** Encrypt data. */
  public static final int DATAENCIPHERMENT = 3;
  /** Key agreement. */
  public static final int KEYAGREEMENT = 4;
  /** Sign certificates. */
  public static final int KEYCERTSIGN = 5;
  /** Sign CRLs. */
  public static final int CRLSIGN = 6;
  /** Only encrypt. */
  public static final int ENCIPHERONLY = 7;
  /** Only decrypt. */
  public static final int DECIPHERONLY = 8;
  /** Boundary. */
  public static final int HIGN_REASON_BOUNDRARY = 11;

  /** Prevents creation of new class. */
  private CertificateConstants() { }
}
