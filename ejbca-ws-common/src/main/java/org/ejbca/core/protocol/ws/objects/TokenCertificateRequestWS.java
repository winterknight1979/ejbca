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

import java.io.IOException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * Base class this is a ITokenCertificateRequest, either a PKCS10 or KeyStore
 * defined by the type field.
 *
 * @version $Id: TokenCertificateRequestWS.java 24737 2016-11-15 13:53:25Z
 *     anatom $
 */
public class TokenCertificateRequestWS {

      /** Param. */
  private String cAName = null;
  /** Param. */
  private String certificateProfileName = null;
  /** Param. */
  private String validityIdDays = null;
  /** Param. */
  private int type = 0;
  /** Param. */
  private byte[] pkcs10Data = null;
  /** Param. */
  private String tokenType = HardTokenConstants.TOKENTYPE_PKCS12;
  /** Param. */
  private String keyspec = "1024";
  /** Param. */
  private String keyalg = "RSA";

  /**
   * @param name name
   * @param acertificateProfileName profile
   * @param avalidityIdDays days
   * @param pkcs10 PKCS req
   * @throws IOException fail
   */
  public TokenCertificateRequestWS(
      String name,
      String acertificateProfileName,
      String avalidityIdDays,
      PKCS10CertificationRequest pkcs10)
      throws IOException {
    super();
    type = HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST;
    cAName = name;
    this.validityIdDays = avalidityIdDays;
    this.certificateProfileName = acertificateProfileName;
    this.pkcs10Data = pkcs10.getEncoded();
  }

  /**
   * @param aname name
   * @param acertificateProfileName profile
   * @param avalidityIdDays days
   * @param atokenType type
   * @param akeyspec spec
   * @param akeyalg algo
   */
  public TokenCertificateRequestWS(
      String aname,
      String acertificateProfileName,
      String avalidityIdDays,
      String atokenType,
      String akeyspec,
      String akeyalg) {
    super();
    type = HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST;
    cAName = aname;
    this.validityIdDays = avalidityIdDays;
    this.certificateProfileName = acertificateProfileName;
    this.tokenType = atokenType;
    this.keyspec = akeyspec;
    this.keyalg = akeyalg;
  }

  /** WS Constructor. */
  public TokenCertificateRequestWS() {
    super();
  }

  /**
   * @return name
   */
  public String getCAName() {
    return cAName;
  }

  /**
   * @param aname name
   */
  public void setCAName(String aname) {
    cAName = aname;
  }

  /**
   * @return name
   */
  public String getCertificateProfileName() {
    return certificateProfileName;
  }

  /**
   * @param acertificateProfileName name
   */
  public void setCertificateProfileName(String acertificateProfileName) {
    this.certificateProfileName = acertificateProfileName;
  }

  /**
   * @return alg
   */
  public String getKeyalg() {
    return keyalg;
  }

  /**
   * @param akeyalg alg
   */
  public void setKeyalg(String akeyalg) {
    this.keyalg = akeyalg;
  }

  /**
   * @return spec
   */
  public String getKeyspec() {
    return keyspec;
  }

  /**
   * @param akeyspec spec
   */
  public void setKeyspec(String akeyspec) {
    this.keyspec = akeyspec;
  }

  /**
   * @return data
   */
  public byte[] getPkcs10Data() {
    return pkcs10Data;
  }

  /**
   * @param thepkcs10Data data
   */
  public void setPkcs10Data(byte[] thepkcs10Data) {
    this.pkcs10Data = thepkcs10Data;
  }

  /**
   * @return typw
   */
  public String getTokenType() {
    return tokenType;
  }

  /**
   * @param atokenType type
   */
  public void setTokenType(String atokenType) {
    this.tokenType = atokenType;
  }

  /**
   * @return type
   */
  public int getType() {
    return type;
  }

  /**
   * @param atype type
   */
  public void setType(int atype) {
    this.type = atype;
  }

  /**
   * @return days
   */
  public String getValidityIdDays() {
    return validityIdDays;
  }

  /**
   * @param avalidityIdDays dys
   */
  public void setValidityIdDays(String avalidityIdDays) {
    this.validityIdDays = avalidityIdDays;
  }
}
