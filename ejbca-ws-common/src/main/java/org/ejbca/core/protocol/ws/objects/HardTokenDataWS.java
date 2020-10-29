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

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * Value object containing WS representation of a hard token data it contains
 * information about PIN/PUK codes, hardtoken serial number certificate stored
 * on the card.
 *
 * @author Philip Vendil
 *     <p>$Id: HardTokenDataWS.java 19902 2014-09-30 14:32:24Z anatom $
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(
    name = "hardTokenDataWS",
    propOrder = {
      "certificates",
      "copies",
      "copyOfSN",
      "createTime",
      "encKeyKeyRecoverable",
      "hardTokenSN",
      "label",
      "modifyTime",
      "pinDatas",
      "tokenType"
    })
public class HardTokenDataWS {

      /** Param. */
  private int tokenType = 0;
  /** Param. */
  private String label = null;
  /** Param. */
  private String hardTokenSN = null;
  /** Param. */
  private String copyOfSN = null;
  /** Param. */
  private List<String> copies = new ArrayList<String>();
  /** Param. */
  private List<PinDataWS> pinDatas = new ArrayList<PinDataWS>();
  /** Param. */
  private List<Certificate> certificates = new ArrayList<Certificate>();

  /** Param. */
  @XmlSchemaType(name = "dateTime")
  private XMLGregorianCalendar createTime = null;

  /** Param. */
  @XmlSchemaType(name = "dateTime")
  private XMLGregorianCalendar modifyTime = null;

  /** Param. */
  private boolean encKeyKeyRecoverable = false;

  /** WS Constructor. */
  public HardTokenDataWS() { }

  /**
   * Constuctor of a HardTokenDataWS with all it fields. This constructor should
   * be used on the server side of EJBCA
   *
   * @param atokenType one of the TOKENTYPE_ constants
   * @param alabel indicating the use of the token, one of the LABEL_ constants
   * @param ahardTokenSN the SN of the hard token
   * @param acopyOfSN of this is a copy of another hard token, specify its SN
   *     otherwise use null.
   * @param thecopies if there is copies of this
   *     hard token a list of serial number
   *     is specified.
   * @param thepinDatas a List of pin datas with PIN and PUK
   * @param acertificates the certificate stored on the token
   * @param aencKeyKeyRecoverable if the token have a special encryption key it
   *     should be specified if it is recoverable or not.
   */
  public HardTokenDataWS(
      int atokenType,
      String alabel,
      String ahardTokenSN,
      String acopyOfSN,
      List<String> thecopies,
      List<PinDataWS> thepinDatas,
      List<Certificate> acertificates,
      boolean aencKeyKeyRecoverable) {
    super();
    this.tokenType = atokenType;
    this.label = alabel;
    this.hardTokenSN = ahardTokenSN;
    this.copyOfSN = acopyOfSN;
    this.copies = thecopies;
    this.pinDatas = thepinDatas;
    this.certificates = acertificates;
    this.encKeyKeyRecoverable = aencKeyKeyRecoverable;
  }

  /**
   * Constuctor that should be used with the genTokenCertificates request.
   *
   * @param atokenType one of the TOKENTYPE_ constants
   * @param alabel indicating the use of the token, one of the LABEL_ constants
   * @param ahardTokenSN the SN of the hard token
   * @param acopyOfSN of this is a copy of another hard token, specify its SN
   *     otherwise use null.
   * @param thepinDatas a List of pin datas with PIN and PUK
   * @param aencKeyKeyRecoverable if the token have a special encryption key it
   *     should be specified if it is recoverable or not.
   */
  public HardTokenDataWS(
      int atokenType,
      String alabel,
      String ahardTokenSN,
      String acopyOfSN,
      List<PinDataWS> thepinDatas,
      boolean aencKeyKeyRecoverable) {
    super();
    this.tokenType = atokenType;
    this.label = alabel;
    this.hardTokenSN = ahardTokenSN;
    this.copyOfSN = acopyOfSN;
    this.pinDatas = thepinDatas;
    this.encKeyKeyRecoverable = aencKeyKeyRecoverable;
  }

  /** @return a list WS representation of the stored certificates */
  public List<Certificate> getCertificates() {
    return certificates;
  }

  /** @param thecertificates a List of EJBCAWS
   *         Certificates stored on the token */
  public void setCertificates(List<Certificate>  thecertificates) {
    this.certificates = thecertificates;
  }

  /**
   * @return a list of hard token SN of copies that have been made of this
   *     token.
   */
  public List<String> getCopies() {
    return copies;
  }

  /**
   * @param thecopies a list of hard token SN of
   *     copies that have been made of this
   *     token.
   */
  public void setCopies(List<String> thecopies) {
    this.copies = thecopies;
  }

  /**
   * @return a serial number of which this token is a copy of, null if it isn't
   *     a copy
   */
  public String getCopyOfSN() {
    return copyOfSN;
  }

  /**
   * @param acopyOfSN a serial number of which this token is a copy of, null if
   *     it isn't a copy
   */
  public void setCopyOfSN(String acopyOfSN) {
    this.copyOfSN = acopyOfSN;
  }

  /**
   * @return true if the token have a separate encryption key and is key
   *     recoverable.
   */
  public boolean isEncKeyKeyRecoverable() {
    return encKeyKeyRecoverable;
  }

  /**
   * @param aencKeyKeyRecoverable if the token have a separate
   *     encryption key and is key recoverable.
   */
  public void setEncKeyKeyRecoverable(boolean aencKeyKeyRecoverable) {
    this.encKeyKeyRecoverable = aencKeyKeyRecoverable;
  }

  /** @return the serial number of the token */
  public String getHardTokenSN() {
    return hardTokenSN;
  }

  /** @param ahardTokenSN the serial number of the token */
  public void setHardTokenSN(String ahardTokenSN) {
    this.hardTokenSN = ahardTokenSN;
  }

  /** @return list of PIN data containing PIN and PUK of the */
  public List<PinDataWS> getPinDatas() {
    return pinDatas;
  }

  /** @param apinDatas list of PIN data containing PIN and PUK of the */
  public void setPinDatas(List<PinDataWS> apinDatas) {
    this.pinDatas = apinDatas;
  }

  /** @return one of the TOKENTYPE_ constants */
  public int getTokenType() {
    return tokenType;
  }

  /** @param atokenType one of the TOKENTYPE_ constants */
  public void setTokenType(int atokenType) {
    this.tokenType = atokenType;
  }

  /**
   * @return the label indicating the use of the token, one of the LABEL_
   *     constants
   */
  public String getLabel() {
    return label;
  }

  /**
   * @param alabel indicating the use of the token, one of the LABEL_ constants
   */
  public void setLabel(String alabel) {
    this.label = alabel;
  }

  /** @return Returns the time this token was created */
  public XMLGregorianCalendar getCreateTime() {
    return createTime;
  }

  /**
   * @param acreateTime time
   */
  public void setCreateTime(XMLGregorianCalendar acreateTime) {
    this.createTime = acreateTime;
  }

  /** @return Returns the time this last was modified. */
  public XMLGregorianCalendar getModifyTime() {
    return modifyTime;
  }

  /**
   * @param amodifyTime time
   */
  public void setModifyTime(XMLGregorianCalendar amodifyTime) {
    this.modifyTime = amodifyTime;
  }
}
