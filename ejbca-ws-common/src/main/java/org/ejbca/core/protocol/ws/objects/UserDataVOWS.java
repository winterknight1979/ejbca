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

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;

/**
 * Class used to represent userdata in the WebService API. Is used instead of
 * EndEntityInformation because of profilenames is used instead of id's.<br>
 * Example code:
 *
 * <pre>
 *   UserDataVOWS user = new UserDataVOWS ();
 *   user.setUsername ("tester");
 *   user.setPassword ("foo123");
 *   user.setClearPwd (false);
 *   user.setSubjectDN ("CN=Tester,C=SE");
 *   user.setCaName ("ManagementCA");
 *   user.setEmail (null);
 *   user.setSubjectAltName (null);
 *   user.setStatus (EndEntityConstants.STATUS_NEW);
 *   user.setTokenType (UserDataVOWS.TOKEN_TYPE_USERGENERATED);
 *   user.setEndEntityProfileName ("EMPTY");
 *   user.setCertificateProfileName ("ENDUSER");
 *
 *   List&lt;ExtendedInformationWS&gt; ei =
 *   new ArrayList&lt;ExtendedInformationWS&gt; ();
 *   ei.add(new ExtendedInformationWS (ExtendedInformation.
 *   CUSTOMDATA+ExtendedInformation.CUSTOM_REVOCATIONREASON,
 *   Integer.toString(RevokeStatus.REVOKATION_REASON_CERTIFICATEHOLD)));
 *   ei.add(new ExtendedInformationWS (ExtendedInformation.SUBJECTDIRATTRIBUTES,
 *    "DATEOFBIRTH=19761123"));
 *   user.setExtendedInformation(ei);
 * </pre>
 *
 * @version $Id: UserDataVOWS.java 26145 2017-07-10 10:45:12Z mikekushner $
 */
public class UserDataVOWS implements Serializable {

  private static final long serialVersionUID = 7557071186257332026L;
  /** Param. */
  public static final String TOKEN_TYPE_USERGENERATED = "USERGENERATED";
  /** Param. */
  public static final String TOKEN_TYPE_JKS = "JKS";
  /** Param. */
  public static final String TOKEN_TYPE_PEM = "PEM";
  /** Param. */
  public static final String TOKEN_TYPE_P12 = "P12";

  /** Param. */
  private String username = null;
  /** Param. */
  private String password = null;
  /** Param. */
  private boolean clearPwd = false;
  /** Param. */
  private String subjectDN = null;
  /** Param. */
  private String caName = null;
  /** Param. */
  private String subjectAltName = null;
  /** Param. */
  private String email = null;
  /** Param. */
  private int status = 0;
  /** Param. */
  private String tokenType = null;
  /** Param. */
  private boolean sendNotification = false;
  /** Param. */
  private boolean keyRecoverable = false;
  /** Param. */
  private String endEntityProfileName = null;
  /** Param. */
  private String certificateProfileName = null;
  /** Param. */
  private String hardTokenIssuerName = null;
  /** Param. */
  private String startTime = null;
  /** Param. */
  private String endTime = null;
  /** Param. */
  private BigInteger certificateSerialNumber;
  /** Param. */
  private List<ExtendedInformationWS> extendedInformation = null;
  /** Param. */
  private String cardNumber;

  /** Emtpy constructor used by internally by web services. */
  public UserDataVOWS() { }

  /**
   * Constructor used when creating a new UserDataVOWS.
   *
   * @param ausername the unique username if the user, used internally in EJBCA
   * @param apassword password u sed to lock the keystore
   * @param aclearPwd true if password should be in clear
   * @param asubjectDN of
   * @param acaName the name of the CA used in the EJBCA web gui.
   * @param asubjectAltName Name
   * @param anemail Email
   * @param astatus one of the STATUS_ constants
   * @param atokenType type of token, one of TOKEN_TYPE constants for soft
   *     tokens, for hard ones use hardtokenprofilename
   * @param anendEntityProfileName Profile
   * @param acertificateProfileName Profile
   * @param ahardTokenIssuerName if no hardTokenIssuer should be used then use
   *     null.
   */
  public UserDataVOWS(
      String ausername,
      String apassword,
      boolean aclearPwd,
      String asubjectDN,
      String acaName,
      String asubjectAltName,
      String anemail,
      int astatus,
      String atokenType,
      String anendEntityProfileName,
      String acertificateProfileName,
      String ahardTokenIssuerName) {
    super();
    this.username = ausername;
    this.password = apassword;
    this.clearPwd = aclearPwd;
    this.subjectDN = asubjectDN;
    this.caName = acaName;
    this.subjectAltName = asubjectAltName;
    this.email = anemail;
    this.status = astatus;
    this.tokenType = atokenType;
    this.endEntityProfileName = anendEntityProfileName;
    this.certificateProfileName = acertificateProfileName;
    this.hardTokenIssuerName = ahardTokenIssuerName;
  }

  /** @return true if the user is keyrecoverable */
  public boolean isKeyRecoverable() {
    return this.keyRecoverable;
  }

  /**
   * indicates if the users keys should be keyrecoverable.
   *
   * @param keyrecoverable bool
   */
  public void setKeyRecoverable(boolean keyrecoverable) {
    this.keyRecoverable = keyrecoverable;
  }

  /**
   * If true notifications will be sent to the user.
   *
   * @return bool
   */
  public boolean isSendNotification() {
    return sendNotification;
  }

  /**
   * set to true if notifications should be sent to the user.
   *
   * @param sendnotification bool
   */
  public void setSendNotification(boolean sendnotification) {
    this.sendNotification = sendnotification;
  }

  /** @return Returns the cAName. */
  public String getCaName() {
    return caName;
  }

  /** @return Returns the certificateProfileName. */
  public String getCertificateProfileName() {
    return certificateProfileName;
  }

  /** @return Returns the email. */
  public String getEmail() {
    return email;
  }

  /** @return Returns the endEntityProfileName. */
  public String getEndEntityProfileName() {
    return endEntityProfileName;
  }

  /** @return Returns the hardTokenIssuerName. */
  public String getHardTokenIssuerName() {
    return hardTokenIssuerName;
  }

  /**
   * Observe when sending userdata to clients outside EJBCA will the password
   * always be null.
   *
   * @return Returns the password.
   */
  public String getPassword() {
    return password;
  }

  /**
   * Observe sending usedata to clients outside EJBCA will always return false.
   *
   * @return Returns the clearpwd.
   */
  public boolean isClearPwd() {
    return clearPwd;
  }

  /** @return Returns the status. */
  public int getStatus() {
    return status;
  }

  /** @return Returns the subjecDN. */
  public String getSubjectDN() {
    return subjectDN;
  }

  /** @return Returns the subjectAltName. */
  public String getSubjectAltName() {
    return subjectAltName;
  }

  /**
   * @return Returns the tokenType. One of TOKEN_TYPE constants for soft tokens,
   *     for hard ones use hardtokenprofilename
   */
  public String getTokenType() {
    return tokenType;
  }

  /** @return Returns the type. */
  public EndEntityType getType() {
    EndEntityType type = new EndEntityType(EndEntityTypes.ENDUSER);

    if (sendNotification) {
      type.addType(EndEntityTypes.SENDNOTIFICATION);
    } else {
      type.removeType(EndEntityTypes.SENDNOTIFICATION);
    }
    if (keyRecoverable) {
      type.addType(EndEntityTypes.KEYRECOVERABLE);
    } else {
      type.removeType(EndEntityTypes.KEYRECOVERABLE);
    }
    return type;
  }

  /** @return Returns the username. */
  public String getUsername() {
    return username;
  }

  /** @param name The caName to set. */
  public void setCaName(String name) {
    caName = name;
  }

  /** @param acertificateProfileName The certificateProfileName to set. */
  public void setCertificateProfileName(String acertificateProfileName) {
    this.certificateProfileName = acertificateProfileName;
  }

  /** @param aclearPwd The clearpwd to set. */
  public void setClearPwd(boolean aclearPwd) {
    this.clearPwd = aclearPwd;
  }

  /** @param anemail The email to set. */
  public void setEmail(String anemail) {
    this.email = anemail;
  }

  /** @param anendEntityProfileName The endEntityProfileName to set. */
  public void setEndEntityProfileName(String anendEntityProfileName) {
    this.endEntityProfileName = anendEntityProfileName;
  }

  /** @param ahardTokenIssuerName The hardTokenIssuerName to set. */
  public void setHardTokenIssuerName(String ahardTokenIssuerName) {
    this.hardTokenIssuerName = ahardTokenIssuerName;
  }

  /** @param apassword The password to set. */
  public void setPassword(String apassword) {
    this.password = apassword;
  }

  /** @param astatus The status to set. */
  public void setStatus(int astatus) {
    this.status = astatus;
  }

  /** @param asubjectAltName The subjectAltName to set. */
  public void setSubjectAltName(String asubjectAltName) {
    this.subjectAltName = asubjectAltName;
  }

  /** @param asubjectDN The subjectDN to set. */
  public void setSubjectDN(String asubjectDN) {
    this.subjectDN = asubjectDN;
  }

  /** @param atokenType The tokenType to set. */
  public void setTokenType(String atokenType) {
    this.tokenType = atokenType;
  }

  /** @param ausername The username to set. */
  public void setUsername(String ausername) {
    this.username = ausername;
  }

  /** @return the startTime */
  public String getStartTime() {
    return this.startTime;
  }

  /** @param astartTime the startTime to set */
  public void setStartTime(String astartTime) {
    this.startTime = astartTime;
  }

  /** @return the endTime */
  public String getEndTime() {
    return this.endTime;
  }

  /** @param anendTime the endTime to set */
  public void setEndTime(String anendTime) {
    this.endTime = anendTime;
  }

  /** @return certificate serial number. */
  public BigInteger getCertificateSerialNumber() {
    return this.certificateSerialNumber;
  }

  /**
   * @param sn Serial number of the certificate to be generated. Only used if
   *     'Allow certificate serial number override' in used certificate profile
   *     is enabled.
   */
  public void setCertificateSerialNumber(BigInteger sn) {
    this.certificateSerialNumber = sn;
  }

  /** @return optional extended information list */
  public List<ExtendedInformationWS> getExtendedInformation() {
    return extendedInformation;
  }

  /**
   * Generic setter for extendedInformation. Set with values from
   * ExtendedInformation such as: ExtendedInformation.CUSTOM_REVOCATIONREASON,
   * Integer.toString(RevokeStatus.REVOCATION_REASON_CERTIFICATEHOLD)
   *
   * @param theextendedInformation info
   */
  public void setExtendedInformation(
      List<ExtendedInformationWS> theextendedInformation) {
    this.extendedInformation = theextendedInformation;
  }

  /** @return card number */
  public String getCardNumber() {
    return cardNumber;
  }

  /**
   * Sets the card number for the cardnumber extension. Only used if 'Card
   * Number Extension' in used certificate profile is enabled.
   *
   * @param acardNumber The card number to set
   */
  public void setCardNumber(String acardNumber) {
    this.cardNumber = acardNumber;
  }
}
