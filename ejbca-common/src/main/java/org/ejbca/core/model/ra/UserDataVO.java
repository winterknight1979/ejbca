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

package org.ejbca.core.model.ra;

import java.beans.XMLEncoder;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;

/**
 * Holds admin data collected from UserData in the database. Strings are stored
 * in Base64 encoded format to be safe for storing in database, xml etc.
 *
 * <p>NOTE! This class is not to be extended anymore. It is kept for backwards
 * serialization compatibility only. use class EndEntityInformation instead.
 *
 * @version $Id: UserDataVO.java 34165 2020-01-02 15:18:44Z samuellb $
 * @deprecated Use org.cesecore.certificates.endentity.EndEntityInformation
 *     instead. Since EJBCA 5.0.0.
 */
public class UserDataVO implements Serializable {

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = 3837505643343885941L;

  // Public constants
  public static final int NO_ENDENTITYPROFILE = 0;
  public static final int NO_CERTIFICATEPROFILE = 0;

  private String username;
  private String subjectDN;
  private transient String subjectDNClean = null;
  private int caid;
  private String subjectAltName;
  private String subjectEmail;
  private String password;
  private String cardNumber;
  /** Status of user, from EndEntityConstants.STATUS_XX */
  private int status;
  /** Type of user, from SecConst */
  private EndEntityType type = EndEntityTypes.INVALID.toEndEntityType();

  private int endentityprofileid;
  private int certificateprofileid;
  private Date timecreated;
  private Date timemodified;
  private int tokentype;
  private int hardtokenissuerid;
  private ExtendedInformation extendedinformation;

  /** Creates new empty UserDataVO */
  public UserDataVO() {}

  /**
   * Creates new UserDataVO. All fields are almost required in this constructor.
   * Password must be set manually though. This is so you should be sure what
   * you do with the password.
   *
   * @param user DOCUMENT ME!
   * @param dn DOCUMENT ME!
   * @param caid CA id of the CA that the user is registered with
   * @param subjectaltname DOCUMENT ME!
   * @param email DOCUMENT ME!
   * @param status DOCUMENT ME!
   * @param type one of SecConst.ENDUSER || ...
   * @param endentityprofileid DOCUMENT ME!
   * @param certificateprofileid DOCUMENT ME!
   * @param timecreated DOCUMENT ME!
   * @param timemodified DOCUMENT ME!
   * @param tokentype DOCUMENT ME!
   * @param hardtokenissuerid DOCUMENT ME!
   * @param extendedinfo Info
   */
  public UserDataVO(
      final String user,
      final String dn,
      final int caid,
      final String subjectaltname,
      final String email,
      final int status,
      final EndEntityType type,
      final int endentityprofileid,
      final int certificateprofileid,
      final Date timecreated,
      final Date timemodified,
      final int tokentype,
      final int hardtokenissuerid,
      final ExtendedInformation extendedinfo) {
    setUsername(user);
    setPassword(null);
    setCardNumber(null);
    setDN(dn);
    setCAId(caid);
    setSubjectAltName(subjectaltname);
    setEmail(email);
    setStatus(status);
    setType(type);
    setEndEntityProfileId(endentityprofileid);
    setCertificateProfileId(certificateprofileid);
    setTimeCreated(timecreated);
    setTimeModified(timemodified);
    setTokenType(tokentype);
    setHardTokenIssuerId(hardtokenissuerid);
    setExtendedinformation(extendedinfo);
    setCardNumber(null);
  }

  /**
   * Creates new UserDataVO. This constructor should only be used from
   * UserDataSource implementations. Status and dates aren't used in these
   * cases.
   *
   * @param user DOCUMENT ME!
   * @param dn DOCUMENT ME!
   * @param caid CA id of the CA that the user is registered with
   * @param subjectaltname DOCUMENT ME!
   * @param email DOCUMENT ME!
   * @param type one of SecConst.ENDUSER || ...
   * @param endentityprofileid DOCUMENT ME!
   * @param certificateprofileid DOCUMENT ME!
   * @param tokentype DOCUMENT ME!
   * @param hardtokenissuerid DOCUMENT ME!
   * @param extendedinfo Info
   */
  public UserDataVO(
      final String user,
      final String dn,
      final int caid,
      final String subjectaltname,
      final String email,
      final EndEntityType type,
      final int endentityprofileid,
      final int certificateprofileid,
      final int tokentype,
      final int hardtokenissuerid,
      final ExtendedInformation extendedinfo) {
    setUsername(user);
    setPassword(null);
    setDN(dn);
    setCAId(caid);
    setSubjectAltName(subjectaltname);
    setEmail(email);
    setType(type);
    setEndEntityProfileId(endentityprofileid);
    setCertificateProfileId(certificateprofileid);
    setTokenType(tokentype);
    setHardTokenIssuerId(hardtokenissuerid);
    setExtendedinformation(extendedinfo);
    setCardNumber(null);
  }

  public void setUsername(final String user) {
    this.username =
        StringTools.putBase64String(StringTools.stripUsername(user));
  }

  public String getUsername() {
    return StringTools.getBase64String(username);
  }

  public void setDN(final String dn) {
    final StringBuilder removedAllEmpties = new StringBuilder(dn.length());
    final StringBuilder removedTrailingEmpties =
        DNFieldsUtil.removeEmpties(dn, removedAllEmpties, true);
    if (removedTrailingEmpties == null) {
      this.subjectDNClean =
          StringTools.putBase64String(removedAllEmpties.toString());
      this.subjectDN = this.subjectDNClean;
    } else {
      this.subjectDNClean =
          StringTools.putBase64String(removedAllEmpties.toString());
      this.subjectDN =
          StringTools.putBase64String(removedTrailingEmpties.toString());
    }
  }
  /**
   * User DN as stored in the database. If the registered DN has unused DN
   * fields the empty ones are kept, i.e. CN=Tomas,OU=,OU=PrimeKey,C=SE. See
   * ECA-1841 for an explanation of this. Use method getCertificateDN() to get
   * the DN stripped from empty fields.
   *
   * @see #getCertificateDN()
   * @return String with DN, might contain empty fields, use getCertificateDN to
   *     get without empty fields
   */
  public String getDN() {
    return StringTools.getBase64String(subjectDN);
  }

  public int getCAId() {
    return this.caid;
  }

  public void setCAId(final int caid) {
    this.caid = caid;
  }

  public void setSubjectAltName(final String subjectaltname) {
    this.subjectAltName = StringTools.putBase64String(subjectaltname);
  }

  public String getSubjectAltName() {
    return StringTools.getBase64String(subjectAltName);
  }

  public void setEmail(final String email) {
    this.subjectEmail = StringTools.putBase64String(email);
  }

  public String getEmail() {
    return StringTools.getBase64String(subjectEmail);
  }

  public void setCardNumber(final String cardNumber) {
    this.cardNumber = StringTools.putBase64String(cardNumber);
  }

  public String getCardNumber() {
    return StringTools.getBase64String(cardNumber);
  }

  public void setPassword(final String pwd) {
    this.password = StringTools.putBase64String(pwd);
  }

  public String getPassword() {
    return StringTools.getBase64String(password);
  }

  public void setStatus(final int status) {
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

  public void setType(final EndEntityType type) {
    this.type = type;
  }

  public EndEntityType getType() {
    return type;
  }

  public void setEndEntityProfileId(final int endentityprofileid) {
    this.endentityprofileid = endentityprofileid;
  }

  public int getEndEntityProfileId() {
    return this.endentityprofileid;
  }

  public void setCertificateProfileId(final int certificateprofileid) {
    this.certificateprofileid = certificateprofileid;
  }

  public int getCertificateProfileId() {
    return this.certificateprofileid;
  }

  public void setTimeCreated(final Date timecreated) {
    this.timecreated = timecreated;
  }

  public Date getTimeCreated() {
    return this.timecreated;
  }

  public void setTimeModified(final Date timemodified) {
    this.timemodified = timemodified;
  }

  public Date getTimeModified() {
    return this.timemodified;
  }

  public int getTokenType() {
    return this.tokentype;
  }

  public void setTokenType(final int tokentype) {
    this.tokentype = tokentype;
  }

  public int getHardTokenIssuerId() {
    return this.hardtokenissuerid;
  }

  public void setHardTokenIssuerId(final int hardtokenissuerid) {
    this.hardtokenissuerid = hardtokenissuerid;
  }

  /**
   * @return bool
   * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This
   *     method is still used for deserializing objects in
   *     CertReqHistoryDataBean.
   */
  public boolean getAdministrator() {
    return type.contains(EndEntityTypes.ADMINISTRATOR);
  }

  /**
   * @param administrator admin
   * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This
   *     method is still used for deserializing objects in
   *     CertReqHistoryDataBean.
   */
  public void setAdministrator(final boolean administrator) {
    if (administrator) {
      type.addType(EndEntityTypes.ADMINISTRATOR);
    } else {
      type.removeType(EndEntityTypes.ADMINISTRATOR);
    }
  }

  public boolean getKeyRecoverable() {
    return type.contains(EndEntityTypes.KEYRECOVERABLE);
  }

  public void setKeyRecoverable(final boolean keyrecoverable) {
    if (keyrecoverable) {
      type.addType(EndEntityTypes.KEYRECOVERABLE);
    } else {
      type.removeType(EndEntityTypes.KEYRECOVERABLE);
    }
  }

  public boolean getSendNotification() {
    return type.contains(EndEntityTypes.SENDNOTIFICATION);
  }

  public void setSendNotification(final boolean sendnotification) {
    if (sendnotification) {
      type.addType(EndEntityTypes.SENDNOTIFICATION);
    } else {
      type.removeType(EndEntityTypes.SENDNOTIFICATION);
    }
  }

  public boolean getPrintUserData() {
    return type.contains(EndEntityTypes.PRINT);
  }

  public void setPrintUserData(final boolean printUserData) {
    if (printUserData) {
      type.addType(EndEntityTypes.PRINT);
    } else {
      type.removeType(EndEntityTypes.PRINT);
    }
  }

  /**
   * @return Returns the extendedinformation or null if no extended information
   *     exists.
   */
  public ExtendedInformation getExtendedinformation() {
    return extendedinformation;
  }
  /** @param extendedinformation The extendedinformation to set. */
  public void setExtendedinformation(
      final ExtendedInformation extendedinformation) {
    this.extendedinformation = extendedinformation;
  }

  /**
   * Help Method used to create an ExtendedInformation from String
   * representation. Used when creating an ExtendedInformation from queries.
   *
   * @param extendedinfostring Info
   * @return Admin
   */
  public static ExtendedInformation getExtendedInformation(
      final String extendedinfostring) {
    ExtendedInformation returnval = null;
    if ((extendedinfostring != null) && (extendedinfostring.length() > 0)) {
      try (SecureXMLDecoder decoder =
          new SecureXMLDecoder(
              new java.io.ByteArrayInputStream(
                  extendedinfostring.getBytes(StandardCharsets.UTF_8)))) {
        @SuppressWarnings("rawtypes")
        HashMap h = (HashMap) decoder.readObject();
        // Handle Base64 encoded string values
        @SuppressWarnings("rawtypes")
        HashMap data = new Base64GetHashMap(h);
        int type = ((Integer) data.get(ExtendedInformation.TYPE)).intValue();
        switch (type) {
          case ExtendedInformation.TYPE_BASIC:
            returnval = new ExtendedInformation();
            returnval.loadData(data);
            break;
        }
      } catch (IOException e) {
        throw new RuntimeException(
            "Problems generating extended information from String", e);
      }
    }
    return returnval;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  public static String extendedInformationToStringData(
      final ExtendedInformation extendedinformation)
      throws UnsupportedEncodingException {
    String ret = null;
    if (extendedinformation != null) {
      // We must base64 encode string for UTF safety
      HashMap a = new Base64PutHashMap();
      a.putAll((HashMap) extendedinformation.saveData());
      java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
      try (XMLEncoder encoder = new XMLEncoder(baos)) {
        encoder.writeObject(a);
      }
      ret = baos.toString("UTF8");
    }
    return ret;
  }

  /**
   * Returns the DN to be used when creating a certificate (without empty
   * fields). If the registered DN has unused DN fields the empty ones are kept,
   * i.e. CN=Tomas,OU=,OU=PrimeKey,C=SE. See ECA-1841 for an explanation of
   * this. Use method getCertificateDN() to get the DN stripped from empty
   * fields, getDN() returns DN with empty fields.
   *
   * @see #getDN()
   * @return String with DN, with no empty fields, use getDN to get including
   *     empty fields
   */
  public String getCertificateDN() {
    if (subjectDNClean == null) {
      // This might be fetched from database serialization so we need to perform
      // the cleaning all over again
      return DNFieldsUtil.removeAllEmpties(getDN());
    } else {
      return StringTools.getBase64String(subjectDNClean);
    }
  }

  /**
   * Helper method to convert this old deprecated type to the new
   * EndEntityInformation
   *
   * @return EndEntityInformation
   */
  public EndEntityInformation toEndEntityInformation() {
    org.cesecore.certificates.endentity.ExtendedInformation newee = null;
    if (extendedinformation != null) {
      newee = new org.cesecore.certificates.endentity.ExtendedInformation();
      newee.loadData(extendedinformation.saveData());
    }
    EndEntityInformation eei =
        new EndEntityInformation(
            getUsername(),
            getDN(),
            caid,
            getSubjectAltName(),
            getEmail(),
            type,
            endentityprofileid,
            certificateprofileid,
            tokentype,
            hardtokenissuerid,
            newee);
    eei.setPassword(getPassword());
    eei.setCardNumber(getCardNumber());
    eei.setStatus(status);
    eei.setTimeCreated(timecreated);
    eei.setTimeModified(timemodified);
    eei.setTokenType(tokentype);
    eei.setHardTokenIssuerId(hardtokenissuerid);
    return eei;
  }
}
