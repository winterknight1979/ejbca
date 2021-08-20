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
import org.cesecore.util.StringUtil;

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
  /** Config. */
  public static final int NO_ENDENTITYPROFILE = 0;
  /** Config. */
  public static final int NO_CERTIFICATEPROFILE = 0;

  /** PAram. */
  private String username;
  /** PAram. */
  private String subjectDN;
  /** PAram. */
  private transient String subjectDNClean = null;
  /** PAram. */
  private int caid;
  /** PAram. */
  private String subjectAltName;
  /** PAram. */
  private String subjectEmail;
  /** PAram. */
  private String password;
  /** PAram. */
  private String cardNumber;
  /** Status of user, from EndEntityConstants.STATUS_XX. */
  private int status;
  /** Type of user, from SecConst. */
  private EndEntityType type = EndEntityTypes.INVALID.toEndEntityType();

  /** PAram. */
  private int endentityprofileid;
  /** PAram. */
  private int certificateprofileid;
  /** PAram. */
  private Date timecreated;
  /** PAram. */
  private Date timemodified;
  /** PAram. */
  private int tokentype;
  /** PAram. */
  private int hardtokenissuerid;
  /** PAram. */
  private ExtendedInformation extendedinformation;

  /** Creates new empty UserDataVO. */
  public UserDataVO() { }

  /**
   * Creates new UserDataVO. All fields are almost required in this constructor.
   * Password must be set manually though. This is so you should be sure what
   * you do with the password.
   *
   * @param user DOCUMENT ME!
   * @param dn DOCUMENT ME!
   * @param acaid CA id of the CA that the user is registered with
   * @param asubjectaltname DOCUMENT ME!
   * @param anemail DOCUMENT ME!
   * @param astatus DOCUMENT ME!
   * @param atype one of SecConst.ENDUSER || ...
   * @param anendentityprofileid DOCUMENT ME!
   * @param acertificateprofileid DOCUMENT ME!
   * @param thetimecreated DOCUMENT ME!
   * @param thetimemodified DOCUMENT ME!
   * @param atokentype DOCUMENT ME!
   * @param ahardtokenissuerid DOCUMENT ME!
   * @param extendedinfo Info
   */
  public UserDataVO(
      final String user,
      final String dn,
      final int acaid,
      final String asubjectaltname,
      final String anemail,
      final int astatus,
      final EndEntityType atype,
      final int anendentityprofileid,
      final int acertificateprofileid,
      final Date thetimecreated,
      final Date thetimemodified,
      final int atokentype,
      final int ahardtokenissuerid,
      final ExtendedInformation extendedinfo) {
    setUsername(user);
    setPassword(null);
    setCardNumber(null);
    setDN(dn);
    setCAId(acaid);
    setSubjectAltName(asubjectaltname);
    setEmail(anemail);
    setStatus(astatus);
    setType(atype);
    setEndEntityProfileId(anendentityprofileid);
    setCertificateProfileId(acertificateprofileid);
    setTimeCreated(thetimecreated);
    setTimeModified(thetimemodified);
    setTokenType(atokentype);
    setHardTokenIssuerId(ahardtokenissuerid);
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
   * @param acaid CA id of the CA that the user is registered with
   * @param asubjectaltname DOCUMENT ME!
   * @param anemail DOCUMENT ME!
   * @param atype one of SecConst.ENDUSER || ...
   * @param anendentityprofileid DOCUMENT ME!
   * @param acertificateprofileid DOCUMENT ME!
   * @param atokentype DOCUMENT ME!
   * @param ahardtokenissuerid DOCUMENT ME!
   * @param extendedinfo Info
   */
  public UserDataVO(
      final String user,
      final String dn,
      final int acaid,
      final String asubjectaltname,
      final String anemail,
      final EndEntityType atype,
      final int anendentityprofileid,
      final int acertificateprofileid,
      final int atokentype,
      final int ahardtokenissuerid,
      final ExtendedInformation extendedinfo) {
    setUsername(user);
    setPassword(null);
    setDN(dn);
    setCAId(acaid);
    setSubjectAltName(asubjectaltname);
    setEmail(anemail);
    setType(atype);
    setEndEntityProfileId(anendentityprofileid);
    setCertificateProfileId(acertificateprofileid);
    setTokenType(atokentype);
    setHardTokenIssuerId(ahardtokenissuerid);
    setExtendedinformation(extendedinfo);
    setCardNumber(null);
  }

  /**
   * @param user user
   */
  public void setUsername(final String user) {
    this.username =
        StringUtil.putBase64String(StringUtil.stripUsername(user));
  }

  /**
   * @return user
   */
  public String getUsername() {
    return StringUtil.getBase64String(username);
  }

  /**
   * @param dn DN
   */
  public void setDN(final String dn) {
    final StringBuilder removedAllEmpties = new StringBuilder(dn.length());
    final StringBuilder removedTrailingEmpties =
        DNFieldsUtil.removeEmpties(dn, removedAllEmpties, true);
    if (removedTrailingEmpties == null) {
      this.subjectDNClean =
          StringUtil.putBase64String(removedAllEmpties.toString());
      this.subjectDN = this.subjectDNClean;
    } else {
      this.subjectDNClean =
          StringUtil.putBase64String(removedAllEmpties.toString());
      this.subjectDN =
          StringUtil.putBase64String(removedTrailingEmpties.toString());
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
    return StringUtil.getBase64String(subjectDN);
  }

  /**
   * @return ID
   */
  public int getCAId() {
    return this.caid;
  }

  /**
   * @param acaid ID
   */
  public void setCAId(final int acaid) {
    this.caid = acaid;
  }

  /**
   * @param subjectaltname name
   */
  public void setSubjectAltName(final String subjectaltname) {
    this.subjectAltName = StringUtil.putBase64String(subjectaltname);
  }

  /**
   * @return name
   */
  public String getSubjectAltName() {
    return StringUtil.getBase64String(subjectAltName);
  }

  /**
   * @param email email
   */
  public void setEmail(final String email) {
    this.subjectEmail = StringUtil.putBase64String(email);
  }

  /**
   * @return email
   */
  public String getEmail() {
    return StringUtil.getBase64String(subjectEmail);
  }

  /**
   * @param acardNumber num
   */
  public void setCardNumber(final String acardNumber) {
    this.cardNumber = StringUtil.putBase64String(acardNumber);
  }

  /**
   * @return num
   */
  public String getCardNumber() {
    return StringUtil.getBase64String(cardNumber);
  }

  /**
   * @param pwd pass
   */
  public void setPassword(final String pwd) {
    this.password = StringUtil.putBase64String(pwd);
  }

  /**
   * @return pass
   */
  public String getPassword() {
    return StringUtil.getBase64String(password);
  }

  /**
   * @param astatus status
   */
  public void setStatus(final int astatus) {
    this.status = astatus;
  }

  /**
   * @return status
   */
  public int getStatus() {
    return status;
  }

  /**
   * @param atype type
   */
  public void setType(final EndEntityType atype) {
    this.type = atype;
  }

  /**
   * @return type
   */
  public EndEntityType getType() {
    return type;
  }

  /**
   * @param anendentityprofileid ID
   */
  public void setEndEntityProfileId(final int anendentityprofileid) {
    this.endentityprofileid = anendentityprofileid;
  }

  /**
   * @return ID
   */
  public int getEndEntityProfileId() {
    return this.endentityprofileid;
  }

  /**
   * @param acertificateprofileid ID
   */
  public void setCertificateProfileId(final int acertificateprofileid) {
    this.certificateprofileid = acertificateprofileid;
  }

  /**
   * @return ID
   */
  public int getCertificateProfileId() {
    return this.certificateprofileid;
  }

  /**
   * @param thetimecreated time
   */
  public void setTimeCreated(final Date thetimecreated) {
    this.timecreated = thetimecreated;
  }

  /**
   * @return time
   */
  public Date getTimeCreated() {
    return this.timecreated;
  }

  /**
   * @param thetimemodified time
   */
  public void setTimeModified(final Date thetimemodified) {
    this.timemodified = thetimemodified;
  }

  /**
   * @return time
   */
  public Date getTimeModified() {
    return this.timemodified;
  }

  /**
   * @return type
   */
  public int getTokenType() {
    return this.tokentype;
  }

  /**
   * @param atokentype type
   */
  public void setTokenType(final int atokentype) {
    this.tokentype = atokentype;
  }

  /**
   * @return ID
   */
  public int getHardTokenIssuerId() {
    return this.hardtokenissuerid;
  }

  /**
   * @param ahardtokenissuerid ID
   */
  public void setHardTokenIssuerId(final int ahardtokenissuerid) {
    this.hardtokenissuerid = ahardtokenissuerid;
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

  /**
   * @return bool
   */
  public boolean getKeyRecoverable() {
    return type.contains(EndEntityTypes.KEYRECOVERABLE);
  }

  /**
   * @param keyrecoverable bool
   */
  public void setKeyRecoverable(final boolean keyrecoverable) {
    if (keyrecoverable) {
      type.addType(EndEntityTypes.KEYRECOVERABLE);
    } else {
      type.removeType(EndEntityTypes.KEYRECOVERABLE);
    }
  }
  /**
   * @return bool
   */
  public boolean getSendNotification() {
    return type.contains(EndEntityTypes.SENDNOTIFICATION);
  }

  /**
   * @param sendnotification bool
   */
  public void setSendNotification(final boolean sendnotification) {
    if (sendnotification) {
      type.addType(EndEntityTypes.SENDNOTIFICATION);
    } else {
      type.removeType(EndEntityTypes.SENDNOTIFICATION);
    }
  }

  /**
   * @return bool
   */
  public boolean getPrintUserData() {
    return type.contains(EndEntityTypes.PRINT);
  }

  /**
   * @param printUserData bool
   */
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
  /** @param theextendedinformation The extendedinformation to set. */
  public void setExtendedinformation(
      final ExtendedInformation theextendedinformation) {
    this.extendedinformation = theextendedinformation;
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
          default: break;
        }
      } catch (IOException e) {
        throw new RuntimeException(
            "Problems generating extended information from String", e);
      }
    }
    return returnval;
  }

  /**
   * @param extendedinformation info
   * @return data
   * @throws UnsupportedEncodingException fail
   */
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
      return StringUtil.getBase64String(subjectDNClean);
    }
  }

  /**
   * Helper method to convert this old deprecated type to the new
   * EndEntityInformation.
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
