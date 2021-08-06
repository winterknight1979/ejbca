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
package org.cesecore.certificates.endentity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;

/**
 * Holds admin data collected from UserData in the database. Strings are stored
 * in Base64 encoded format to be safe for storing in database, xml etc.
 *
 * @version $Id: EndEntityInformation.java 34163 2020-01-02 15:00:17Z samuellb $
 */
public class EndEntityInformation implements Serializable {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(EndEntityInformation.class);

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = 3837505643343885941L;

  /** User. */
  private String username;
  /** DN. */
  private String subjectDN;
  /** Cleaned-up DN. */
  private transient String subjectDNClean = null;
  /** CA. */
  private int caid;
  /** Name. */
  private String subjectAltName;
  /** Email. */
  private String subjectEmail;
  /** Password. */
  private String password;
  /** Number. */
  private String cardNumber;
  /** Status of user, from {@link EndEntityConstants#STATUS_NEW} etc. */
  private int status;
  /** Type. */
  private int type;
  /** EE ID. */
  private int endentityprofileid;
  /** Cert ID. */
  private int certificateprofileid;
  /** Created. */
  private Date timecreated;
  /** Modified. */
  private Date timemodified;
  /** Type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc. */
  private int tokentype;

  /** Issuer ID. */
  private int hardtokenissuerid;
  /** ExtendedInformation holding extra data of the End entity. */
  private ExtendedInformation extendedinformation;
  /** Maz size of Extended Info buffer. */
  private static final int INFO_SIZE = 512;

  /** Creates new empty EndEntityInformation. */
  public EndEntityInformation() { }

  /**
   * Copy constructor for {@link EndEntityInformation}.
   *
   * @param endEntityInformation an end entity to copy
   */
  public EndEntityInformation(final EndEntityInformation endEntityInformation) {
    this.username = endEntityInformation.getUsername();
    this.subjectDN = endEntityInformation.getDN();
    this.caid = endEntityInformation.getCAId();
    this.subjectAltName = endEntityInformation.getSubjectAltName();
    this.subjectEmail = endEntityInformation.getEmail();
    this.password = endEntityInformation.getPassword();
    this.cardNumber = endEntityInformation.getCardNumber();
    this.status = endEntityInformation.getStatus();
    this.type = endEntityInformation.getType().getHexValue();
    this.tokentype = endEntityInformation.getTokenType();
    this.endentityprofileid = endEntityInformation.getEndEntityProfileId();
    this.certificateprofileid = endEntityInformation.getCertificateProfileId();
    this.timecreated = endEntityInformation.getTimeCreated();
    this.timemodified = endEntityInformation.getTimeModified();
    this.tokentype = endEntityInformation.getTokenType();
    this.extendedinformation =
        endEntityInformation.getExtendedInformation() != null
            ? new ExtendedInformation(
                endEntityInformation.getExtendedInformation())
            : null;
  }

  /**
   * Creates new EndEntityInformation. All fields are almost required in this
   * constructor. Password must be set manually though. This is so you should be
   * sure what you do with the password.
   *
   * @param ausername the unique username.
   * @param dn the DN the subject is given in his certificate.
   * @param acaid CA id of the CA that the user is registered with
   * @param subjectaltname the Subject Alternative Name to be used.
   * @param email the email of the subject (may be null).
   * @param astatus Status of user, from {@link EndEntityConstants#STATUS_NEW}
   *     etc
   * @param atype Type of user, from {@link EndEntityTypes#ENDUSER} etc, can be
   *     "or:ed" together, i.e. EndEntityTypes#ENDUSER | {@link
   *     EndEntityTypes#SENDNOTIFICATION}
   * @param aendentityprofileid the id number of the end entity profile bound to
   *     this user.
   * @param acertificateprofileid the id number of the certificate profile that
   *     should be generated for the user.
   * @param atimecreated DOCUMENT ME!
   * @param atimemodified DOCUMENT ME!
   * @param atokentype the type of token, from {@link
   *     EndEntityConstants#TOKEN_USERGEN} etc
   * @param ahardtokenissuerid if token should be hard, the id of the hard token
   *     issuer, else 0.
   * @param extendedinfo info
   */
  public EndEntityInformation(// NOPMD: params
      final String ausername,
      final String dn,
      final int acaid,
      final String subjectaltname,
      final String email,
      final int astatus,
      final EndEntityType atype,
      final int aendentityprofileid,
      final int acertificateprofileid,
      final Date atimecreated,
      final Date atimemodified,
      final int atokentype,
      final int ahardtokenissuerid,
      final ExtendedInformation extendedinfo) {
    setUsername(ausername);
    setPassword(null);
    setCardNumber(null);
    setDN(dn);
    setCAId(acaid);
    setSubjectAltName(subjectaltname);
    setEmail(email);
    setStatus(astatus);
    setType(atype);
    setEndEntityProfileId(aendentityprofileid);
    setCertificateProfileId(acertificateprofileid);
    setTimeCreated(atimecreated);
    setTimeModified(atimemodified);
    setTokenType(atokentype);
    setHardTokenIssuerId(ahardtokenissuerid);
    setExtendedInformation(extendedinfo);
    setCardNumber(null);
  }

  /**
   * Creates new EndEntityInformation. This constructor should only be used from
   * UserDataSource implementations. Status and dates aren't used in these
   * cases.
   *
   * @param ausername the unique username.
   * @param dn the DN the subject is given in his certificate.
   * @param acaid the id of the CA that should be used to issue the users
   *     certificate
   * @param subjectaltname the Subject Alternative Name to be used.
   * @param email the email of the subject (may be null).
   * @param atype one of EndEntityTypes.USER_ENDUSER || ...
   * @param aendentityprofileid the id number of the end entity profile bound to
   *     this user.
   * @param acertificateprofileid the id number of the certificate profile that
   *     should be generated for the user.
   * @param atokentype the type of token, from {@link
   *     EndEntityConstants#TOKEN_USERGEN} etc
   * @param ahardtokenissuerid if token should be hard, the id of the hard token
   *     issuer, else 0.
   * @param extendedinfo info
   */
  public EndEntityInformation(// NOPMD: params
      final String ausername,
      final String dn,
      final int acaid,
      final String subjectaltname,
      final String email,
      final EndEntityType atype,
      final int aendentityprofileid,
      final int acertificateprofileid,
      final int atokentype,
      final int ahardtokenissuerid,
      final ExtendedInformation extendedinfo) {
    setUsername(ausername);
    setPassword(null);
    setDN(dn);
    setCAId(acaid);
    setSubjectAltName(subjectaltname);
    setEmail(email);
    setType(atype);
    setEndEntityProfileId(aendentityprofileid);
    setCertificateProfileId(acertificateprofileid);
    setTokenType(atokentype);
    setHardTokenIssuerId(ahardtokenissuerid);
    setExtendedInformation(extendedinfo);
    setCardNumber(null);
  }

  /**
   * @param user User
   */
  public void setUsername(final String user) {
    this.username =
        StringTools.putBase64String(StringTools.stripUsername(user));
  }

  /**
   * @return User
   */
  public String getUsername() {
    return StringTools.getBase64String(username);
  }

  /**
   * @param odn DN
   */
  public void setDN(final String odn) {
     String dn;
     if (odn == null) {
      dn = "";
    } else {
        dn = odn;
    }
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

  /**
   * @return ID
   */
  public int getCAId() {
    return this.caid;
  }

  /**
   * @param aCaid ID
   */
  public void setCAId(final int aCaid) {
    this.caid = aCaid;
  }

  /**
   * @param aSubjectaltname Name
   */
  public void setSubjectAltName(final String aSubjectaltname) {
    this.subjectAltName = StringTools.putBase64String(aSubjectaltname);
  }

  /**
   * @return Name
   */
  public String getSubjectAltName() {
    return StringTools.getBase64String(subjectAltName);
  }

  /**
   * @param aEmail mail
   */
  public void setEmail(final String aEmail) {
    this.subjectEmail = StringTools.putBase64String(aEmail);
  }

  /**
   * @return Email
   */
  public String getEmail() {
    return StringTools.getBase64String(subjectEmail);
  }

  /**
   * @param aCardNumber Number
   */
  public void setCardNumber(final String aCardNumber) {
    this.cardNumber = StringTools.putBase64String(aCardNumber);
  }

  /**
   * @return Number
   */
  public String getCardNumber() {
    return StringTools.getBase64String(cardNumber);
  }

  /**
   * @param aPwd password
   */
  public void setPassword(final String aPwd) {
    this.password = StringTools.putBase64String(aPwd);
  }

  /**
   * Gets the user's clear text password. For empty passwords, it can either
   * return null or an empty string depending on the database software used.
   *
   * @return password
   */
  public String getPassword() {
    return StringTools.getBase64String(password);
  }

  /**
   * @param aStatus status
   */
  public void setStatus(final int aStatus) {
    this.status = aStatus;
  }

  /**
   * @return Status
   */
  public int getStatus() {
    return status;
  }

  /**
   * @param aType type
   */
  public void setType(final EndEntityType aType) {
    this.type = aType.getHexValue();
  }

  /**
   * @return Type.
   */
  public EndEntityType getType() {
    return new EndEntityType(type);
  }

  /**
   * @param aEndentityprofileid ID
   */
  public void setEndEntityProfileId(final int aEndentityprofileid) {
    this.endentityprofileid = aEndentityprofileid;
  }

  /**
   * @return ID
   */
  public int getEndEntityProfileId() {
    return this.endentityprofileid;
  }

  /**
   * @param aCertificateprofileid ID
   */
  public void setCertificateProfileId(final int aCertificateprofileid) {
    this.certificateprofileid = aCertificateprofileid;
  }

  /**
   * @return Id
   */
  public int getCertificateProfileId() {
    return this.certificateprofileid;
  }

  /**
   * @param aTimecreated time
   */
  public void setTimeCreated(final Date aTimecreated) {
    this.timecreated = aTimecreated;
  }

  /**
   * @return time
   */
  public Date getTimeCreated() {
    return this.timecreated;
  }

  /**
   * @param aTimemodified time
   */
  public void setTimeModified(final Date aTimemodified) {
    this.timemodified = aTimemodified;
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
   * @param aTokentype type
   */
  public void setTokenType(final int aTokentype) {
    this.tokentype = aTokentype;
  }

  /**
   * @return ID
   */
  public int getHardTokenIssuerId() {
    return this.hardtokenissuerid;
  }

  /**
   * @param aHardtokenissuerid ID
   */
  public void setHardTokenIssuerId(final int aHardtokenissuerid) {
    this.hardtokenissuerid = aHardtokenissuerid;
  }

  /**
   * @return boolean
   * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This
   *     method is still used for deserializing objects in
   *     CertReqHistoryDataBean.
   */
  @Deprecated
  public boolean getAdministrator() {
    return getType().contains(EndEntityTypes.ADMINISTRATOR);
  }

  /**
   * @param administrator boolean
   * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This
   *     method is still used for deserializing objects in
   *     CertReqHistoryDataBean.
   */
  @Deprecated
  public void setAdministrator(final boolean administrator) {
    final EndEntityType aType = getType();
    if (administrator) {
      aType.addType(EndEntityTypes.ADMINISTRATOR);
    } else {
      aType.removeType(EndEntityTypes.ADMINISTRATOR);
    }
    setType(aType);
  }

  /**
   * @return bool
   */
  public boolean getKeyRecoverable() {
    return getType().contains(EndEntityTypes.KEYRECOVERABLE);
  }

  /**
   * @param keyrecoverable bool
   */
  public void setKeyRecoverable(final boolean keyrecoverable) {
    final EndEntityType aType = getType();
    if (keyrecoverable) {
      aType.addType(EndEntityTypes.KEYRECOVERABLE);
    } else {
      aType.removeType(EndEntityTypes.KEYRECOVERABLE);
    }
    setType(aType);
  }

  /**
   * @return bool
   */
  public boolean getSendNotification() {
    return getType().contains(EndEntityTypes.SENDNOTIFICATION);
  }

  /**
   * Sets flag (part of end entity type) that an email notification (triggered
   * through the End Entity Profile) should be sent. setSendNotification() must
   * be called after setType(), because it adds to the type
   *
   * @param sendnotification true or false
   */
  public void setSendNotification(final boolean sendnotification) {
    final EndEntityType aType = getType();
    if (sendnotification) {
      aType.addType(EndEntityTypes.SENDNOTIFICATION);
    } else {
      aType.removeType(EndEntityTypes.SENDNOTIFICATION);
    }
    setType(aType);
  }

  /**
   * @return bool
   */
  public boolean getPrintUserData() {
    return getType().contains(EndEntityTypes.PRINT);
  }

  /**
   * @param printUserData bool
   */
  public void setPrintUserData(final boolean printUserData) {
    final EndEntityType aType = getType();
    if (printUserData) {
      aType.addType(EndEntityTypes.PRINT);
    } else {
      aType.removeType(EndEntityTypes.PRINT);
    }
    setType(aType);
  }

  /**
   * @return Returns the extendedinformation or null if no extended information
   *     exists.
   */
  public ExtendedInformation getExtendedInformation() {
    return extendedinformation;
  }
  /** @param aExtendedinformation The extendedinformation to set. */
  public void setExtendedInformation(
          final ExtendedInformation aExtendedinformation) {
    this.extendedinformation = aExtendedinformation;
  }

  /**
   * Help Method used to create an ExtendedInformation from String
   * representation. Used when creating an ExtendedInformation from queries.
   *
   * @param extendedinfostring info string
   * @return info object
   */
  public static ExtendedInformation getExtendedInformationFromStringData(
      final String extendedinfostring) {
    ExtendedInformation returnval = null;
    if (extendedinfostring != null && !extendedinfostring.isEmpty()) {
      try (SecureXMLDecoder decoder =
          new SecureXMLDecoder(
              new ByteArrayInputStream(
                  extendedinfostring.getBytes(StandardCharsets.UTF_8)))) {
        final HashMap<?, ?> data = (HashMap<?, ?>) decoder.readObject();
        // No need to b64 decode Integer value, just read it
        final int type =
            ((Integer) data.get(ExtendedInformation.TYPE)).intValue();
        switch (type) {
          case ExtendedInformation.TYPE_BASIC:
            returnval = new ExtendedInformation();
            returnval.loadData(data);
            break;
          default:
              // do nothing
        }
      } catch (IOException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Failed to parse ExtendedInformation for End Entity. Data:\n"
                  + extendedinfostring);
        }
        throw new IllegalStateException(
            "Failed to parse ExtendedInformation data map for End Entity: "
                + e.getMessage(),
            e);
      }
    }
    return returnval;
  }

  /**
   * @param extendedinformation Info
   * @return String representation.
   */
  public static String extendedInformationToStringData(
      final ExtendedInformation extendedinformation) {
    String ret = null;
    if (extendedinformation != null) {
      // We must base64 encode string for UTF safety
      final HashMap<Object, Object> b64DataMap = new Base64PutHashMap();
      b64DataMap.putAll(extendedinformation.getRawData());
      ByteArrayOutputStream baos = new ByteArrayOutputStream(INFO_SIZE);
      try (java.beans.XMLEncoder encoder =
          new java.beans.XMLEncoder(baos); ) {
        encoder.writeObject(b64DataMap);
      }
      ret = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }
    return ret;
  }

  /**
   * @return the DN to be used when creating a certificate (without empty
   *     fields). If the registered DN has unused DN fields the empty ones are
   *     kept, i.e. CN=Tomas,OU=,OU=PrimeKey,C=SE. See ECA-1841 for an
   *     explanation of this. Use method getCertificateDN() to get the DN
   *     stripped from empty fields, getDN() returns DN with empty fields.
   * @see #getDN()
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
   * @return an information map about this end entity, listing all general
   *     fields.
   */
  public Map<String, String> getDetailMap() {
    @SuppressWarnings("unchecked")
    Map<String, String> details = new Base64GetHashMap();
    details.put("caid", Integer.toString(caid));
    details.put("cardnumber", cardNumber);
    details.put("certificateprofileid", Integer.toString(certificateprofileid));
    details.put("endentityprofileid", Integer.toString(endentityprofileid));
    if (extendedinformation != null) {
      StringBuilder extendedInformationDump = new StringBuilder("{");
      LinkedHashMap<Object, Object> rawData = extendedinformation.getRawData();
      for (Object key : rawData.keySet()) {
        if (rawData.get(key) != null) {
          extendedInformationDump.append(
              ", [" + (String) key + ":" + rawData.get(key).toString() + "]");
        }
      }
      extendedInformationDump.append("}");
      details.put("extendedInformation", extendedInformationDump.substring(2));
    }
    details.put("hardtokenissuerid", Integer.toString(hardtokenissuerid));
    details.put("status", Integer.toString(status));
    details.put("subjectAltName", subjectAltName);
    details.put("subjectDN", subjectDN);
    details.put("subjectEmail", subjectEmail);
    if (timecreated != null) {
      details.put("timecreated", timecreated.toString());
    }
    if (timemodified != null) {
      details.put("timemodified", timemodified.toString());
    }
    details.put("tokentype", Integer.toString(tokentype));
    details.put("type", Integer.toString(type));
    details.put("username", username);
    return details;
  }

  /**
   * @param other another {@link EndEntityInformation}
   * @return the differences between this map and the parameter, as &lt;key,
   *     [thisValue, otherValue]&gt;
   */
  public Map<String, String[]> getDiff(final EndEntityInformation other) {
    Map<String, String[]> changedValues = new LinkedHashMap<>();
    Map<String, String> thisValues = getDetailMap();
    Map<String, String> otherValues = other.getDetailMap();
    List<String> thisKeySet = new ArrayList<>(thisValues.keySet());
    for (String key : thisKeySet) {
      String thisValue = thisValues.get(key);
      String otherValue = otherValues.get(key);
      if (thisValue == null) {
        if (otherValue != null) {
          changedValues.put(key, new String[] {"<null>", otherValue});
        }
      } else if (!thisValue.equals(otherValue)) {
        changedValues.put(key, new String[] {thisValue, otherValue});
      }
      thisValues.remove(key);
      otherValues.remove(key);
    }
    // Add in any values that may have been in otherValues but not here
    for (String otherKey : otherValues.keySet()) {
      changedValues.put(
          otherKey, new String[] {"<null>", otherValues.get(otherKey)});
    }
    return changedValues;
  }
}
