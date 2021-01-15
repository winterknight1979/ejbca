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

package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.StringTools;

/**
 * A class representing a web interface view of a user in the ra user database.
 *
 * @version $Id: UserView.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class UserView implements Serializable, Comparable<UserView> {

  private static final long serialVersionUID = 2390294870669249774L;

  /** Param. */
  private SortBy sortby;
  /** Param. */
  private final EndEntityInformation userdata;
  /** Param. */
  private final DNFieldExtractor subjectdnfields;
  /** Param. */
  private final DNFieldExtractor subjectaltnames;
  /** Param. */
  private final DNFieldExtractor subjectdirattrs;
  /** Param. */
  private String commonname = "";
  /** Param. */
  private String caname;
  /** Param. */
  private boolean cleartextpwd;

  /** Constructor.
   */
  public UserView() {
    userdata = new EndEntityInformation();
    userdata.setType(EndEntityTypes.ENDUSER.toEndEntityType());
    subjectdnfields = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDN);
    subjectaltnames =
        new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTALTNAME);
    subjectdirattrs =
        new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDIRATTR);
  }

  /**
   * @param newuserdata data
   * @param caidtonamemap ID
   */
  public UserView(
      final EndEntityInformation newuserdata,
      final Map<Integer, String> caidtonamemap) {
    userdata = newuserdata;
    this.caname = caidtonamemap.get(Integer.valueOf(newuserdata.getCAId()));
    subjectdnfields =
        new DNFieldExtractor(userdata.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
    subjectaltnames =
        new DNFieldExtractor(
            userdata.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
    String dirattrs =
        userdata.getExtendedInformation() != null
            ? userdata.getExtendedInformation().getSubjectDirectoryAttributes()
            : null;
    subjectdirattrs =
        new DNFieldExtractor(dirattrs, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    setCommonName();

    cleartextpwd = userdata.getPassword() != null;
  }

  /**
   * @param user user
   */
  public void setUsername(final String user) {
    userdata.setUsername(StringTools.stripUsername(user));
  }

  /**
   * @return user
   */
  public String getUsername() {
    return userdata.getUsername();
  }

  /**
   * @param dn DN
   */
  public void setSubjectDN(final String dn) {
    userdata.setDN(dn);
    subjectdnfields.setDN(dn, DNFieldExtractor.TYPE_SUBJECTDN);

    setCommonName();
  }

  /**
   * @return DN
   */
  public String getSubjectDN() {
    return userdata.getDN();
  }

  /**
   * @param subjectaltname name
   */
  public void setSubjectAltName(final String subjectaltname) {
    userdata.setSubjectAltName(subjectaltname);
    subjectaltnames.setDN(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
  }

  /**
   * @return name
   */
  public String getSubjectAltName() {
    return userdata.getSubjectAltName();
  }

  /**
   * @param subjectdirattr attrs
   */
  public void setSubjectDirAttributes(final String subjectdirattr) {
    ExtendedInformation ext = userdata.getExtendedInformation();
    if (ext == null) {
      ext = new ExtendedInformation();
    }
    ext.setSubjectDirectoryAttributes(subjectdirattr);
    userdata.setExtendedInformation(ext);
    subjectdirattrs.setDN(subjectdirattr, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
  }

  /**
   * @return sttrs
   */
  public String getSubjectDirAttributes() {
    return userdata.getExtendedInformation() != null
        ? userdata.getExtendedInformation().getSubjectDirectoryAttributes()
        : null;
  }

  /**
   * @param email email
   */
  public void setEmail(final String email) {
    userdata.setEmail(email);
  }

  /**
   * @return email
   */
  public String getEmail() {
    return userdata.getEmail();
  }

  /**
   * @param pwd pwd
   */
  public void setPassword(final String pwd) {
    userdata.setPassword(pwd);
  }

  /**
   * @return pwd
   */
  public String getPassword() {
    return userdata.getPassword();
  }

  /**
   * @return bool
   */
  public boolean getClearTextPassword() {
    return cleartextpwd;
  }

  /**
   * @param acleartextpwd bool
   */
  public void setClearTextPassword(final boolean acleartextpwd) {
    this.cleartextpwd = acleartextpwd;
  }

  /**
   * @param status status
   */
  public void setStatus(final int status) {
    userdata.setStatus(status);
  }

  /**
   * @return status
   */
  public int getStatus() {
    return userdata.getStatus();
  }

  /**
   * @param type type
   */
  public void setType(final EndEntityType type) {
    userdata.setType(type);
  }

  /**
   * @return type
   */
  public EndEntityType getType() {
    return userdata.getType();
  }

  /**
   * @param keyrecoverable bool
   */
  public void setKeyRecoverable(final boolean keyrecoverable) {
    userdata.setKeyRecoverable(keyrecoverable);
  }

  /**
   * @return key
   */
  public boolean getKeyRecoverable() {
    return userdata.getKeyRecoverable();
  }

  /**
   * @param cardNumber num
   */
  public void setCardNumber(final String cardNumber) {
    userdata.setCardNumber(cardNumber);
  }

  /**
   * @return num
   */
  public String getCardNumber() {
    return userdata.getCardNumber();
  }

  /**
   * @param sendnotification bool
   */
  public void setSendNotification(final boolean sendnotification) {
    userdata.setSendNotification(sendnotification);
  }

  /**
   * @return bool
   */
  public boolean getSendNotification() {
    return userdata.getSendNotification();
  }

  /**
   * @param printUserData Data
   */
  public void setPrintUserData(final boolean printUserData) {
    userdata.setPrintUserData(printUserData);
  }

  /**
   * @return Data
   */
  public boolean getPrintUserData() {
    return userdata.getPrintUserData();
  }

  /**
   * @param profileid ID
   */
  public void setEndEntityProfileId(final int profileid) {
    userdata.setEndEntityProfileId(profileid);
  }

  /**
   * @return ID
   */
  public int getEndEntityProfileId() {
    return userdata.getEndEntityProfileId();
  }

  /**
   * @param profileid ID
   */
  public void setCertificateProfileId(final int profileid) {
    userdata.setCertificateProfileId(profileid);
  }

  /**
   * @return ID
   */
  public int getCertificateProfileId() {
    return userdata.getCertificateProfileId();
  }

  /**
   * @param timecreated toime
   */
  public void setTimeCreated(final Date timecreated) {
    userdata.setTimeCreated(timecreated);
  }

  /**
   * @return time
   */
  public Date getTimeCreated() {
    return userdata.getTimeCreated();
  }

  /**
   * @param timemodified time
   */
  public void setTimeModified(final Date timemodified) {
    userdata.setTimeModified(timemodified);
  }

  /**
   * @return time
   */
  public Date getTimeModified() {
    return userdata.getTimeModified();
  }

  /**
   * @return type
   */
  public int getTokenType() {
    return userdata.getTokenType();
  }

  /**
   * @param tokentype type
   */
  public void setTokenType(final int tokentype) {
    userdata.setTokenType(tokentype);
  }

  /**
   * @return ID
   */
  public int getHardTokenIssuerId() {
    return userdata.getHardTokenIssuerId();
  }

  /**
   * @param hardtokenissuerid ID
   */
  public void setHardTokenIssuerId(final int hardtokenissuerid) {
    userdata.setHardTokenIssuerId(hardtokenissuerid);
  }

  /**
   * @return ID
   */
  public int getCAId() {
    return userdata.getCAId();
  }

  /**
   * @param caid ID
   */
  public void setCAId(final int caid) {
    userdata.setCAId(caid);
  }

  /**
   * @return name
   */
  public String getCAName() {
    return caname;
  }

  /**
   * @param extinfo info
   */
  public void setExtendedInformation(final ExtendedInformation extinfo) {
    userdata.setExtendedInformation(extinfo);
  }

  /**
   * @return info
   */
  public ExtendedInformation getExtendedInformation() {
    return userdata.getExtendedInformation();
  }
  /**
   * @param parameter param
   * @param number num
   * @return field
   */
  public String getSubjectDNField(final int parameter, final int number) {
    // We don't need to htmlescape the output, because we use JSTL output stuff
    // in JSP pages that does it for us
    // in the output shown in browser
    return subjectdnfields.getField(parameter, number);
  }
  /**
   * @param parameter param
   * @param number num
   * @return field
   */
  public String getSubjectAltNameField(final int parameter, final int number) {
    return subjectaltnames.getField(parameter, number);
  }

  /**
   * @param parameter param
   * @param number num
   * @return field
   */
  public String getSubjectDirAttributeField(
      final int parameter, final int number) {
    return subjectdirattrs.getField(parameter, number);
  }

  /**
   * getCommonName is a special function used in list end entity gui to display
   * names in cases not a CN field exists in dn only, surname and givenname.
   *
   * @return Name
   */
  public String getCommonName() {

    return commonname;
  }

  private void setCommonName() {
    commonname = getSubjectDNField(DNFieldExtractor.CN, 0);
    if (commonname.equals("")) {
      commonname =
          getSubjectDNField(DNFieldExtractor.GIVENNAME, 0)
              + " "
              + getSubjectDNField(DNFieldExtractor.SURNAME, 0);
    }
  }

  @Override
  public int compareTo(final UserView obj) {
    int returnvalue = -1;
    int asortby = this.sortby.getSortBy();
    switch (asortby) {
      case SortBy.USERNAME:
        returnvalue = getUsername().compareTo(obj.getUsername());
        break;
      case SortBy.COMMONNAME:
        returnvalue = this.commonname.compareTo(obj.getCommonName());
        break;
      case SortBy.DNSERIALNUMBER:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.SN, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.SN, 0));
        break;
      case SortBy.TITLE:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.T, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.T, 0));
        break;
      case SortBy.ORGANIZATIONALUNIT:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.OU, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.OU, 0));
        break;
      case SortBy.ORGANIZATION:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.O, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.O, 0));
        break;
      case SortBy.LOCALITY:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.L, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.L, 0));
        break;
      case SortBy.STATEORPROVINCE:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.ST, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.ST, 0));
        break;
      case SortBy.DOMAINCOMPONENT:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.DC, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.DC, 0));
        break;
      case SortBy.COUNTRY:
        returnvalue =
            getSubjectDNField(DNFieldExtractor.C, 0)
                .compareTo(obj.getSubjectDNField(DNFieldExtractor.C, 0));
        break;
      case SortBy.EMAIL:
        returnvalue = getEmail().compareTo(obj.getEmail());
        break;
      case SortBy.STATUS:
        returnvalue =
            (Integer.valueOf(getStatus()))
                .compareTo(Integer.valueOf(obj.getStatus()));
        break;
      case SortBy.TIMECREATED:
        returnvalue = getTimeCreated().compareTo(obj.getTimeCreated());
        break;
      case SortBy.TIMEMODIFIED:
        returnvalue = getTimeModified().compareTo(obj.getTimeModified());
        break;
      case SortBy.CA:
        returnvalue = getCAName().compareTo(obj.getCAName());
        break;
      default:
        returnvalue = getUsername().compareTo(obj.getUsername());
    }
    if (this.sortby.getSortOrder() == SortBy.DECENDING) {
      returnvalue = 0 - returnvalue;
    }
    return returnvalue;
  }

  /**
   * @param asortby key
   */
  public void setSortBy(final SortBy asortby) {
    this.sortby = asortby;
  }
}
