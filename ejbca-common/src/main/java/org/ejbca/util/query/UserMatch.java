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
package org.ejbca.util.query;

import org.apache.commons.lang.StringUtils;

/**
 * A class used by Query class to build a query for EJBCA RA module.
 *
 * @version $Id: UserMatch.java 26481 2017-09-04 11:43:58Z henriks $
 */
public class UserMatch extends BasicMatch {

  private static final long serialVersionUID = 5458563135026714888L;

  /** Config. */
  public static final int MATCH_NONE = -1;

  /** Config. */
  public static final int MATCH_WITH_USERNAME = 0;
  /** Config. */
  public static final int MATCH_WITH_EMAIL = 1;
  /** Config. */
  public static final int MATCH_WITH_STATUS =
      2; // Value must the number representation.
  /** Config. */
  public static final int MATCH_WITH_ENDENTITYPROFILE =
      3; // Matches the profile id not profilename.
  /** Config. */
  public static final int MATCH_WITH_CERTIFICATEPROFILE =
      4; // Matches the certificatetype id not name.
  /** Config. */
  public static final int MATCH_WITH_CA = 5; // Matches the CA id not CA name.
  /** Config. */
  public static final int MATCH_WITH_TOKEN = 6;
  /** Config. */
  public static final int MATCH_WITH_DN = 7;
  // Subject DN fields.
  /** Config. */
  public static final int MATCH_WITH_UID = 100;
  /** Config. */
  public static final int MATCH_WITH_COMMONNAME = 101;
  /** Config. */
  public static final int MATCH_WITH_DNSERIALNUMBER = 102;
  /** Config. */
  public static final int MATCH_WITH_GIVENNAME = 103;
  /** Config. */
  public static final int MATCH_WITH_INITIALS = 104;
  /** Config. */
  public static final int MATCH_WITH_SURNAME = 105;
  /** Config. */
  public static final int MATCH_WITH_TITLE = 106;
  /** Config. */
  public static final int MATCH_WITH_ORGANIZATIONALUNIT = 107;
  /** Config. */
  public static final int MATCH_WITH_ORGANIZATION = 108;
  /** Config. */
  public static final int MATCH_WITH_LOCALITY = 109;
  /** Config. */
  public static final int MATCH_WITH_STATEORPROVINCE = 110;
  /** Config. */
  public static final int MATCH_WITH_DOMAINCOMPONENT = 111;
  /** Config. */
  public static final int MATCH_WITH_COUNTRY = 112;
  // Subject Altname Fields
  /** Config. */
  public static final int MATCH_WITH_RFC822NAME = 200;
  /** Config. */
  public static final int MATCH_WITH_DNSNAME = 201;
  /** Config. */
  public static final int MATCH_WITH_IPADDRESS = 202;
  /** Config. */
  public static final int MATCH_WITH_X400ADDRESS = 203;
  /** Config. */
  public static final int MATCH_WITH_DIRECTORYNAME = 204;
  /** Config. */
  public static final int MATCH_WITH_EDIPARTYNAME = 205;
  /** Config. */
  public static final int MATCH_WITH_URI = 206;
  /** Config. */
  public static final int MATCH_WITH_REGISTEREDID = 207;
  /** Config. */
  public static final int MATCH_WITH_UPN = 208;
  /** Config. */
  public static final int MATCH_WITH_GUID = 209;

  /** Config. */
  static final String[] MATCH_WITH_SQLNAMES = {
    "username",
    "subjectEmail",
    "status",
    "endEntityProfileId",
    "certificateProfileId",
    "cAId",
    "tokenType"
  };

  // Represents the column names in ra userdata table.
  /** Config. */
  private static final String MATCH_WITH_USERNAMESTRING = "UPPER(username)";
  /** Config. */
  private static final String MATCH_WITH_SUBJECTDN = "UPPER(subjectDN)";
  /** Config. */
  private static final String[] MATCH_WITH_SUBJECTDN_NAMES = {
    "UID=",
    "CN=",
    "SN=",
    "GIVENNAME=",
    "INITIALS=",
    "SURNAME=",
    "T=",
    "OU=",
    "O=",
    "L=",
    "ST=",
    "DC",
    "C="
  };

  /** Config. */
  private static final String MATCH_WITH_SUBJECTALTNAME = "subjectAltName";
  /** Config. */
  private static final String[] MATCH_WITH_SUBJECTALTNAME_NAMES = {
    "RFC822NAME=", "DNSNAME=", "IPADDRESS=", "X400ADDRESS=", "DIRECTORYNAME=",
    "EDIPARTYNAME=", "UNIFORMRESOURCEIDENTIFIER=", "REGISTEREDID=", "UPN=",
        "GUID="
  };

  /** For example UserMatch.MATCH_WITH_USERNAME. */
  private final int matchwith;
  /** For example BasicMatch.MATCH_TYPE_EQUALS. */
  private final int matchtype;
  /** For example a username. */
  private final String matchvalue;

  /**
   * Creates a new instance of UserMatch.
   *
   * @param amatchwith determines which field i userdata table to match with.
   * @param amatchtype determines how to match the field. SubjectDN fields can
   *     only be matched with 'begins with'.
   * @param amatchvalue the value to match with.
   * @throws NumberFormatException if matchvalue contains illegal numbervalue
   *     when matching number field.
   */
  public UserMatch(
      final int amatchwith, final int amatchtype, final String amatchvalue)
      throws NumberFormatException {
    this.matchwith = amatchwith;
    this.matchtype = amatchtype;
    this.matchvalue = amatchvalue;
    if (amatchwith >= MATCH_WITH_STATUS && amatchwith <= MATCH_WITH_CA) {
      Integer.valueOf(amatchvalue);
    }
  }

  @Override
  public String getQueryString() {
    String returnval = "";
    final String amatchvalue = super.escapeSql(this.matchvalue).toUpperCase();
    if (isSubjectDNMatch()) {
      // Ignore MATCH_TYPE_EQUALS.
      returnval =
          MATCH_WITH_SUBJECTDN
              + " LIKE '%"
              + MATCH_WITH_SUBJECTDN_NAMES[matchwith - DN_START]
              + amatchvalue
              + "%'";
    } else if (isSubjectAltNameMatch()) {
      returnval =
          MATCH_WITH_SUBJECTALTNAME
              + " LIKE '%"
              + MATCH_WITH_SUBJECTALTNAME_NAMES[matchwith - ALT_START]
              + amatchvalue
              + "%'";
    } else if (matchwith == MATCH_WITH_DN) {
      if (matchtype == BasicMatch.MATCH_TYPE_EQUALS) {
        returnval = MATCH_WITH_SUBJECTDN + " = '" + amatchvalue.trim() + "'";
      } else if (matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH) {
        returnval = MATCH_WITH_SUBJECTDN + " LIKE '" + amatchvalue + "%'";
      } else if (matchtype == BasicMatch.MATCH_TYPE_CONTAINS) {
        returnval = MATCH_WITH_SUBJECTDN + " LIKE '%" + amatchvalue + "%'";
      }
    } else if (matchwith == MATCH_WITH_USERNAME) {
      if (matchtype == BasicMatch.MATCH_TYPE_EQUALS) {
        returnval =
            MATCH_WITH_USERNAMESTRING + " = '" + amatchvalue.trim() + "'";
      } else if (matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH) {
        returnval = MATCH_WITH_USERNAMESTRING + " LIKE '" + amatchvalue + "%'";
      } else if (matchtype == BasicMatch.MATCH_TYPE_CONTAINS) {
        returnval = MATCH_WITH_USERNAMESTRING + " LIKE '%" + amatchvalue + "%'";
      }
    } else if (matchtype == BasicMatch.MATCH_TYPE_EQUALS) {
      // Because some databases (read JavaDB/Derby) does not allow matching of
      // integer with a string expression
      // like "where status='10'" instead of "where status=10", we have to have
      // some special handling here.
      String stringChar = "'";
      if (matchwith == MATCH_WITH_STATUS
          || matchwith == MATCH_WITH_CA
          || matchwith == MATCH_WITH_CERTIFICATEPROFILE
          || matchwith == MATCH_WITH_ENDENTITYPROFILE
          || matchwith == MATCH_WITH_TOKEN) {
        stringChar = "";
      }
      returnval =
          MATCH_WITH_SQLNAMES[matchwith]
              + " = "
              + stringChar
              + amatchvalue.trim()
              + stringChar;
    } else if (matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH) {
      returnval =
          MATCH_WITH_SQLNAMES[matchwith] + " LIKE '" + amatchvalue + "%'";
    }
    return returnval;
  }

  @Override
  public boolean isLegalQuery() {
    return StringUtils.isNotBlank(matchvalue);
  }

  /** Config. */
  private static final int DN_START = 100;
  /** Config. */
  private static final int DN_END = 200;
  /** Config. */
  private static final int ALT_START = DN_END;
  /** Config. */
  private static final int ALT_END = 300;

  private boolean isSubjectDNMatch() {
    return this.matchwith >= DN_START && this.matchwith < DN_END;
  }

  private boolean isSubjectAltNameMatch() {
    return this.matchwith >= ALT_START && this.matchwith < ALT_END;
  }
}
