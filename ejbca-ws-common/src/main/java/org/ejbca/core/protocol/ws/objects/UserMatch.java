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
import org.ejbca.util.query.BasicMatch;

/**
 * Holder of user match/search data.
 *
 * @version $Id: UserMatch.java 28961 2018-05-18 06:53:27Z mikekushner $
 */
public class UserMatch implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  public static final int MATCH_WITH_USERNAME =
      org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME;
  /** Param. */
  public static final int MATCH_WITH_EMAIL =
      org.ejbca.util.query.UserMatch.MATCH_WITH_EMAIL;
  /** Param. */
  public static final int MATCH_WITH_STATUS =
      org.ejbca.util.query.UserMatch
          .MATCH_WITH_STATUS; // Value must the number representation.
  /** Param. */
  public static final int MATCH_WITH_ENDENTITYPROFILE =
      org.ejbca.util.query.UserMatch
          .MATCH_WITH_ENDENTITYPROFILE; // Matches the end entity profile name.
  /** Param. */
  public static final int MATCH_WITH_CERTIFICATEPROFILE =
      org.ejbca.util.query.UserMatch
          .MATCH_WITH_CERTIFICATEPROFILE; // Matches the certificate profile
                                          // name.
  /** Param. */
  public static final int MATCH_WITH_CA =
      org.ejbca.util.query.UserMatch.MATCH_WITH_CA; // Matches the CA name.
  /** Param. */
  public static final int MATCH_WITH_TOKEN =
      org.ejbca.util.query.UserMatch.MATCH_WITH_TOKEN;
  /** Param. */
  public static final int MATCH_WITH_DN =
      org.ejbca.util.query.UserMatch.MATCH_WITH_DN;
  // Subject DN fields.
  /** Param. */
  public static final int MATCH_WITH_UID =
      org.ejbca.util.query.UserMatch.MATCH_WITH_UID;
  /** Param. */
  public static final int MATCH_WITH_COMMONNAME =
      org.ejbca.util.query.UserMatch.MATCH_WITH_COMMONNAME;
  /** Param. */
  public static final int MATCH_WITH_DNSERIALNUMBER =
      org.ejbca.util.query.UserMatch.MATCH_WITH_DNSERIALNUMBER;
  /** Param. */
  public static final int MATCH_WITH_GIVENNAME =
      org.ejbca.util.query.UserMatch.MATCH_WITH_GIVENNAME;
  /** Param. */
  public static final int MATCH_WITH_INITIALS =
      org.ejbca.util.query.UserMatch.MATCH_WITH_INITIALS;
  /** Param. */
  public static final int MATCH_WITH_SURNAME =
      org.ejbca.util.query.UserMatch.MATCH_WITH_SURNAME;
  /** Param. */
  public static final int MATCH_WITH_TITLE =
      org.ejbca.util.query.UserMatch.MATCH_WITH_TITLE;
  /** Param. */
  public static final int MATCH_WITH_ORGANIZATIONALUNIT =
      org.ejbca.util.query.UserMatch.MATCH_WITH_ORGANIZATIONALUNIT;
  /** Param. */
  public static final int MATCH_WITH_ORGANIZATION =
      org.ejbca.util.query.UserMatch.MATCH_WITH_ORGANIZATION;
  /** Param. */
  public static final int MATCH_WITH_LOCALITY =
      org.ejbca.util.query.UserMatch.MATCH_WITH_LOCALITY;
  /** Param. */
  public static final int MATCH_WITH_STATEORPROVINCE =
      org.ejbca.util.query.UserMatch.MATCH_WITH_STATEORPROVINCE;
  /** Param. */
  public static final int MATCH_WITH_DOMAINCOMPONENT =
      org.ejbca.util.query.UserMatch.MATCH_WITH_DOMAINCOMPONENT;
  /** Param. */
  public static final int MATCH_WITH_COUNTRY =
      org.ejbca.util.query.UserMatch.MATCH_WITH_COUNTRY;
  /** Param. */
  public static final int MATCH_TYPE_EQUALS = BasicMatch.MATCH_TYPE_EQUALS;
  /** Param. */
  public static final int MATCH_TYPE_BEGINSWITH =
      BasicMatch.MATCH_TYPE_BEGINSWITH;
  /** Param. */
  public static final int MATCH_TYPE_CONTAINS = BasicMatch.MATCH_TYPE_CONTAINS;

  /** Param. */
  private int matchwith;
  /** Param. */
  private int matchtype;
  /** Param. */
  private String matchvalue;

  /** Default Web Service Constructor. */
  public UserMatch() { }

  /**
   * Constuctor to use to create a UserMatch.
   *
   * @param amatchwith one of MATCH_WITH_ constants.
   * @param amatchtype one of MATCH_TYPE_ constants.
   * @param amatchvalue a string to search for.
   */
  public UserMatch(int amatchwith, int amatchtype, String amatchvalue) {
    this.matchwith = amatchwith;
    this.matchtype = amatchtype;
    this.matchvalue = amatchvalue;
  }

  /** @return Returns the matchtype, one of MATCH_TYPE_ constants. */
  public int getMatchtype() {
    return matchtype;
  }

  /** @param amatchtype The matchtype to set, one of MATCH_TYPE_ constants. */
  public void setMatchtype(int amatchtype) {
    this.matchtype = amatchtype;
  }

  /** @return Returns the matchvalue. */
  public String getMatchvalue() {
    return matchvalue;
  }

  /** @param amatchvalue The matchvalue to set. */
  public void setMatchvalue(String amatchvalue) {
    this.matchvalue = amatchvalue;
  }

  /** @return Returns the matchwith, one of MATCH_WITH_ constants. */
  public int getMatchwith() {
    return matchwith;
  }

  /** @param amatchwith The matchwith to set, one of MATCH_WITH_ constants. */
  public void setMatchwith(int amatchwith) {
    this.matchwith = amatchwith;
  }
}
