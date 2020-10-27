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

package org.ejbca.core.model.hardtoken;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.hardtoken.types.HardToken;

/**
 * This is a value class containing the data relating to a hard token sent
 * between server and clients.
 *
 * @version $Id: HardTokenInformation.java 26797 2017-10-12 04:45:37Z anatom $
 */
public class HardTokenInformation
    implements Serializable, Comparable<HardTokenInformation> {

  private static final long serialVersionUID = 2801790818906276161L;

  // Public Constructors
  /**
   * Constructor of a hard token data.
   *
   * @param aTokensn the tokensn
   * @param aUsername the username owning the token
   * @param aCreatetime time the token was created
   * @param aModifytime time whem token was modified or a copy was made.
   * @param aTokentype the hardtokenprofile used to create the token
   * @param aSignificantIssuerDN of the CA that the card belongs to
   * @param aHardtoken the actual hardtoken data
   * @param aCopyof tokenSN of original or null of this is an original
   * @param theCopies Collection of tokensn of tokens copied from this token,
   *     null if no copies have been made.
   */
  public HardTokenInformation(
      final String aTokensn,
      final String aUsername,
      final Date aCreatetime,
      final Date aModifytime,
      final int aTokentype,
      final String aSignificantIssuerDN,
      final HardToken aHardtoken,
      final String aCopyof,
      final Collection<String> theCopies) {
    this.tokensn = aTokensn;
    this.username = StringTools.stripUsername(aUsername);
    this.createtime = aCreatetime;
    this.modifytime = aModifytime;
    this.tokentype = aTokentype;
    this.significantIssuerDN = aSignificantIssuerDN;
    this.hardtoken = aHardtoken;
    this.copyof = aCopyof;
    this.copies = theCopies;
  }

  /** Default constructor. */
  public HardTokenInformation() { }

  // Public Methods

  /**
   * @return serial
   */
  public String getTokenSN() {
    return this.tokensn;
  }

  /**
   * @param aTokensn Serial
   */
  public void setTokenSN(final String aTokensn) {
    this.tokensn = aTokensn;
  }

  /**
   * @return User
   */
  public String getUsername() {
    return this.username;
  }

  /**
   * @param aUsername user
   */
  public void setUsername(final String aUsername) {
    this.username = StringTools.stripUsername(aUsername);
  }

  /**
   * @return time
   */
  public Date getCreateTime() {
    return this.createtime;
  }

  /**
   * @param aCreatetime time
   */
  public void setCreateTime(final Date aCreatetime) {
    this.createtime = aCreatetime;
  }

  /**
   * @return time
   */
  public Date getModifyTime() {
    return this.modifytime;
  }

  /**
   * @param aModifytime time
   */
  public void setModifyTime(final Date aModifytime) {
    this.modifytime = aModifytime;
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
   * @return token
   */
  public HardToken getHardToken() {
    return this.hardtoken;
  }

  /**
   * @param aHardtoken token
   */
  public void setHardToken(final HardToken aHardtoken) {
    this.hardtoken = aHardtoken;
  }

  /**
   * @return bool
   */
  public boolean isOriginal() {
    return copyof == null;
  }

  /**
   * @return copy
   */
  public String getCopyOf() {
    return copyof;
  }

  /**
   * @return DN
   */
  public String getSignificantIssuerDN() {
    return significantIssuerDN;
  }

  /**
   * Returns a collection of (Strings) containing the tokenSN of all copies made
   * of this token.
   *
   * @return A Collection of tokenSN or null of no copies have been made.
   */
  public Collection<String> getCopies() {
    return copies;
  }

  // Private fields
  /** SN. */
  private String tokensn;
  /** User. */
  private String username;
  /** Time. */
  private Date createtime;
  /** Time. */
  private Date modifytime;
  /** Type. */
  private int tokentype;
  /** DN. */
  private String significantIssuerDN;
  /** Token. */
  private HardToken hardtoken;
  /** Copy. */
  private String copyof;
  /** Copies. */
  private Collection<String> copies;

  /**
   * When viewing the tokens in the GUI they should come in the order that they
   * were created.
   *
   * @see java.lang.Comparable#compareTo(java.lang.Object)
   */
  @Override
  public int compareTo(final HardTokenInformation o) {
    if (this.createtime.equals(o.getCreateTime())) {
      return 0;
    }
    return this.createtime.after(o.getCreateTime()) ? -1 : 1;
  }
}
