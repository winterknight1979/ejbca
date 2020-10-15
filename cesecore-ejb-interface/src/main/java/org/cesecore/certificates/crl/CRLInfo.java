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
package org.cesecore.certificates.crl;

import java.io.Serializable;
import java.util.Date;

/**
 * Holds information about a CRL but not he CRL itself.
 *
 * @version $Id: CRLInfo.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public class CRLInfo implements Serializable {

  private static final long serialVersionUID = 4942836797714142516L;
  /** DN. */
  protected String subjectdn;
  /** Number. */
  protected int lastcrlnumber;
  /** Date. */
  protected Date thisupdate;
  /** Date. */
  protected Date nextupdate;

  /**
   * @param aSubjectdn DN
   * @param theLastcrlnumber Number
   * @param theLastupdate Date
   * @param theNextupdate Date
   */
  public CRLInfo(
      final String aSubjectdn,
      final int theLastcrlnumber,
      final long theLastupdate,
      final long theNextupdate) {
    this.subjectdn = aSubjectdn;
    this.lastcrlnumber = theLastcrlnumber;
    this.thisupdate = new Date(theLastupdate);
    this.nextupdate = new Date(theNextupdate);
  }

  /**
   * @return DN
   */
  public String getSubjectDN() {
    return subjectdn;
  }

  /**
   * @return Number
   */
  public int getLastCRLNumber() {
    return lastcrlnumber;
  }

  /**
   * @return Date
   */
  public Date getCreateDate() {
    return thisupdate;
  }

  /**
   * @return Date
   */
  public Date getExpireDate() {
    return nextupdate;
  }
}
