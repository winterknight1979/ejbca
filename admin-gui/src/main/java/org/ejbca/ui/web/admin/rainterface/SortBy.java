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

/**
 * A class specifying which field to sort the userdata by.
 *
 * @author Philip Vendil
 * @version $Id: SortBy.java 19947 2014-10-07 00:39:24Z davidcarella $
 */
public class SortBy implements java.io.Serializable {
  private static final long serialVersionUID = -2924038902779549663L;
  // Public constants
  // Constants used by userdata.
  /** Param. */
  public static final int USERNAME = 0;
  /** Param. */
  public static final int PASSWORD = 1;
  /** Param. */
  public static final int COMMONNAME = 2;
  /** Param. */
  public static final int DNSERIALNUMBER = 3;
  /** Param. */
  public static final int TITLE = 4;
  /** Param. */
  public static final int ORGANIZATIONALUNIT = 5;
  /** Param. */
  public static final int ORGANIZATION = 6;
  /** Param. */
  public static final int LOCALITY = 7;
  /** Param. */
  public static final int STATEORPROVINCE = 8;
  /** Param. */
  public static final int DOMAINCOMPONENT = 9;
  /** Param. */
  public static final int COUNTRY = 10;
  /** Param. */
  public static final int EMAIL = 11;
  /** Param. */
  public static final int STATUS = 12;
  /** Param. */
  public static final int TIMECREATED = 13;
  /** Param. */
  public static final int TIMEMODIFIED = 14;
  /** Param. */
  public static final int CA = 15;
  // Constants used by logentrydata.

  /** Param. */
  public static final int ADMINTYPE = 1;
  /** Param. */
  public static final int ADMINDATA = 2;
  /** Param. */
  public static final int MODULE = 4;
  /** Param. */
  public static final int TIME = 5;
  /** Param. */
  public static final int CERTIFICATE = 6;
  /** Param. */
  public static final int EVENT = 7;
  /** Param. */
  public static final int COMMENT = 8;

  /** Param. */
  public static final int ACCENDING = 0;
  /** Param. */
  public static final int DECENDING = 1;

  /** Creates a new instance of SortBy. */
  public SortBy() {
    this.sortby = USERNAME;
    this.sortorder = ACCENDING;
  }

  /**
   * @param asortby key
   * @param asortorder order
   */
  public SortBy(final int asortby, final int asortorder) {
    this.sortby = asortby;
    this.sortorder = asortorder;
  }

  /**
   * @return Sort
   */
  public int getSortBy() {
    return sortby;
  }

  /**
   * @return Order
   */
  public int getSortOrder() {
    return sortorder;
  }

  /**
   * @param asortby sort
   */
  public void setSortBy(final int asortby) {
    this.sortby = asortby;
  }

  /**
   * @param asortorder Order
   */
  public void setSortOrder(final int asortorder) {
    this.sortorder = asortorder;
  }
  // Private fields.
  /** Param. */
  private int sortby;
  /** Param. */
  private int sortorder;
}
