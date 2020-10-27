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

import java.util.Date;
import org.apache.log4j.Logger;

/**
 * A class used by Query class to build a query for EJBCA RA modules.
 *
 * @version $Id: TimeMatch.java 25704 2017-04-18 14:42:43Z jeklund $
 */
public class TimeMatch extends BasicMatch {

  private static final long serialVersionUID = 555503673432162539L;
  /** Log. */
  private static final Logger LOG = Logger.getLogger(TimeMatch.class);

  /** UserMatch Specific Constant. */
  public static final int MATCH_WITH_TIMECREATED = 0;
  /** UserMatch Specific Constant.*/
  public static final int MATCH_WITH_TIMEMODIFIED = 1;

  /** ApprovalMatch Specific Constant. */
  public static final int MATCH_WITH_REQUESTORAPPROVALTIME = 0;
  /** ApprovalMatch Specific Constant. */
  public static final int MATCH_WITH_EXPIRETIME = 1;

  /** Represents the column names in (log,) UserData and ApprovalData tables. */
  private static final String[] MATCH_WITH_SQLNAMES = {
    "", "", "timeCreated", "timeModified", "requestDate", "expireDate"
  };

  /** Param. */
  private final int matchwith;
  /** Param. */
  private final int type;
  /** Param. */
  private final Date startdate;
  /** Param. */
  private final Date enddate;

  /**
   * Creates a new instance of TimeMatch. Constructor should only be used in ra
   * user queries.
   *
   * @param atype uses Query class constants to determine if it's a log query or
   *     ra query.
   * @param amatchwith should be one of MATCH_WITH constants to determine with
   *     field to search. Only used in ra user queries.
   * @param astartdate gives a startdate for the query, null if not needed.
   * @param anenddate gives a enddate for the query, null if not needed.
   */
  public TimeMatch(
      final int atype,
      final int amatchwith,
      final Date astartdate,
      final Date anenddate) {
    this.type = atype;
    this.matchwith = amatchwith;
    this.startdate = astartdate;
    this.enddate = anenddate;
  }

  /**
   * Creates a new instance of TimeMatch.
   *
   * @param atype uses Query class constants to determine if it's a log query or
   *     ra query.
   * @param astartdate gives a startdate for the query, null if not needed.
   * @param anenddate gives a enddate for the query, null if not needed.
   */
  public TimeMatch(
          final int atype, final Date astartdate, final Date anenddate) {
    this(atype, MATCH_WITH_TIMECREATED, astartdate, anenddate);
  }

  @Override
  public String getQueryString() {
    String returnval = "( ";
    if (startdate != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Making match with startdate: " + startdate);
      }
      returnval +=
          (MATCH_WITH_SQLNAMES[(type * 2) + matchwith]
              + " >= "
              + startdate.getTime()
              + " ");
      if (enddate != null) {
        returnval += " AND ";
      }
    }
    if (enddate != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Making match with enddate: " + enddate);
      }
      returnval +=
          (MATCH_WITH_SQLNAMES[(type * 2) + matchwith]
              + " <= "
              + enddate.getTime()
              + " ");
    }
    returnval += " )";
    return returnval;
  }

  @Override
  public boolean isLegalQuery() {
    return startdate != null || enddate != null;
  }
}
