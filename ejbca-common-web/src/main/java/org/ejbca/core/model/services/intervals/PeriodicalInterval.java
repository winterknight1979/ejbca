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
package org.ejbca.core.model.services.intervals;

import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.services.BaseInterval;

/**
 * Class implementing a peridical IInterval for monitoring services.
 *
 * <p>The main method is getTimeToExecution
 *
 * @author Philip Vendil 2006 sep 27
 * @version $Id: PeriodicalInterval.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class PeriodicalInterval extends BaseInterval {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(PeriodicalInterval.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Param. */
  public static final String PROP_UNIT = "interval.periodical.unit";
  /** Param. */
  public static final String PROP_VALUE = "interval.periodical.value";

  /** Param. */
  public static final String UNIT_SECONDS = "SECONDS";
  /** Param. */
  public static final String UNIT_MINUTES = "MINUTES";
  /** Param. */
  public static final String UNIT_HOURS = "HOURS";
  /** Param. */
  public static final String UNIT_DAYS = "DAYS";

  /** Param. */
  public static final int UNITVAL_SECONDS = 1;
  /** Param. */
  public static final int UNITVAL_MINUTES = 60;
  /** Param. */
  public static final int UNITVAL_HOURS = 3600;
  /** Param. */
  public static final int UNITVAL_DAYS = 86400;

  /** Param. */
  public static final String[] AVAILABLE_UNITS = {
    UNIT_SECONDS, UNIT_MINUTES, UNIT_HOURS, UNIT_DAYS
  };
  /** Param. */
  public static final int[] AVAILABLE_UNITSVALUES = {
    UNITVAL_SECONDS, UNITVAL_MINUTES, UNITVAL_HOURS, UNITVAL_DAYS
  };

  /** Param. */
  private transient int interval = 0;

  /**
   * Methods that reads the interval from the configured properties and
   * transforms it into seconds.
   *
   * @see org.ejbca.core.model.services.IInterval#getTimeToExecution()
   */
  @Override
  public long getTimeToExecution() {
    LOG.trace(">PeriodicalInterval.getTimeToExecution()");
    if (interval == 0) {
      String unit = properties.getProperty(PROP_UNIT);
      if (unit == null) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.interval.errorconfig", serviceName, "UNIT");
        throw new EJBException(msg);
      }
      int unitval = 0;
      for (int i = 0; i < AVAILABLE_UNITS.length; i++) {
        if (AVAILABLE_UNITS[i].equalsIgnoreCase(unit)) {
          unitval = AVAILABLE_UNITSVALUES[i];
          break;
        }
      }
      if (unitval == 0) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.interval.errorconfig", serviceName, "UNIT");
        throw new EJBException(msg);
      }

      String value = properties.getProperty(PROP_VALUE);
      int intvalue = 0;
      try {
        intvalue = Integer.parseInt(value);
      } catch (NumberFormatException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.interval.errorconfig", serviceName, "VALUE");
        throw new EJBException(msg);
      }

      if (intvalue == 0) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.interval.errorconfig", serviceName, "UNIT");
        throw new EJBException(msg);
      }
      interval = intvalue * unitval;
    }
    LOG.debug("PeriodicalInterval.getTimeToExecution() : " + interval);
    return interval;
  }
}
