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
package org.ejbca.core.model.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.intervals.DummyInterval;

/**
 * Abstract base class that initializes the worker and its interval and action.
 *
 * @version $Id: BaseWorker.java 24488 2016-10-10 09:14:05Z anatom $
 */
public abstract class BaseWorker implements IWorker {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(BaseWorker.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Param. */
  protected Properties properties = null;
  /** Param. */
  protected String serviceName = null;
  /** Param. */
  protected ServiceConfiguration serviceConfiguration = null;
  /**
   * The time this service should have been running. Usually this is 'now'. But
   * is the appserver was down it can have been delayed execution
   */
  protected long runTimeStamp;
  /** The next time the service is scheduled to run. */
  protected long nextRunTimeStamp;

  /** Param. */
  private IAction action = null;
  /** Param. */
  private IInterval interval = null;

  /** Param. */
  protected AuthenticationToken admin = null;

  /** Param. */
  private transient Collection<Integer> cAIdsToCheck = null;
  /** Param. */
  private transient long timeBeforeExpire = -1;

  /** @see org.ejbca.core.model.services.IWorker#init */
  @Override
  public void init(
      final AuthenticationToken anadmin,
      final ServiceConfiguration aserviceConfiguration,
      final String aserviceName,
      final long arunTimeStamp,
      final long anextRunTimeStamp) {
    this.admin = anadmin;
    this.serviceName = aserviceName;
    this.runTimeStamp = arunTimeStamp;
    this.nextRunTimeStamp = anextRunTimeStamp;
    this.serviceConfiguration = aserviceConfiguration;
    this.properties = aserviceConfiguration.getWorkerProperties();

    String actionClassPath = aserviceConfiguration.getActionClassPath();
    if (actionClassPath != null) {
      try {
        action =
            (IAction)
                Thread.currentThread()
                    .getContextClassLoader()
                    .loadClass(actionClassPath)
                    .getConstructor()
                    .newInstance();
        action.init(aserviceConfiguration.getActionProperties(), aserviceName);
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.erroractionclasspath", aserviceName);
        LOG.error(msg, e);
      }
    } else {
      LOG.debug(
          "Warning no action class i defined for the service " + aserviceName);
    }

    String intervalClassPath = aserviceConfiguration.getIntervalClassPath();
    if (intervalClassPath != null) {
      try {
        interval =
            (IInterval)
                Thread.currentThread()
                    .getContextClassLoader()
                    .loadClass(intervalClassPath)
                    .getConstructor()
                    .newInstance();
        interval.init(
            aserviceConfiguration.getIntervalProperties(), aserviceName);
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.errorintervalclasspath", aserviceName);
        LOG.error(msg, e);
      }
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "services.errorintervalclasspath", aserviceName);
      LOG.error(msg);
    }

    if (interval == null) {
      interval = new DummyInterval();
    }
  }

  /** @see org.ejbca.core.model.services.IWorker#getNextInterval() */
  @Override
  public long getNextInterval() {
    return interval.getTimeToExecution();
  }

  /**
   * @return action
   */
  protected IAction getAction() {
    if (action == null) {
      String msg =
          INTRES.getLocalizedMessage(
              "services.erroractionclasspath", serviceName);
      LOG.error(msg);
    }
    return action;
  }

  /**
   * Returns the admin that should be used for other calls.
   *
   * @return token
   */
  protected AuthenticationToken getAdmin() {
    return admin;
  }

  /**
   * Returns the amount of time, in milliseconds that the expire time of
   * configured for.
   *
   * @return timw
   * @throws ServiceExecutionFailedException fail
   */
  protected long getTimeBeforeExpire() throws ServiceExecutionFailedException {
    final int ms = 1000;
    if (timeBeforeExpire == -1) {
      String unit = properties.getProperty(PROP_TIMEUNIT);
      if (unit == null) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.errorexpireworker.errorconfig", serviceName, "UNIT");
        throw new ServiceExecutionFailedException(msg);
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
                "services.errorexpireworker.errorconfig", serviceName, "UNIT");
        throw new ServiceExecutionFailedException(msg);
      }

      int intvalue = 0;
      try {
        intvalue =
            Integer.parseInt(properties.getProperty(PROP_TIMEBEFOREEXPIRING));
      } catch (NumberFormatException e) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.errorexpireworker.errorconfig", serviceName, "VALUE");
        throw new ServiceExecutionFailedException(msg);
      }

      if (intvalue == 0) {
        String msg =
            INTRES.getLocalizedMessage(
                "services.errorexpireworker.errorconfig", serviceName, "VALUE");
        throw new ServiceExecutionFailedException(msg);
      }
      timeBeforeExpire = (long) intvalue * unitval;
    }

    return timeBeforeExpire * ms;
  }

  /**
   * returns a collection of String with CAIds as gotten from the property
   * BaseWorker.PROP_CAIDSTOCHECK.
   *
   * @param includeAllCAsIfNull set to true if the 'catch all' SecConst.ALLCAS
   *     should be included in the list IF there does not exist a list. This
   *     CAId is not recognized by all recipients... This is due to that the
   *     feature of selecting CAs was enabled in EJBCA 3.9.1, and we want the
   *     service to keep working even after an upgrade from an earlier version.
   * @return Collection&lt;String&gt; of integer CA ids in String form, use
   *     Integer.valueOf to convert to int.
   * @throws ServiceExecutionFailedException fail
   */
  protected Collection<Integer> getCAIdsToCheck(
      final boolean includeAllCAsIfNull)
      throws ServiceExecutionFailedException {
    if (cAIdsToCheck == null) {
      cAIdsToCheck = new ArrayList<Integer>();
      String cas = properties.getProperty(PROP_CAIDSTOCHECK);
      if (LOG.isDebugEnabled()) {
        LOG.debug("CAIds to check: " + cas);
      }
      if (cas != null) {
        String[] caids = cas.split(";");
        for (int i = 0; i < caids.length; i++) {
          try {
            Integer.valueOf(caids[i]);
          } catch (Exception e) {
            String msg =
                INTRES.getLocalizedMessage(
                    "services.errorexpireworker.errorconfig",
                    serviceName,
                    PROP_CAIDSTOCHECK);
            throw new ServiceExecutionFailedException(msg, e);
          }
          cAIdsToCheck.add(Integer.valueOf(caids[i]));
        }
      } else if (includeAllCAsIfNull) {
        cAIdsToCheck.add(Integer.valueOf(SecConst.ALLCAS));
      }
    }
    return cAIdsToCheck;
  }
}
