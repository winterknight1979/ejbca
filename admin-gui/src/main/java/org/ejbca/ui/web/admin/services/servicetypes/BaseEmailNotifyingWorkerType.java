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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.faces.model.SelectItem;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class managing the view of the Certificate Expiration Notifier Worker.
 *
 * @version $Id: BaseEmailNotifyingWorkerType.java 28844 2018-05-04 08:31:02Z
 *     samuellb $
 */
public abstract class BaseEmailNotifyingWorkerType extends BaseWorkerType {

      /** Param. */
  public static final boolean DEFAULT_USEENDUSERNOTIFICATIONS = false;
  /** Param. */
  public static final boolean DEFAULT_USEADMINNOTIFICATIONS = false;

  private static final long serialVersionUID = -4521088640797284656L;

  /** Param. */
  private String timeUnit = DEFAULT_TIMEUNIT;
  /** Param. */
  private String timeValue = DEFAULT_TIMEVALUE;
  /** Param. */
  private boolean useEndUserNotifications = DEFAULT_USEENDUSERNOTIFICATIONS;
  /** Param. */
  private boolean useAdminNotifications = DEFAULT_USEADMINNOTIFICATIONS;
  /** Param. */
  private String endUserSubject = "";
  /** Param. */
  private String adminSubject = "";
  /** Param. */
  private String endUserMessage = "";
  /** Param. */
  private String adminMessage = "";

  /**
   * @param name Name
   * @param jsp PAge
   * @param classpath CP
   */
  public BaseEmailNotifyingWorkerType(
      final String name, final String jsp, final String classpath) {
    super(jsp, name, true, classpath);

    addCompatibleActionTypeName(MailActionType.NAME);
    addCompatibleActionTypeName(NoActionType.NAME);

    addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
  }

  /**
   * Overrides.
   *
   * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties
   */
  @Override
  public Properties getProperties(final ArrayList<String> errorMessages)
      throws IOException {
    Properties retval = super.getProperties(errorMessages);

    retval.setProperty(IWorker.PROP_TIMEUNIT, timeUnit);

    try {
      int value = Integer.parseInt(timeValue);
      if (value < 1) {
        throw new NumberFormatException();
      }
    } catch (NumberFormatException e) {
      errorMessages.add("TIMEBEFOREEXPIRATIONERROR");
    }
    retval.setProperty(IWorker.PROP_TIMEBEFOREEXPIRING, timeValue);

    if (useEndUserNotifications) {
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "TRUE");
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_USERSUBJECT, endUserSubject);
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_USERMESSAGE, endUserMessage);
    } else {
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
      retval.setProperty(EmailSendingWorkerConstants.PROP_USERSUBJECT, "");
      retval.setProperty(EmailSendingWorkerConstants.PROP_USERMESSAGE, "");
    }

    if (useAdminNotifications) {
      retval.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "TRUE");
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_ADMINSUBJECT, adminSubject);
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_ADMINMESSAGE, adminMessage);
    } else {
      retval.setProperty(
          EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
      retval.setProperty(EmailSendingWorkerConstants.PROP_ADMINSUBJECT, "");
      retval.setProperty(EmailSendingWorkerConstants.PROP_ADMINMESSAGE, "");
    }

    return retval;
  }

  /**
   * Overrides.
   *
   * @see
   *     org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
   */
  @Override
  public void setProperties(final Properties properties) throws IOException {
    super.setProperties(properties);

    timeUnit = properties.getProperty(IWorker.PROP_TIMEUNIT, DEFAULT_TIMEUNIT);
    timeValue =
        properties.getProperty(
            IWorker.PROP_TIMEBEFOREEXPIRING, DEFAULT_TIMEVALUE);

    useEndUserNotifications =
        properties
            .getProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "")
            .equalsIgnoreCase("TRUE");
    useAdminNotifications =
        properties
            .getProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "")
            .equalsIgnoreCase("TRUE");

    endUserSubject =
        properties.getProperty(
            EmailSendingWorkerConstants.PROP_USERSUBJECT, "");
    adminSubject =
        properties.getProperty(
            EmailSendingWorkerConstants.PROP_ADMINSUBJECT, "");
    endUserMessage =
        properties.getProperty(
            EmailSendingWorkerConstants.PROP_USERMESSAGE, "");
    adminMessage =
        properties.getProperty(
            EmailSendingWorkerConstants.PROP_ADMINMESSAGE, "");
  }

  /**
   * @return Unit
   */
  public String getTimeUnit() {
    return timeUnit;
  }

  /**
   * @param unit unit
   */
  public void setTimeUnit(final String unit) {
    this.timeUnit = unit;
  }

  /**
   * @return units
   */
  public List<SelectItem> getAvailableUnits() {
    ArrayList<SelectItem> retval = new ArrayList<>();
    for (int i = 0; i < PeriodicalInterval.AVAILABLE_UNITS.length; i++) {
      retval.add(
          new SelectItem(
              PeriodicalInterval.AVAILABLE_UNITS[i],
              EjbcaJSFHelper.getBean()
                  .getText()
                  .get(PeriodicalInterval.AVAILABLE_UNITS[i])));
    }

    return retval;
  }

  /**
   * @return message
   */
  public String getAdminMessage() {
    return adminMessage;
  }

  /**
   * @param anadminMessage message
   */
  public void setAdminMessage(final String anadminMessage) {
    this.adminMessage = anadminMessage;
  }

  /**
   * @return subj
   */
  public String getAdminSubject() {
    return adminSubject;
  }

  /**
   * @param anadminSubject subj
   */
  public void setAdminSubject(final String anadminSubject) {
    this.adminSubject = anadminSubject;
  }

  /**
   * @return message
   */
  public String getEndUserMessage() {
    return endUserMessage;
  }

  /**
   * @param anendUserMessage USer
   */
  public void setEndUserMessage(final String anendUserMessage) {
    this.endUserMessage = anendUserMessage;
  }

  /**
   * @return subj
   */
  public String getEndUserSubject() {
    return endUserSubject;
  }

  /**
   * @param anendUserSubject subj
   */
  public void setEndUserSubject(final String anendUserSubject) {
    this.endUserSubject = anendUserSubject;
  }

  /**
   * @return a
   */
  public String getTimeValue() {
    return timeValue;
  }

  /**
   * @param atimeValue time
   */
  public void setTimeValue(final String atimeValue) {
    this.timeValue = atimeValue;
  }

  /**
   * @return bool
   */
  public boolean isUseAdminNotifications() {
    return useAdminNotifications;
  }

  /**
   * @param douseAdminNotifications bool
   */
  public void setUseAdminNotifications(final boolean douseAdminNotifications) {
    this.useAdminNotifications = douseAdminNotifications;
  }

  /**
   * @return bool
   */
  public boolean isUseEndUserNotifications() {
    return useEndUserNotifications;
  }

  /**
   * @param douseEndUserNotifications bool
   */
  public void setUseEndUserNotifications(
      final boolean douseEndUserNotifications) {
    this.useEndUserNotifications = douseEndUserNotifications;
  }
}
