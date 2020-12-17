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

package org.ejbca.core.model.services.workers;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;

/**
 * @version $Id: EmailSendingWorker.java 22117 2015-10-29 10:53:42Z mikekushner
 *     $
 */
public abstract class EmailSendingWorker extends BaseWorker {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(EmailSendingWorker.class);

  /** Default constructor. */
  private transient String endUserSubject = null;
  /** Default constructor. */
  private transient String adminSubject = null;
  /** Default constructor. */
  private transient String endUserMessage = null;
  /** Default constructor. */
  private transient String adminMessage = null;

  /** Default constructor. */
  public EmailSendingWorker() {
    super();
  }

  class EmailCertData {

        /** Param. */
    private String fingerPrint = null;
    /** Param. */
    private MailActionInfo actionInfo = null;

    /**
     * @param afingerPrint FP
     * @param theactionInfo Info
     */
    EmailCertData(
        final String afingerPrint, final MailActionInfo theactionInfo) {
      super();
      this.fingerPrint = afingerPrint;
      this.actionInfo = theactionInfo;
    }

    public String getFingerPrint() {
      return fingerPrint;
    }

    public MailActionInfo getActionInfo() {
      return actionInfo;
    }
  }

  /**
   * Method that must be implemented by all subclasses to EmailSendingWorker,
   * used to update status of a certificate, user, or similar.
   *
   * @param pk primary key of object to update
   * @param status status to update to
   */
  protected abstract void updateStatus(String pk, int status);

  /**
   * @param queue Queue
   * @param ejbs Beans
   * @throws ServiceExecutionFailedException Fail
   */
  protected void sendEmails(
      final ArrayList<EmailCertData> queue, final Map<Class<?>, Object> ejbs)
      throws ServiceExecutionFailedException {
    Iterator<EmailCertData> iter = queue.iterator();
    while (iter.hasNext()) {
      try {
        EmailCertData next = iter.next();
        getAction().performAction(next.getActionInfo(), ejbs);
        updateStatus(
            next.getFingerPrint(),
            CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION);
      } catch (Exception fe) {
        LOG.error("Error sending emails: ", fe);
        throw new ServiceExecutionFailedException(fe);
      }
    }
  }

  /**
   * @return message
   */
  protected String getAdminMessage() {
    if (adminMessage == null) {
      adminMessage =
          properties.getProperty(
              EmailSendingWorkerConstants.PROP_ADMINMESSAGE,
              "No Message Configured");
    }
    return adminMessage;
  }

  /**
   * @return subject
   */
  protected String getAdminSubject() {
    if (adminSubject == null) {
      adminSubject =
          properties.getProperty(
              EmailSendingWorkerConstants.PROP_ADMINSUBJECT,
              "No Subject Configured");
    }

    return adminSubject;
  }

  /**
   * @return message
   */
  protected String getEndUserMessage() {
    if (endUserMessage == null) {
      endUserMessage =
          properties.getProperty(
              EmailSendingWorkerConstants.PROP_USERMESSAGE,
              "No Message Configured");
    }

    return endUserMessage;
  }

  /**
   * @return subject
   */
  protected String getEndUserSubject() {
    if (endUserSubject == null) {
      endUserSubject =
          properties.getProperty(
              EmailSendingWorkerConstants.PROP_USERSUBJECT,
              "No Subject Configured");
    }

    return endUserSubject;
  }

  /**
   * @return bool
   */
  protected boolean isSendToAdmins() {
    return properties
        .getProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE")
        .equalsIgnoreCase("TRUE");
  }

  /**
   * @return bool
   */
  protected boolean isSendToEndUsers() {
    return properties
        .getProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE")
        .equalsIgnoreCase("TRUE");
  }
}
