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

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Date;

/**
 * This is a class containing information about one log event in the database.
 * Used mainly during database queries by the web interface.
 *
 * @author TomSelleck
 * @version $Id: LogEntry.java 26057 2017-06-22 08:08:34Z anatom $
 */
public class LogEntry implements Serializable {

  // Indicates the type of administrator.
  /** An administrator authenticated with client certificate. */
  public static final int TYPE_CLIENTCERT_USER = 0;
  /** A user of the public web pages. */
  public static final int TYPE_PUBLIC_WEB_USER = 1;
  /** An internal RA function, such as cmd line or CMP. */
  public static final int TYPE_RA_USER = 2;
  /** An internal CA admin function, such as cms line. */
  public static final int TYPE_CACOMMANDLINE_USER = 3;
  /** Batch generation tool. */
  public static final int TYPE_BATCHCOMMANDLINE_USER = 4;
  /** Internal user in EJBCA, such as automatic job .*/
  public static final int TYPE_INTERNALUSER = 5;

  /** param. */
  private final int id;
  /** One of LogEntry.TYPE_ constants. */
  private final int admintype;

  /** param. */
  private final String admindata;
  /** param. */
  private final int caid;
  /** param. */
  private final int module;
  /** param. */
  private final Date time;
  /** param. */
  private final String username;
  /** param. */
  private final String certificatesnr;
  /** param. */
  private final int event;
  /** param. */
  private final String comment;

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = -1L;

  /**
   * Function used by EJBCA to log information.
   *
   * @param anid ID
   * @param amadmintype is pricipally the type of data stored in the admindata
   *     field, should be one of org.ejbca.core.model.log.Admin.TYPE_ constants.
   * @param aadmindata is the data identifying the administrator, should be
   *     certificate snr or ip-address when no certificate could be retrieved.
   * @param acaid CA ID
   * @param amodule indicates from which module the event was logged. i.e one of
   *     the constans LogConstants.MODULE_RA, LogConstants.MODULE_CA ....
   * @param atime the time the event occured.
   * @param ausername the name of the user involved or null if no user is
   *     involved.
   * @param acertificatesnr the certificate involved in the event or null if no
   *     certificate is involved.
   * @param anevent id of the event, should be one of the
   *     org.ejbca.core.model.log.LogConstants.EVENT_ constants.
   * @param acomment comment of the event.
   */
  public LogEntry(
      final int anid,
      final int amadmintype,
      final String aadmindata,
      final int acaid,
      final int amodule,
      final Date atime,
      final String ausername,
      final String acertificatesnr,
      final int anevent,
      final String acomment) {
    this.id = anid;
    this.admintype = amadmintype;
    this.admindata = aadmindata;
    this.caid = acaid;
    this.module = amodule;
    this.time = atime;
    this.username = ausername;
    this.certificatesnr = acertificatesnr;
    this.event = anevent;
    this.comment = acomment;
  }

  // Public methods

  /**
   * Method used to map between event id and a string representation of event.
   *
   * @return a string representation of the event.
   */
  public String getEventName() {
    if (this.event < LogConstants.EVENT_ERROR_BOUNDRARY) {
      return LogConstants.EVENTNAMES_INFO[this.event];
    }
    if (this.event < LogConstants.EVENT_SYSTEM_BOUNDRARY) {
      return LogConstants.EVENTNAMES_ERROR[
          this.event - LogConstants.EVENT_ERROR_BOUNDRARY];
    }
    return LogConstants.EVENTNAMES_SYSTEM[
        this.event - LogConstants.EVENT_SYSTEM_BOUNDRARY];
  }

  /**
   * Method used to map between event id and a string representation of event.
   *
   * @param eventId ID
   * @return a string representation of the event.
   */
  public static String getEventName(final int eventId) {
    if (eventId < LogConstants.EVENT_ERROR_BOUNDRARY) {
      return LogConstants.EVENTNAMES_INFO[eventId];
    }
    if (eventId < LogConstants.EVENT_SYSTEM_BOUNDRARY) {
      return LogConstants.EVENTNAMES_ERROR[
          eventId - LogConstants.EVENT_ERROR_BOUNDRARY];
    }
    return LogConstants.EVENTNAMES_SYSTEM[
        eventId - LogConstants.EVENT_SYSTEM_BOUNDRARY];
  }

  /**
   * @return ID
   */
  public int getId() {
    return this.id;
  }

  /**
   * @return type
   */
  public int getAdminType() {
    return this.admintype;
  }

  /**
   * @return Data
   */
  public String getAdminData() {
    return this.admindata;
  }

  /**
   * @return ID
   */
  public int getCAId() {
    return this.caid;
  }

  /**
   * @return module
   */
  public int getModule() {
    return this.module;
  }

  /**
   * @return time
   */
  public Date getTime() {
    return this.time;
  }

  /**
   * @return user
   */
  public String getUsername() {
    return this.username;
  }

  /**
   * @return SN
   */
  public String getCertificateSNR() {
    return this.certificatesnr;
  }

  /**
   * @return event
   */
  public int getEvent() {
    return this.event;
  }

  /**
   * @return comment
   */
  public String getComment() {
    return this.comment;
  }
}
