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
package org.cesecore.audit;

import java.util.Map;
import java.util.Properties;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.TrustedTime;

/**
 * Interface for writing secure audit events.
 *
 * @version $Id: AuditLogger.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public interface AuditLogger {
  /**
   * Creates a signed log, stored in the database.
   *
   * @param trustedTime TrustedTime instance will be used to get a trusted
   *     timestamp.
   * @param event  Event
   * @param module The module where the operation took place.
   * @param service The service(application) that performed the operation.
   * @param authToken The authentication token that invoked the operation.
   * @param customId ID
   * @param details  Details
   *
   * @throws AuditRecordStorageException if unable to store the log record
   */
  void log(
      TrustedTime trustedTime,
      Event event,
      ModuleType module,
      ServiceType service,
      String authToken,
      String customId,
      Details details
      )
      throws AuditRecordStorageException;

   class Event {
          /** Param. */
      private final EventType eventType;
      /** Param. */
      private final EventStatus eventStatus;

      /**
        * @param type The event log type.
        * @param status The status of the operation to log.
       */
    public Event(final EventType type, final EventStatus status) {
        this.eventType = type;
        this.eventStatus = status;
    }
    /**
     * @return the eventType
     */
    public EventType getEventType() {
        return eventType;
    }
    /**
     * @return the eventStatus
     */
    public EventStatus getEventStatus() {
        return eventStatus;
    }
  }


   class Details {
          /** Param. */
      private final String searchDetail1;
      /** Param. */
      private final String searchDetail2;
      /** Param. */
      private final Map<String, Object> additionalDetails;
      /** Param. */
      private final Properties properties;

      /**
       * @param d1 Search 1
       * @param d2 Search 2
       * @param aD Additional details to be logged.
       * @param props properties to be passed on the device
       */
      public Details(
              final String d1,
              final String d2,
              final Map<String, Object> aD,
              final Properties props) {
          this.searchDetail1 = d1;
          this.searchDetail2 = d2;
          this.additionalDetails = aD;
          this.properties = props;
      }

    /**
     * @return the searchDetail1
     */
    public String getSearchDetail1() {
        return searchDetail1;
    }

    /**
     * @return the searchDetail2
     */
    public String getSearchDetail2() {
        return searchDetail2;
    }

    /**
     * @return the additionalDetails
     */
    public Map<String, Object> getAdditionalDetails() {
        return additionalDetails;
    }

    /**
     * @return the properties
     */
    public Properties getProperties() {
        return properties;
    }


   }
}
