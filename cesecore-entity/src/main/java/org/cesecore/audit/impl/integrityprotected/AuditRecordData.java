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
package org.cesecore.audit.impl.integrityprotected;

import java.io.Serializable;
import java.util.Map;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.apache.commons.lang.StringUtils;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypeHolder;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ModuleTypeHolder;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.enums.ServiceTypeHolder;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.GUIDGenerator;
import org.cesecore.util.XmlSerializerUtil;

/**
 * This class represents an audit log record.
 *
 * <p>The following index is recommended as a minimum: create unique index
 * auditrecorddata_idx1 on AuditRecordData (nodeId,timeStamp,sequenceNumber);
 *
 * @version $Id: AuditRecordData.java 28560 2018-03-27 12:39:10Z
 *     jekaterina_b_helmes $
 */
@Entity
@Table(name = "AuditRecordData")
public class AuditRecordData extends ProtectedData
    implements Serializable, AuditLogEntry {

  private static final long serialVersionUID = 3998646190932834045L;

  /** Key. */
  private String pk;
  /** ID. */
  private String nodeId;
  /** Sequence. */
  private Long sequenceNumber;
  /** Time. */
  private Long timeStamp;
  /** Type. */
  private String eventType;
  /** Status. */
  private String eventStatus;
  /** Auth. */
  private String authToken;
  /** Service. */
  private String service;
  /** Mod. */
  private String module;
  /**ID. */
  private String customId;
  /** Search. */
  private String searchDetail1;
  /** Search. */
  private String searchDetail2;
  /** Details. */
  private String additionalDetails;
  /** Version. */
  private int rowVersion = 0;
  /** Protection. */
  private String rowProtection;

  /** Null constructor. */
  public AuditRecordData() { }

  /**   *
   * @param aNodeId ID
   * @param aSequenceNumber SN
   * @param aTimeStamp TS
   * @param anEventType Type
   * @param anEventStatus Status
   * @param anAuthToken Token
   * @param aService Service
   * @param aModule Mod
   * @param aCustomId ID
   * @param theSearchDetail1 Search
   * @param theSearchDetail2 Search
   * @param theAdditionalDetails Details
   */
  public AuditRecordData(// NOPMD
      final String aNodeId,
      final Long aSequenceNumber,
      final Long aTimeStamp,
      final EventType anEventType,
      final EventStatus anEventStatus,
      final String anAuthToken,
      final ServiceType aService,
      final ModuleType aModule,
      final String aCustomId,
      final String theSearchDetail1,
      final String theSearchDetail2,
      final Map<String, Object> theAdditionalDetails) {
    this.pk = GUIDGenerator.generateGUID(this);
    this.nodeId = aNodeId;
    this.sequenceNumber = aSequenceNumber;
    this.timeStamp = aTimeStamp;
    this.eventType = anEventType.toString();
    this.eventStatus = anEventStatus.toString();
    this.authToken = anAuthToken;
    this.service = aService.toString();
    this.module = aModule.toString();
    this.customId = aCustomId;
    this.searchDetail1 = theSearchDetail1;
    this.searchDetail2 = theSearchDetail2;
    setMapAdditionalDetails(theAdditionalDetails);
  }

  /** @return the primary key */
  public String getPk() {
    return pk;
  }

  /** @param apk is the primary key */
  public void setPk(final String apk) {
    this.pk = apk;
  }

  @Override
  public String getNodeId() {
    return nodeId;
  }

  /** @param aNodeId The node identifier that this log record comes from. */
  public void setNodeId(final String aNodeId) {
    this.nodeId = aNodeId;
  }

  @Override
  public Long getSequenceNumber() {
    return sequenceNumber;
  }

  /** @param aSequenceNumber This log sequence number MUST be unique. */
  public void setSequenceNumber(final Long aSequenceNumber) {
    this.sequenceNumber = aSequenceNumber;
  }

  @Override
  public Long getTimeStamp() {
    return timeStamp;
  }

  /** @param aTimeStamp Sets Timestamp to this value. */
  public void setTimeStamp(final Long aTimeStamp) {
    this.timeStamp = aTimeStamp;
  }

  /** @return event type string. @see EventTypes */
  public String getEventType() {
    return eventType;
  }

  /**
   * Sets event type. @see EventTypes
   *
   * @param anEventType should match the enumeration names.
   */
  public void setEventType(final String anEventType) {
    this.eventType = anEventType;
  }

  /** @return event status. @see EventStatusEnum */
  public String getEventStatus() {
    return eventStatus;
  }

  @Transient
  @Override
  public EventStatus getEventStatusValue() {
    return EventStatus.valueOf(getEventStatus());
  }

  /**
   * Sets event type. @see EventStatusEnum
   *
   * @param anEventStatus should match the enumeration names.
   */
  public void setEventStatus(final String anEventStatus) {
    this.eventStatus = anEventStatus;
  }

  @Override
  public String getAuthToken() {
    return authToken;
  }

  /**
   * Sets the user that triggered the creation of a log.
   *
   * @param anAuthToken user id. Normally obtained by the following example:
   *     authenticationToken.toString()
   */
  public void setAuthToken(final String anAuthToken) {
    this.authToken = anAuthToken;
  }

  /**
   * Gets service type. @see ServiceTypes
   *
   * @return service
   */
  public String getService() {
    return service;
  }

  /**
   * Sets service type. @see ServiceTypes
   *
   * @param aService service
   */
  public void setService(final String aService) {
    this.service = aService;
  }

  /**
   * Gets module type. @see ModuleTypes
   *
   * @return module type.
   */
  public String getModule() {
    return module;
  }

  /**
   * Sets module type. @see ModuleTypes
   *
   * @param aModule Module type.
   */
  public void setModule(final String aModule) {
    this.module = aModule;
  }

  @Override
  public String getCustomId() {
    return customId;
  }

  /**
   * @param aCustomId ID
   */
  public void setCustomId(final String aCustomId) {
    this.customId = aCustomId;
  }

  @Override
  public String getSearchDetail1() {
    return searchDetail1;
  }

  /**
   * @param aSearchDetail1 Search
   */
  public void setSearchDetail1(final String aSearchDetail1) {
    this.searchDetail1 = aSearchDetail1;
  }

  @Override
  public String getSearchDetail2() {
    return searchDetail2;
  }

  /**
   * @param aSearchDetail2 Search
   */
  public void setSearchDetail2(final String aSearchDetail2) {
    this.searchDetail2 = aSearchDetail2;
  }

  /**
   * @return RDN value
   */
  @Transient
  public String getUnescapedRndValue() {
    String value = getAdditionalDetails();
    if (StringUtils.isNotEmpty(value)) {
      return CertTools.getUnescapedRdnValue(value);
    } else {
      return value;
    }
  }

  /** @return additional details in raw format. */
  public String getAdditionalDetails() {
    return additionalDetails;
  }

  /**
   * Sets additional details in raw format.
   *
   * @param theAdditionalDetails details
   */
  public void setAdditionalDetails(final String theAdditionalDetails) {
    this.additionalDetails = theAdditionalDetails;
  }

  /**
   * @return version
   */
  // @Version @Column
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param aRowVersion version
   */
  public void setRowVersion(final int aRowVersion) {
    this.rowVersion = aRowVersion;
  }

  // @Column @Lob
  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Override
  public void setRowProtection(final String aRowProtection) {
    this.rowProtection = aRowProtection;
  }

  /** @return additional details. */
  @Transient
  @Override
  public Map<String, Object> getMapAdditionalDetails() {
    // TODO: Decide on which implementation to use for serialization of the
    // additional details
    return XmlSerializerUtil.decode(getUnescapedRndValue());
  }

  /** @param theAdditionalDetails additional details. */
  @Transient
  public void setMapAdditionalDetails(
      final Map<String, Object> theAdditionalDetails) {
    // TODO: Decide on which implementation to use for serialization of the
    // additional details
    setAdditionalDetails(XmlSerializerUtil.encode(theAdditionalDetails));
    // setAdditionalDetails(JsonSerializer.toJSON(additionalDetails));
  }

  //
  // Start Database integrity protection methods
  //

  @Transient
  @Override
  protected String getProtectString(final int version) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder();
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getPk())
        .append(getNodeId())
        .append(getSequenceNumber())
        .append(getTimeStamp());
    build
        .append(getEventType())
        .append(getEventStatus())
        .append(getAuthToken())
        .append(getService())
        .append(getModule());
    build
        .append(getCustomId())
        .append(getSearchDetail1())
        .append(getSearchDetail2())
        .append(getAdditionalDetails());
    return build.toString();
  }

  @Transient
  @Override
  protected int getProtectVersion() {
    return 1;
  }

  @PrePersist
  @PreUpdate
  @Override
  protected void protectData() {
    super.protectData();
  }

  @PostLoad
  @Override
  protected void verifyData() {
    super.verifyData();
  }

  @Override
  @Transient
  protected String getRowId() {
    return getPk();
  }
  //
  // End Database integrity protection methods
  //

  @Override
  @Transient
  public EventType getEventTypeValue() {
    return new EventTypeHolder(getEventType());
  }

  @Override
  @Transient
  public ModuleType getModuleTypeValue() {
    return new ModuleTypeHolder(getModule());
  }

  @Override
  @Transient
  public ServiceType getServiceTypeValue() {
    return new ServiceTypeHolder(getService());
  }
}
