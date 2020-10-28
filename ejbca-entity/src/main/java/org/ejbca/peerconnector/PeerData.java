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
package org.ejbca.peerconnector;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Basic entity been for peer types.
 *
 * <p>INT4 id VARCHAR(25x) name INT4 connectorState (0=disabled, 1=enabled)
 * VARCHAR(25x) url CLOB data: initiator capabilities INT4 rowVersion CLOB
 * rowProtection
 *
 * @version $Id: PeerData.java 19902 2014-09-30 14:32:24Z anatom $
 */
@Entity
@Table(name = "PeerData")
public class PeerData extends ProtectedData implements Serializable {

  private static final long serialVersionUID = 3304969435926944799L;
  /** Data. */
  private int rowVersion = 0;
  /** Data. */
  private String rowProtection;

  /** Data. */
  private int id;
  /** Data. */
  private String name;
  /** Data. */
  private int connectorState;
  /** Data. */
  private String url;
  /** Data. */
  private String data;

  /** Empty. */
  public PeerData() {
    super();
  }

  /**
   * @param anid ID
   * @param aname NAme
   * @param aurl URL
   * @param aconnectorState State
   * @param thedata Data
   */
  public PeerData(
      final int anid,
      final String aname,
      final String aurl,
      final int aconnectorState,
      final String thedata) {
    super();
    this.id = anid;
    this.name = aname;
    this.setUrl(aurl);
    this.setConnectorState(aconnectorState);
    this.data = thedata;
  }

  /**
   * @return ID
   */
  public int getId() {
    return id;
  }

  /**
   * @param anid ID
   */
  public void setId(final int anid) {
    this.id = anid;
  }

  /**
   * @return name
   */
  public String getName() {
    return name;
  }

  /**
   * @param aname name
   */
  public void setName(final String aname) {
    this.name = aname;
  }

  /**
   * @return data
   */
  public String getData() {
    return data;
  }

  /**
   * @param thedata data
   */
  public void setData(final String thedata) {
    this.data = thedata;
  }

  /**
   * @return version
   */
  public int getRowVersion() {
    return rowVersion;
  }

  /**
   * @param arowVersion version
   */
  public void setRowVersion(final int arowVersion) {
    this.rowVersion = arowVersion;
  }

  //
  // Start Database integrity protection methods
  //

  @Override
  protected String getProtectString(final int rowversion) {
    final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
    // What is important to protect here is the data that we define
    // rowVersion is automatically updated by JPA, so it's not important, it is
    // only used for optimistic locking
    build
        .append(getData())
        .append(getUrl())
        .append(getId())
        .append(getName())
        .append(getConnectorState());
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
  public void setRowProtection(final String arowProtection) {
    this.rowProtection = arowProtection;
  }

  @Override
  public String getRowProtection() {
    return rowProtection;
  }

  @Transient
  @Override
  protected String getRowId() {
    return String.valueOf(getId());
  }

  /**
   * @return state
   */
  public int getConnectorState() {
    return connectorState;
  }

  /**
   * @param aconnectorState state
   */
  public void setConnectorState(final int aconnectorState) {
    this.connectorState = aconnectorState;
  }

  /**
   * @return URL
   */
  public String getUrl() {
    return url;
  }

  /**
   * @param aurl URL
   */
  public void setUrl(final String aurl) {
    this.url = aurl;
  }
}
