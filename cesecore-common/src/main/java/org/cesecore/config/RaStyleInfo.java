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

package org.cesecore.config;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Represents an individual RA Style Archive. May or may not contain logo files,
 * mulitple CSS files and identifiers.
 *
 * @version $Id: RaStyleInfo.java 26914 2017-10-27 10:10:32Z henriks $
 */
public class RaStyleInfo implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Random generator. */
  private static final Random RANDOM = new Random();

  /** ID. */
  private int archiveId;
  /** Map. */
  private Map<String, RaCssInfo> raCssInfos;
  /** Bytes. */
  private byte[] logoBytes;
  /** Name. */
  private String logoName;
  /** Type. */
  private String logoContentType;
  /** Archive. */
  private String archiveName;

  /**
   * Creates a RA CSS Info object to hold information and CSS data to be stored
   * in database for deployment on RA-web.
   *
   * @param fileName name of the archive
   * @param aRaCssInfos List of CSS info holders. May be null
   * @param aLogoBytes Byte array of custom logo. May be null
   * @param aLogoName Name of custom logo. May be null
   */
  public RaStyleInfo(
      final String fileName,
      final Map<String, RaCssInfo> aRaCssInfos,
      final byte[] aLogoBytes,
      final String aLogoName) {
    this.archiveId = RANDOM.nextInt();
    if (aRaCssInfos == null) {
      this.raCssInfos = new HashMap<>();
    } else {
      this.raCssInfos = aRaCssInfos;
    }
    this.logoBytes = aLogoBytes;
    this.archiveName = fileName;
    this.logoName = aLogoName;
  }

  @SuppressWarnings("serial")
  public static class RaCssInfo implements Serializable {
    /** Bytes. */
    private byte[] cssBytes;
    /** Name. */
    private String cssName;

    /**
     * @param aCssBytes bytes
     * @param aCssName name
     */
    public RaCssInfo(final byte[] aCssBytes, final String aCssName) {
      this.cssBytes = aCssBytes;
      this.cssName = aCssName;
    }

    /**
     * @return bytes
     */
    public byte[] getCssBytes() {
      return cssBytes;
    }

    /**
     * @param aCssBytes bytes
     */
    public void setCssBytes(final byte[] aCssBytes) {
      this.cssBytes = aCssBytes;
    }

    /**
     * @return name
     */
    public String getCssName() {
      return cssName;
    }

    /**
     * @param aCssName name
     */
    public void setCssName(final String aCssName) {
      this.cssName = aCssName;
    }
  }

  /** @return unique id for RaCssInfo object */
  public int getArchiveId() {
    return archiveId;
  }

  /**
   * Should not be used normally!
   *
   * @param aArchiveId ID
   */
  public void setArchiveId(final int aArchiveId) {
    this.archiveId = aArchiveId;
  }

  /** @param raCssInfo CSS info added to archive */
  public void addRaCssInfo(final RaCssInfo raCssInfo) {
    this.raCssInfos.put(raCssInfo.getCssName(), raCssInfo);
  }

  /** @return Map of all CSS infos in archive */
  public Map<String, RaCssInfo> getRaCssInfos() {
    return raCssInfos;
  }

  /** @return List of all CSS infos in the archive */
  public List<RaCssInfo> getRaCssValues() {
    return new ArrayList<RaCssInfo>(getRaCssInfos().values());
  }

  /** @param aRaCssInfos sets a list of CSS infos to archive */
  public void setRaCssInfos(final HashMap<String, RaCssInfo> aRaCssInfos) {
    this.raCssInfos = aRaCssInfos;
  }

  /** @return byte array of logo */
  public byte[] getLogoBytes() {
    return logoBytes;
  }

  /** @param aLogoBytes logoBytes of logo image */
  public void setLogoBytes(final byte[] aLogoBytes) {
    this.logoBytes = aLogoBytes;
  }

  /** @return file name associated with CSS */
  public String getArchiveName() {
    return archiveName;
  }

  /** @param fileName to be associated with CSS */
  public void setArchiveName(final String fileName) {
    this.archiveName = fileName;
  }

  /** @return name of logo */
  public String getLogoName() {
    return logoName;
  }

  /** @param aLogoName sets logo name */
  public void setLogoName(final String aLogoName) {
    this.logoName = aLogoName;
  }

  /** @return content type of logo, e.g 'image/png' */
  public String getLogoContentType() {
    return logoContentType;
  }

  /** @param aLogoContentType e.g 'image/png' */
  public void setLogoContentType(final String aLogoContentType) {
    this.logoContentType = aLogoContentType;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + archiveId;
    return result;
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    RaStyleInfo other = (RaStyleInfo) obj;
    return archiveId == other.archiveId;
  }
}
