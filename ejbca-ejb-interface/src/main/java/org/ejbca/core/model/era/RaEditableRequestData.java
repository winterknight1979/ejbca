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
package org.ejbca.core.model.era;

import java.io.Serializable;

/**
 * @version $Id: RaEditableRequestData.java 23548 2016-05-26 08:01:44Z samuellb
 *     $
 */
public class RaEditableRequestData implements Serializable, Cloneable {

  private static final long serialVersionUID = 1L;

  // For add end entity requests
  /** Param. */
  private String username;
  /** Param. */
  private String subjectDN;
  /** Param. */
  private String subjectAltName;
  /** Param. */
  private String subjectDirAttrs;
  /** Param. */
  private String email;

  /**
   * @return user
   */
  public String getUsername() {
    return username;
  }

  /**
   * @param ausername user
   */
  public void setUsername(final String ausername) {
    this.username = ausername;
  }

  /**
   * @return DN
   */
  public String getSubjectDN() {
    return subjectDN;
  }

  /**
   * @param asubjectDN DN
   */
  public void setSubjectDN(final String asubjectDN) {
    this.subjectDN = asubjectDN;
  }

  /**
   * @return name
   */
  public String getSubjectAltName() {
    return subjectAltName;
  }

  /**
   * @param asubjectAltName name
   */
  public void setSubjectAltName(final String asubjectAltName) {
    this.subjectAltName = asubjectAltName;
  }

  /**
   * @return attrs
   */
  public String getSubjectDirAttrs() {
    return subjectDirAttrs;
  }

  /**
   * @param thesubjectDirAttrs attrs
   */
  public void setSubjectDirAttrs(final String thesubjectDirAttrs) {
    this.subjectDirAttrs = thesubjectDirAttrs;
  }

  /**
   * @return email
   */
  public String getEmail() {
    return email;
  }

  /**
   * @param anemail email
   */
  public void setEmail(final String anemail) {
    this.email = anemail;
  }

  @Override
  public RaEditableRequestData clone() {
    try {
      return (RaEditableRequestData) super.clone();
    } catch (CloneNotSupportedException e) {
      throw new IllegalStateException("Object should be clonable");
    }
  }
}
