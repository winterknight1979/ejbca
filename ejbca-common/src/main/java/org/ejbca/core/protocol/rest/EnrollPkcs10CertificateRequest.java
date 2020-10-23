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
package org.ejbca.core.protocol.rest;

import java.io.Serializable;

/**
 * A DTO class representing the input for certificate enrollment.
 *
 * @version $Id: EnrollPkcs10CertificateRequest.java 28909 2018-05-10 12:16:53Z
 *     tarmo_r_helmes $
 */
public final class EnrollPkcs10CertificateRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private final String certificateRequest;
  /** Param. */
  private final String certificateProfileName;
  /** Param. */
  private final String endEntityProfileName;
  /** Param. */
  private final String certificateAuthorityName;
  /** Param. */
  private final String username;
  /** Param. */
  private final String password;

  /**
   * @return req
   */
  public String getCertificateRequest() {
    return certificateRequest;
  }

  /**
   * @return profile
   */
  public String getCertificateProfileName() {
    return certificateProfileName;
  }

  /**
   * @return profile
   */
  public String getEndEntityProfileName() {
    return endEntityProfileName;
  }

  /**
   * @return Auth
   */
  public String getCertificateAuthorityName() {
    return certificateAuthorityName;
  }

  /**
   * @return User
   */
  public String getUsername() {
    return username;
  }

  /**
   * @return Pass
   */
  public String getPassword() {
    return password;
  }

  public static class Builder {
	    /** Param. */
    private String certificateRequest;
    /** Param. */
    private String certificateProfileName;
    /** Param. */
    private String endEntityProfileName;
    /** Param. */
    private String certificateAuthorityName;
    /** Param. */
    private String username;
    /** Param. */
    private String password;

    /**
     * @param acertificateRequest request
     * @return this
     */
    public Builder certificateRequest(final String acertificateRequest) {
      this.certificateRequest = acertificateRequest;
      return this;
    }

    /**
     * @param acertificateProfileName profie
     * @return this
     */
    public Builder certificateProfileName(
    		final String acertificateProfileName) {
      this.certificateProfileName = acertificateProfileName;
      return this;
    }

    /**
     * @param anendEntityProfileName profile
     * @return this
     */
    public Builder endEntityProfileName(final String anendEntityProfileName) {
      this.endEntityProfileName = anendEntityProfileName;
      return this;
    }

    /**
     * @param acertificateAuthorityName authority
     * @return this
     */
    public Builder certificateAuthorityName(
        final String acertificateAuthorityName) {
      this.certificateAuthorityName = acertificateAuthorityName;
      return this;
    }

    /**
     * @param ausername user
     * @return   this
     * */   
    public Builder username(final String ausername) {
      this.username = ausername;
      return this;
    }

    /**
     * @param apassword password
     * @return this
     */
    public Builder password(final String apassword) {
      this.password = apassword;
      return this;
    }

    /**
     * @return request
     */
    public EnrollPkcs10CertificateRequest build() {
      return new EnrollPkcs10CertificateRequest(this);
    }
  }

  /**
   * @param builder Builder
   */
  private EnrollPkcs10CertificateRequest(final Builder builder) {
    this.certificateRequest = builder.certificateRequest;
    this.certificateProfileName = builder.certificateProfileName;
    this.endEntityProfileName = builder.endEntityProfileName;
    this.certificateAuthorityName = builder.certificateAuthorityName;
    this.username = builder.username;
    this.password = builder.password;
  }
}
