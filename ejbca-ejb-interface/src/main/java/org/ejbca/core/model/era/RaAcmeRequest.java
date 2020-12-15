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
import java.util.HashMap;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Data for all types of requests from the ACME module on the RA to the CA.
 *
 * @version $Id: RaAcmeRequest.java 25831 2017-05-10 14:03:17Z mikekushner $
 */
public class RaAcmeRequest implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Certificate Request. <b>Input:</b> CSR. <b>Output:</b> Certificate */
  public static final int TYPE_GETCERT = 10;

/** Constant. */
  public static final int TYPE_GETNONCE = 20;
  /** Constant. */
  public static final int TYPE_SETNONCE = 21;
  /** Constant. */
  public static final int TYPE_ISNONCE = 22;
  /** Constant. */
  public static final int TYPE_REMNONCE = 23;

/** Constant. */
  public static final int TYPE_GETREGOBJ = 30;
  /** Constant. */
  public static final int TYPE_SETREGOBJ = 31;
  /** Constant. */
  public static final int TYPE_ISREGOBJ = 32;
  /** Constant. */
  public static final int TYPE_REMREGOBJ = 33;

/** Constant. */
  public static final int TYPE_GETAUTHOBJ = 40;
  /** Constant. */
  public static final int TYPE_SETAUTHOBJ = 41;
  /** Constant. */
  public static final int TYPE_ISAUTHOBJ = 42;
  /** Constant. */
  public static final int TYPE_REMAUTHOBJ = 43;
/** Constant. */
  public static final int TYPE_UNSUPPORTED = 90;

  /** Type of request, one of the TYPE_... constants. */
  private int type;

  /** Param. */
  private String acmeBaseUrl;

  /** Param. */
  private byte[] csr;

  /** This contains all the data requested. */
  private HashMap<String, Object> data = new HashMap<>();

  /**
   * @param anacmeBaseUrl URL
   * @param atype Type
   */
  public RaAcmeRequest(final String anacmeBaseUrl, final int atype) {
    this.acmeBaseUrl = anacmeBaseUrl;
    this.type = atype;
  }

  /**
   * @param thedata Data
   */
  public void setData(final HashMap<String, Object> thedata) {
    this.data = thedata;
  }

  /**
   * @param k Key
   * @param v Value
   */
  public void setDataTuple(final String k, final Object v) {
    data.put(k, v);
  }

  /**
   * @return Data
   */
  public HashMap<String, Object> getData() {
    return this.data;
  }

  /**
   * @return URL
   */
  public String getAcmeBaseUrl() {
    return acmeBaseUrl;
  }

  /**
   * @param anacmeBaseUrl URL
   */
  public void setAcmeBaseUrl(final String anacmeBaseUrl) {
    this.acmeBaseUrl = anacmeBaseUrl;
  }

  /**
   * @return type
   */
  public int getType() {
    return type;
  }

  /**
   * @param atype Type
   */
  public void setType(final int atype) {
    this.type = atype;
  }

  /**
   * @return CSR
   */
  public byte[] getCsr() {
    return csr;
  }

  /**
   * @param acsr CSR
   */
  public void setCsr(final byte[] acsr) {
    this.csr = acsr;
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public boolean equals(final Object o) {
      return EqualsBuilder.reflectionEquals(this, o);
  }
}
