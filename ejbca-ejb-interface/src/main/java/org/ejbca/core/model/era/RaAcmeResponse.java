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
import java.util.Map;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * A response from the CA to the ACME module on the RA.
 *
 * @version $Id: RaAcmeResponse.java 25831 2017-05-10 14:03:17Z mikekushner $
 */
public class RaAcmeResponse implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Param. */
  private byte[] certificate;

  /** Param. */
  private Map<String, Object> result;
  /** Param. */
  private int operation = 0;

  /**
   * @return Cert
   */
  public byte[] getCertificate() {
    return certificate;
  }

  /**
   * @param acertificate Cart
   */
  public void setCertificate(final byte[] acertificate) {
    this.certificate = acertificate;
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  @Override
  public boolean equals(final Object o) {
      return EqualsBuilder.reflectionEquals(this, o);
  }

  /**
   * Sets the operation, and the result. since the acme method on the RA
   * contains multiple operations we setup the computed result and operation
   * inside the ACMERESPONSE
   *
   * @param anoperation operatioon
   * @param aresult result
   */
  public void setOperation(
      final int anoperation, final Map<String, Object> aresult) {
    this.operation = anoperation;
    this.result = aresult;
  }
  /**
   * This returns an object with information about the response operation and
   * the type of object related to it.
   *
   * @return map
   */
  public Map<String, Object> getResult() {
    HashMap<String, Object> aresult = new HashMap<>();
    aresult.put("result", this.result);
    aresult.put("operation", this.operation);
    return aresult;
  }
}
