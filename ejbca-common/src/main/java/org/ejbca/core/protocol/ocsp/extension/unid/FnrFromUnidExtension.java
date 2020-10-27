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

package org.ejbca.core.protocol.ocsp.extension.unid;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;

/**
 * The ASN.1 extension with OID 2.16.578.1.16.3.2 used to request an FNR from a
 * UNID and respond with the FNR. When requesting, the fnr passed in the
 * extension does not matter, use 1.
 *
 * <p>id-fnrFromUnid OBJECT IDENTIFIER ::= { 2 16 578 1 16 3 2 }
 *
 * <p>FnrFromUnid ::= Fnr
 *
 * <p>Fnr ::= IA5String
 *
 * @version $Id: FnrFromUnidExtension.java 28652 2018-04-09 14:35:21Z aminkh $
 */
public class FnrFromUnidExtension extends ASN1Object {

    /** Config. */
  public static final ASN1ObjectIdentifier FNR_FROM_UNID_OID =
      new ASN1ObjectIdentifier("2.16.578.1.16.3.2");

  /** FNR. */
  private final String fnr;

  /**
   * @param obj object
   * @return instance
   */
  public static FnrFromUnidExtension getInstance(final Object obj) {
    if (obj == null || obj instanceof FnrFromUnidExtension) {
      return (FnrFromUnidExtension) obj;
    }

    if (obj instanceof DERIA5String) {
      return new FnrFromUnidExtension((DERIA5String) obj);
    }

    throw new IllegalArgumentException(
        "Invalid FnrFromUnidExtension: " + obj.getClass().getName());
  }

  /**
   * @param nr NR
   */
  public FnrFromUnidExtension(final String nr) {
    this.fnr = nr;
  }

  /**
   * @param nr NR
   */
  public FnrFromUnidExtension(final DERIA5String nr) {
    this.fnr = nr.getString();
  }

  /**
   * @return FNR
   */
  public String getFnr() {
    return fnr;
  }

 @Override
  public ASN1Primitive toASN1Primitive() {
    return new DERIA5String(fnr);
  }
}
