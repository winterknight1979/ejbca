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

package org.ejbca.util;

import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.cesecore.util.CeSecoreNameStyle;

/**
 * Name style used for parsing and building DNs for use with LDAP. Used by
 * LdapTools and LdapPublisher
 *
 * @version $Id: LdapNameStyle.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public final class LdapNameStyle extends BCStyle {

    /** Singleton. */
  public static final X500NameStyle INSTANCE = new LdapNameStyle();

  /**
   * Default look up table translating OID values into their common symbols
   * Please call initLookupTables() before using this!
   */
  private static Hashtable<ASN1ObjectIdentifier, String> defaultSymbols;

  /**
   * Look up table translating common symbols into their OIDS. Please call
   * initLookupTables() before using this!
   */
  private static Hashtable<String, ASN1ObjectIdentifier> defaultLookUp;

  /**
   * Look up table translating common symbols into their OIDS. Please call
   * initLookupTables() before using this!
   */
  private static Hashtable<String, String> defaultStringStringLookUp;

  /**
   * Must call this method before using the lookup tables. It's automatically
   * called when using LdapNameStyle.INSTANCE to access this class.
   */
  public static void initLookupTables() {
    defaultSymbols = new Hashtable<ASN1ObjectIdentifier, String>();
    defaultLookUp = new Hashtable<String, ASN1ObjectIdentifier>();
    defaultStringStringLookUp = new Hashtable<String, String>();

    // Copy from CeSecore
    defaultSymbols.putAll(CeSecoreNameStyle.DEFAULT_SYMBOLS);
    defaultLookUp.putAll(CeSecoreNameStyle.DEFAULT_LOOKUP);
    defaultStringStringLookUp.putAll(
        CeSecoreNameStyle.DEFAULT_STRING_STRING_LOKUP);

    // Apply differences in LDAP
    defaultSymbols.put(SN, "serialNumber");
    defaultSymbols.put(EmailAddress, "mail");
    defaultLookUp.put("mail", E);
    defaultStringStringLookUp.put(
        "MAIL", E.getId()); // different from CeSecoreNameStyle
  }

  private LdapNameStyle() {
    if (defaultSymbols == null) {
      initLookupTables();
    }
  }

  @Override
  public String toString(final X500Name name) {
    return CeSecoreNameStyle.buildString(defaultSymbols, name);
  }

  @Override
  public ASN1ObjectIdentifier attrNameToOID(final String attrName) {
    return IETFUtils.decodeAttrName(attrName, defaultLookUp);
  }
}
