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

package org.cesecore.util;

import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * Class that determines string representations of DNs. Overrides the default
 * BCStyle in order to: - Be consistent for all future for backwards
 * compatibility (serialnumber) - Be able to add fields that does not (yet)
 * exist in BC (like CABForum Jurisdiction* in BC 1.54)
 *
 * @version $Id: CeSecoreNameStyle.java 26562 2017-09-16 19:07:04Z samuellb $
 */
public class CeSecoreNameStyle extends BCStyle {

    /** Singleton. */
  public static final X500NameStyle INSTANCE = new CeSecoreNameStyle();

  /**
   * EV TLS jurisdictionCountry.
   * https://cabforum.org/wp-content/uploads/EV-V1_5_2Libre.pdf
   */
  public static final ASN1ObjectIdentifier JURISDICTION_COUNTRY =
      new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");
  /**
   * EV TLS jurisdictionState.
   * https://cabforum.org/wp-content/uploads/EV-V1_5_2Libre.pdf
   */
  public static final ASN1ObjectIdentifier JURISDICTION_STATE =
      new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2");
  /**
   * EV TLS jurisdictionLocality.
   * https://cabforum.org/wp-content/uploads/EV-V1_5_2Libre.pdf
   */
  public static final ASN1ObjectIdentifier JURISDICTION_LOCALITY =
      new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1");
  /**
   * X.520 organizationIdentifier, used by ETSI TS 319 412 (eIDAS).
   * https://www.itu.int/rec/dologin.asp?lang=e&amp;id=T-REC-X.520-201210-S!Cor3!PDF-E&amp;type=items
   */
  public static final ASN1ObjectIdentifier ORGANIZATION_IDENTIFIER =
      new ASN1ObjectIdentifier("2.5.4.97");

  /** */
  public static final ASN1ObjectIdentifier DESCRIPTION =
      new ASN1ObjectIdentifier("2.5.4.13");

  /**
   * default look up table translating OID values into their common symbols
   * following the convention in RFC 2253 with a few extras.
   */
  public static final Hashtable<ASN1ObjectIdentifier, String> DEFAULT_SYMBOLS =
      new Hashtable<>();

  /** look up table translating common symbols into their OIDS. */
  public static final Hashtable<String, ASN1ObjectIdentifier> DEFAULT_LOOKUP =
      new Hashtable<>();

  /** look up table translating common symbols into their OIDS. */
  public static final Hashtable<String, String> DEFAULT_STRING_STRING_LOKUP =
      new Hashtable<>();

  static {
    DEFAULT_SYMBOLS.put(C, "C");
    DEFAULT_SYMBOLS.put(O, "O");
    DEFAULT_SYMBOLS.put(T, "T");
    DEFAULT_SYMBOLS.put(OU, "OU");
    DEFAULT_SYMBOLS.put(CN, "CN");
    DEFAULT_SYMBOLS.put(L, "L");
    DEFAULT_SYMBOLS.put(ST, "ST");
    DEFAULT_SYMBOLS.put(SN, "SN");
    DEFAULT_SYMBOLS.put(EmailAddress, "E");
    DEFAULT_SYMBOLS.put(DC, "DC");
    DEFAULT_SYMBOLS.put(UID, "UID");
    DEFAULT_SYMBOLS.put(STREET, "STREET");
    DEFAULT_SYMBOLS.put(SURNAME, "SURNAME");
    DEFAULT_SYMBOLS.put(GIVENNAME, "GIVENNAME");
    DEFAULT_SYMBOLS.put(INITIALS, "INITIALS");
    DEFAULT_SYMBOLS.put(GENERATION, "GENERATION");
    DEFAULT_SYMBOLS.put(UnstructuredAddress, "unstructuredAddress");
    DEFAULT_SYMBOLS.put(UnstructuredName, "unstructuredName");
    DEFAULT_SYMBOLS.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
    DEFAULT_SYMBOLS.put(DN_QUALIFIER, "DN");
    DEFAULT_SYMBOLS.put(PSEUDONYM, "Pseudonym");
    DEFAULT_SYMBOLS.put(POSTAL_ADDRESS, "PostalAddress");
    DEFAULT_SYMBOLS.put(NAME_AT_BIRTH, "NameAtBirth");
    DEFAULT_SYMBOLS.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
    DEFAULT_SYMBOLS.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
    DEFAULT_SYMBOLS.put(GENDER, "Gender");
    DEFAULT_SYMBOLS.put(PLACE_OF_BIRTH, "PlaceOfBirth");
    DEFAULT_SYMBOLS.put(DATE_OF_BIRTH, "DateOfBirth");
    DEFAULT_SYMBOLS.put(POSTAL_CODE, "PostalCode");
    DEFAULT_SYMBOLS.put(BUSINESS_CATEGORY, "BusinessCategory");
    DEFAULT_SYMBOLS.put(TELEPHONE_NUMBER, "TelephoneNumber");
    DEFAULT_SYMBOLS.put(NAME, "Name");
    DEFAULT_SYMBOLS.put(JURISDICTION_LOCALITY, "JurisdictionLocality");
    DEFAULT_SYMBOLS.put(JURISDICTION_STATE, "JurisdictionState");
    DEFAULT_SYMBOLS.put(JURISDICTION_COUNTRY, "JurisdictionCountry");
    DEFAULT_SYMBOLS.put(ORGANIZATION_IDENTIFIER, "organizationIdentifier");
    DEFAULT_SYMBOLS.put(DESCRIPTION, "description");

    DEFAULT_LOOKUP.put("c", C);
    DEFAULT_LOOKUP.put("o", O);
    DEFAULT_LOOKUP.put("t", T);
    DEFAULT_LOOKUP.put("ou", OU);
    DEFAULT_LOOKUP.put("cn", CN);
    DEFAULT_LOOKUP.put("l", L);
    DEFAULT_LOOKUP.put("st", ST);
    DEFAULT_LOOKUP.put("sn", SN);
    DEFAULT_LOOKUP.put("serialnumber", SN);
    DEFAULT_LOOKUP.put("street", STREET);
    DEFAULT_LOOKUP.put("emailaddress", E);
    DEFAULT_LOOKUP.put("dc", DC);
    DEFAULT_LOOKUP.put("e", E);
    DEFAULT_LOOKUP.put("uid", UID);
    DEFAULT_LOOKUP.put("surname", SURNAME);
    DEFAULT_LOOKUP.put("givenname", GIVENNAME);
    DEFAULT_LOOKUP.put("initials", INITIALS);
    DEFAULT_LOOKUP.put("generation", GENERATION);
    DEFAULT_LOOKUP.put("unstructuredaddress", UnstructuredAddress);
    DEFAULT_LOOKUP.put("unstructuredname", UnstructuredName);
    DEFAULT_LOOKUP.put("uniqueidentifier", UNIQUE_IDENTIFIER);
    DEFAULT_LOOKUP.put("dn", DN_QUALIFIER);
    DEFAULT_LOOKUP.put("pseudonym", PSEUDONYM);
    DEFAULT_LOOKUP.put("postaladdress", POSTAL_ADDRESS);
    DEFAULT_LOOKUP.put("nameofbirth", NAME_AT_BIRTH);
    DEFAULT_LOOKUP.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
    DEFAULT_LOOKUP.put("countryofresidence", COUNTRY_OF_RESIDENCE);
    DEFAULT_LOOKUP.put("gender", GENDER);
    DEFAULT_LOOKUP.put("placeofbirth", PLACE_OF_BIRTH);
    DEFAULT_LOOKUP.put("dateofbirth", DATE_OF_BIRTH);
    DEFAULT_LOOKUP.put("postalcode", POSTAL_CODE);
    DEFAULT_LOOKUP.put("businesscategory", BUSINESS_CATEGORY);
    DEFAULT_LOOKUP.put("telephonenumber", TELEPHONE_NUMBER);
    DEFAULT_LOOKUP.put("name", NAME);
    DEFAULT_LOOKUP.put("jurisdictionlocality", JURISDICTION_LOCALITY);
    DEFAULT_LOOKUP.put("jurisdictionstate", JURISDICTION_STATE);
    DEFAULT_LOOKUP.put("jurisdictioncountry", JURISDICTION_COUNTRY);
    DEFAULT_LOOKUP.put("organizationidentifier", ORGANIZATION_IDENTIFIER);
    DEFAULT_LOOKUP.put("description", DESCRIPTION);

    DEFAULT_STRING_STRING_LOKUP.put("C", C.getId());
    DEFAULT_STRING_STRING_LOKUP.put("O", O.getId());
    DEFAULT_STRING_STRING_LOKUP.put("T", T.getId());
    DEFAULT_STRING_STRING_LOKUP.put("OU", OU.getId());
    DEFAULT_STRING_STRING_LOKUP.put("CN", CN.getId());
    DEFAULT_STRING_STRING_LOKUP.put("L", L.getId());
    DEFAULT_STRING_STRING_LOKUP.put("ST", ST.getId());
    DEFAULT_STRING_STRING_LOKUP.put("SN", SN.getId());
    DEFAULT_STRING_STRING_LOKUP.put("SERIALNUMBER", SN.getId());
    DEFAULT_STRING_STRING_LOKUP.put("STREET", STREET.getId());
    DEFAULT_STRING_STRING_LOKUP.put("EMAILADDRESS", E.getId());
    DEFAULT_STRING_STRING_LOKUP.put("DC", DC.getId());
    DEFAULT_STRING_STRING_LOKUP.put("E", E.getId());
    DEFAULT_STRING_STRING_LOKUP.put("UID", UID.getId());
    DEFAULT_STRING_STRING_LOKUP.put("SURNAME", SURNAME.getId());
    DEFAULT_STRING_STRING_LOKUP.put("GIVENNAME", GIVENNAME.getId());
    DEFAULT_STRING_STRING_LOKUP.put("INITIALS", INITIALS.getId());
    DEFAULT_STRING_STRING_LOKUP.put("GENERATION", GENERATION.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "UNSTRUCTUREDADDRESS", UnstructuredAddress.getId());
    DEFAULT_STRING_STRING_LOKUP.put("UNSTRUCTUREDNAME",
            UnstructuredName.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "UNIQUEIDENTIFIER", UNIQUE_IDENTIFIER.getId());
    DEFAULT_STRING_STRING_LOKUP.put("DN", DN_QUALIFIER.getId());
    DEFAULT_STRING_STRING_LOKUP.put("PSEUDONYM", PSEUDONYM.getId());
    DEFAULT_STRING_STRING_LOKUP.put("POSTALADDRESS", POSTAL_ADDRESS.getId());
    DEFAULT_STRING_STRING_LOKUP.put("NAMEOFBIRTH", NAME_AT_BIRTH.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "COUNTRYOFCITIZENSHIP", COUNTRY_OF_CITIZENSHIP.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "COUNTRYOFRESIDENCE", COUNTRY_OF_RESIDENCE.getId());
    DEFAULT_STRING_STRING_LOKUP.put("GENDER", GENDER.getId());
    DEFAULT_STRING_STRING_LOKUP.put("PLACEOFBIRTH", PLACE_OF_BIRTH.getId());
    DEFAULT_STRING_STRING_LOKUP.put("DATEOFBIRTH", DATE_OF_BIRTH.getId());
    DEFAULT_STRING_STRING_LOKUP.put("POSTALCODE", POSTAL_CODE.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "BUSINESSCATEGORY", BUSINESS_CATEGORY.getId());
    DEFAULT_STRING_STRING_LOKUP.put("TELEPHONENUMBER",
            TELEPHONE_NUMBER.getId());
    DEFAULT_STRING_STRING_LOKUP.put("NAME", NAME.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "JURISDICTIONLOCALITY", JURISDICTION_LOCALITY.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "JURISDICTIONSTATE", JURISDICTION_STATE.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "JURISDICTIONCOUNTRY", JURISDICTION_COUNTRY.getId());
    DEFAULT_STRING_STRING_LOKUP.put(
        "ORGANIZATIONIDENTIFIER", ORGANIZATION_IDENTIFIER.getId());
    DEFAULT_STRING_STRING_LOKUP.put("DESCRIPTION", DESCRIPTION.getId());
  }

  /**
   * This method is intended to be used in toString() in BCStyle classes. It is
   * useful e.g. when the DefaultSymbols map is not the default inherited from
   * BCStyle. It is public so it can be re-used by other classes as well (e.g.
   * LdapNameStyle in EJBCA).
   *
   * @param defaultSymbols symbols
   * @param name Name
   * @return String
   */
  public static String buildString(
      final Hashtable<ASN1ObjectIdentifier, String> defaultSymbols,
      final X500Name name) {
    StringBuffer buf = new StringBuffer();
    boolean first = true;

    RDN[] rdns = name.getRDNs();

    for (int i = 0; i < rdns.length; i++) {
      if (first) {
        first = false;
      } else {
        buf.append(',');
      }

      if (rdns[i].isMultiValued()) {
        AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
        boolean firstAtv = true;

        for (int j = 0; j != atv.length; j++) {
          if (firstAtv) {
            firstAtv = false;
          } else {
            buf.append('+');
          }

          IETFUtils.appendTypeAndValue(buf, atv[j], defaultSymbols);
        }
      } else {
        IETFUtils.appendTypeAndValue(buf, rdns[i].getFirst(), defaultSymbols);
      }
    }

    return buf.toString();
  }

  @Override
  public String toString(final X500Name name) {
    return buildString(DEFAULT_SYMBOLS, name);
  }

  @Override
  public ASN1Encodable stringToValue(
          final ASN1ObjectIdentifier oid, final String value) {
    // JurisdictionCountry is not included in BC (at least up to and including
    // 1.49), and must be PrintableString
    if (oid.equals(CeSecoreNameStyle.JURISDICTION_COUNTRY)) {
      return new DERPrintableString(value);
    }
    return super.stringToValue(oid, value);
  }

  @Override
  public ASN1ObjectIdentifier attrNameToOID(final String attrName) {
    return IETFUtils.decodeAttrName(attrName, DEFAULT_LOOKUP);
  }
}
