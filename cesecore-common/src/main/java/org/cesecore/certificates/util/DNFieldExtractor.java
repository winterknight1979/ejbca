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

package org.cesecore.certificates.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.ietf.ldap.LDAPDN;

/**
 * A class used to retrieve different fields from a Distinguished Name or
 * Subject Alternate Name or Subject Directory Attributes strings.
 *
 * @version $Id: DNFieldExtractor.java 28678 2018-04-12 10:06:36Z anatom $
 */
public class DNFieldExtractor implements java.io.Serializable {

  private static final long serialVersionUID = -1313839342568999844L;

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(DNFieldExtractor.class);
  // Public constants
  /** DN. */
  public static final int TYPE_SUBJECTDN = 0;
  /** Name.*/
  public static final int TYPE_SUBJECTALTNAME = 1;
  /** Attrs. */
  public static final int TYPE_SUBJECTDIRATTR = 2;

  // Note, these IDs duplicate values in profilemappings.properties

  // Subject DN Fields.
  /** E.*/
  public static final int E = 0;
  /** UID. */
  public static final int UID = 1;
  /** CN. */
  public static final int CN = 2;
  /** SN. */
  public static final int SN = 3;
  /** Name. */
  public static final int GIVENNAME = 4;
  /** Name. */
  public static final int INITIALS = 5;
  /** Name. */
  public static final int SURNAME = 6;
  /** T. */
  public static final int T = 7;
  /** OU. */
  public static final int OU = 8;
  /** O. */
  public static final int O = 9;
  /** L. */
  public static final int L = 10;
  /** ST. */
  public static final int ST = 11;
  /** DC. */
  public static final int DC = 12;
  /** C. */
  public static final int C = 13;
  /** Addr.*/
  public static final int UNSTRUCTUREDADDRESS = 14;
  /** Name. */
  public static final int UNSTRUCTUREDNAME = 15;
  /** Postcode. */
  public static final int POSTALCODE = 32;
  /** Cat. */
  public static final int BUSINESSCATEGORY = 33;
  /** DN. */
  public static final int DN = 34;
  /** Address. */
  public static final int POSTALADDRESS = 35;
  /** Tele.*/
  public static final int TELEPHONENUMBER = 36;
  /** Pseud. */
  public static final int PSEUDONYM = 37;
  /** Street. */
  public static final int STREET = 38;
  /** Name. */
  public static final int NAME = 55;
  /** Desc. */
  public static final int DESCRIPTION = 60;
  /** OID. */
  public static final int ORGANIZATIONIDENTIFIER = 106;

  // Subject Alternative Names.
  /** Other. */
  public static final int OTHERNAME = 16;
  /** Email. */
  public static final int RFC822NAME = 17;
  /** DNS. */
  public static final int DNSNAME = 18;
  /** IP. */
  public static final int IPADDRESS = 19;
  /** Address. */
  public static final int X400ADDRESS = 20;
  /** Name. */
  public static final int DIRECTORYNAME = 21;
  /** Name. */
  public static final int EDIPARTYNAME = 22;
  /** URI. */
  public static final int URI = 23;
  /** ID. */
  public static final int REGISTEREDID = 24;
  /** UPN. */
  public static final int UPN = 25;
  /** GUID. */
  public static final int GUID = 26;
  /** Kerberos. */
  public static final int KRB5PRINCIPAL = 52;
  /** ID. */
  public static final int PERMANTIDENTIFIER = 56;
  /** Method. */
  public static final int SUBJECTIDENTIFICATIONMETHOD = 59;

  // Subject Directory Attributes
  /** DOB. */
  public static final int DATEOFBIRTH = 27;
  /** POB. */
  public static final int PLACEOFBIRTH = 28;
  /** Gender. */
  public static final int GENDER = 29;
  /** Country. */
  public static final int COUNTRYOFCITIZENSHIP = 30;
  /** Country. */
  public static final int COUNTRYOFRESIDENCE = 31;
  /** Boundary. */
  private static final int BOUNDRARY = 100;
  /** Mapping dnid to number of occurrences in this DN. */
  private HashMap<Integer, Integer> fieldnumbers;
  /**
   * mapping dn (or altname or subject dir attrs) numerical ids with the value
   * of the components.
   */
  private HashMap<Integer, String> dnfields;

  /** Exists. */
  private boolean existsother = false;
  /** Illegal. */
  private boolean illegal = false;
  /** Type. */
  private int type;

  /**
   * @return type.
   */
  public int getType() {
    return type;
  }

  /**
   * Creates a new instance of DNFieldExtractor.
   *
   * @param dn DOCUMENT ME!
   * @param aType DOCUMENT ME!
   */
  public DNFieldExtractor(final String dn, final int aType) {
    dnfields = new HashMap<>();
    setDN(dn, aType);
  }

  /**
   * Fields that can be selected in Certificate profile and Publisher.
   *
   * @param type Type
   * @return fields
   */
  public static List<Integer> getUseFields(final int type) {
    if (type == DNFieldExtractor.TYPE_SUBJECTDN) {
      return DnComponents.getDnDnIds();
    } else if (type == DNFieldExtractor.TYPE_SUBJECTALTNAME) {
      return DnComponents.getAltNameDnIds();
    } else if (type == DNFieldExtractor.TYPE_SUBJECTDIRATTR) {
      return DnComponents.getDirAttrDnIds();
    } else {
      return new ArrayList<Integer>();
    }
  }

  /**
   * Returns the valid components for the given DN type (Subject DN, Subject
   * Alternative Name or Subject Directory Attributes).
   *
   * @param dnType DNFieldExtractor.TYPE_*
   * @return List of valid components from DnComponents.*
   */
  public static List<String> getValidFieldComponents(final int dnType) {
    switch (dnType) {
      case DNFieldExtractor.TYPE_SUBJECTDN:
        return DnComponents.getDnProfileFields();
      case DNFieldExtractor.TYPE_SUBJECTALTNAME:
        return DnComponents.getAltNameFields();
      case DNFieldExtractor.TYPE_SUBJECTDIRATTR:
        return DnComponents.getDirAttrFields();
      default:
        throw new IllegalStateException("Invalid DN type");
    }
  }

  /**
   * @param field field
   * @param type type
   * @return string
   */
  public static String getFieldComponent(final int field, final int type) {
    final String ret;
    if (type == DNFieldExtractor.TYPE_SUBJECTDN) {
      ret = DnComponents.getDnExtractorFieldFromDnId(field);
    } else if (type == DNFieldExtractor.TYPE_SUBJECTALTNAME) {
      ret = DnComponents.getAltNameExtractorFieldFromDnId(field);
    } else {
      ret = DnComponents.getDirAttrExtractorFieldFromDnId(field);
    }
    return ret;
  }

  /**
   * Looks up a DN Id (for use with DnComponents functions etc.) from a DN
   * component.
   *
   * @param dnComponent Component, e.g. "CN". Not case sensitive.
   * @param dnType DN type, e.g. DNFieldExtractor.TYPE_SUBJECTDN
   * @return DN Id, or null if no such component exists for the given DN type.
   */
  public static Integer getDnIdFromComponent(
      final String dnComponent, final int dnType) {
    switch (dnType) {
      case DNFieldExtractor.TYPE_SUBJECTDN:
        return DnComponents.getDnIdFromDnName(dnComponent);
      case DNFieldExtractor.TYPE_SUBJECTALTNAME:
        return DnComponents.getDnIdFromAltName(dnComponent);
      case DNFieldExtractor.TYPE_SUBJECTDIRATTR:
        DnComponents.getDnIdFromDirAttr(dnComponent);
      default:
        throw new IllegalStateException("Invalid DN type");
    }
  }

  /**
   * Fills the dnfields variable with dn (or altname or subject dir attrs)
   * numerical ids and the value of the components (i.e. the value of CN). Also
   * populates fieldnumbers with number of occurances in dn
   *
   * @param dn DOCUMENT ME!
   * @param aType DOCUMENT ME!
   */
  public final void setDN(final String dn, final int aType) {

    this.type = aType;
    final ArrayList<Integer> ids;
    if (aType == TYPE_SUBJECTDN) {
      ids = DnComponents.getDnDnIds();
    } else if (aType == TYPE_SUBJECTALTNAME) {
      ids = DnComponents.getAltNameDnIds();
    } else if (aType == TYPE_SUBJECTDIRATTR) {
      ids = DnComponents.getDirAttrDnIds();
    } else {
      ids = new ArrayList<>();
    }
    fieldnumbers = new HashMap<>();
    for (Integer id : ids) {
      fieldnumbers.put(id, 0);
    }

    if ((dn != null) && !dn.equalsIgnoreCase("null")) {
      dnfields = new HashMap<>();
      try {
        final String[] dnexploded = LDAPDN.explodeDN(dn, false);
        for (int i = 0; i < dnexploded.length; i++) {
          boolean exists = false;

          for (Integer id : ids) {
            Integer number = fieldnumbers.get(id);
            String field;
            if (aType == TYPE_SUBJECTDN) {
              field = DnComponents.getDnExtractorFieldFromDnId(id.intValue());
            } else if (aType == TYPE_SUBJECTALTNAME) {
              field =
                  DnComponents.getAltNameExtractorFieldFromDnId(id.intValue());
            } else {
              field =
                  DnComponents.getDirAttrExtractorFieldFromDnId(id.intValue());
            }
            final String dnex = dnexploded[i].toUpperCase();
            if (id.intValue() == DNFieldExtractor.URI) {
              // Fix up URI, which can have several forms
              if (dnex.indexOf(CertTools.URI.toUpperCase(Locale.ENGLISH) + "=")
                  > -1) {
                field = CertTools.URI.toUpperCase(Locale.ENGLISH) + "=";
              }
              if (dnex.indexOf(CertTools.URI1.toUpperCase(Locale.ENGLISH) + "=")
                  > -1) {
                field = CertTools.URI1.toUpperCase(Locale.ENGLISH) + "=";
              }
            }

            if (dnex.startsWith(field)) {

              exists = true;
              final String rdn;
              final String tmp;
              // LDAPDN.unescapeRDN don't like fields with just a key but no
              // contents. Example: 'OU='
              if (dnexploded[i].charAt(dnexploded[i].length() - 1) != '=') {
                tmp = LDAPDN.unescapeRDN(dnexploded[i]);
              } else {
                tmp = dnexploded[i];
              }
              // We don't want the CN= (or whatever) part of the RDN
              if (tmp.toUpperCase().startsWith(field)) {
                rdn = tmp.substring(field.length(), tmp.length());
              } else {
                rdn = tmp;
              }

              // Same code for TYPE_SUBJECTDN, TYPE_SUBJECTALTNAME and
              // TYPE_SUBJECTDIRATTR and we will never get here
              // if it is not one of those types
              dnfields.put(
                  Integer.valueOf(
                      (id.intValue() * BOUNDRARY) + number.intValue()),
                  rdn);

              number = Integer.valueOf(number.intValue() + 1);
              fieldnumbers.put(id, number);
            }
          }
          if (!exists) {
            existsother = true;
          }
        }
      } catch (Exception e) {
        LOG.warn("setDN: ", e);
        illegal = true;
        if (aType == TYPE_SUBJECTDN) {
          dnfields.put(Integer.valueOf((CN * BOUNDRARY)), "Illegal DN : " + dn);
        } else if (aType == TYPE_SUBJECTALTNAME) {
          dnfields.put(
              Integer.valueOf((RFC822NAME * BOUNDRARY)),
              "Illegal Subjectaltname : " + dn);
        } else if (aType == TYPE_SUBJECTDIRATTR) {
          dnfields.put(
              Integer.valueOf((PLACEOFBIRTH * BOUNDRARY)),
              "Illegal Subjectdirectory attribute : " + dn);
        }
      }
    }
  }

  /**
   * Returns the value of a certain DN component.
   *
   * @param field the DN component, one of the constants DNFieldExtractor.CN,
   *     ...
   * @param number the number of the component if several entries for this
   *     component exists, normally 0 fir the first
   * @return A String for example "PrimeKey" if DNFieldExtractor.O and 0 was
   *     passed, "PrimeKey" if DNFieldExtractor.DC and 0 was passed or "com" if
   *     DNFieldExtractor.DC and 1 was passed. Returns an empty String "", if no
   *     such field with the number exists.
   */
  public String getField(final int field, final int number) {
    String returnval =
        dnfields.get(Integer.valueOf((field * BOUNDRARY) + number));

    if (returnval == null) {
      returnval = "";
    }

    return returnval;
  }

  /**
   * Returns a string representation of a certain DN component.
   *
   * @param field the DN component, one of the constants DNFieldExtractor.CN,
   *     ...
   * @return A String for example "CN=Tomas Gustavsson" if DNFieldExtractor.CN
   *     was passed, "DC=PrimeKey,DC=com" if DNFieldExtractor.DC was passed.
   *     This string is escaped so it can be used in a DN string.
   */
  public String getFieldString(final int field) {
    String retval = "";
    String fieldname = DnComponents.getDnExtractorFieldFromDnId(field);
    if (type != TYPE_SUBJECTDN) {
      fieldname = DnComponents.getAltNameExtractorFieldFromDnId(field);
    }
    final int num = getNumberOfFields(field);
    for (int i = 0; i < num; i++) {
      if (retval.length() == 0) {
        retval += LDAPDN.escapeRDN(fieldname + getField(field, i));
      } else {
        retval += "," + LDAPDN.escapeRDN(fieldname + getField(field, i));
      }
    }
    return retval;
  }

  /**
   * Function that returns true if non standard DN field exists in dn string.
   *
   * @return true if non standard DN field exists, false otherwise
   */
  public boolean existsOther() {
    return existsother;
  }

  /**
   * Returns the number of one kind of dn field.
   *
   * @param field the DN component, one of the constants DNFieldExtractor.CN,
   *     ...
   * @return number of components available for a field, for example 1 if DN is
   *     "dc=primekey" and 2 if DN is "dc=primekey,dc=com"
   */
  public int getNumberOfFields(final int field) {
    Integer ret = fieldnumbers.get(Integer.valueOf(field));
    if (ret == null) {
      LOG.error("Not finding fieldnumber value for " + field);
      ret = Integer.valueOf(0);
    }
    return ret.intValue();
  }

  /**
   * Returns the complete array determining the number of DN components of the
   * various types (i.e. if there are two CNs but 0 Ls etc)
   *
   * <p>TODO: DOCUMENT
   *
   * @return DOCUMENT ME!
   */
  public HashMap<Integer, Integer> getNumberOfFields() {
    return fieldnumbers;
  }

  /**
   * @return bool
   */
  public boolean isIllegal() {
    return illegal;
  }
}
