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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Translates field types from EndEntityProfile to subject DN field names and
 * human-readable names.
 *
 * @version $Id: DNFieldDescriber.java 19902 2014-09-30 14:32:24Z anatom $
 */
public final class DNFieldDescriber {

  /** Index in dn fields array. */
  private final int index;

  /** Param. */
  private final int[] fielddata;
  /** Param. */
  private final boolean fieldModifiable;
  /** Param. */
  private final boolean fieldRequired;
  /** Param. */
  private final boolean fieldUse;
  /** DN codes, e.g. CN, C, O. */
  private final String name;

  /** Param. */
  private final String defaultValue;

  /** Param. */
  private final Map<String, Boolean>
      allowedValuesMap; // maps to true. Used from .jsp
  /** Param. */
  private final List<String> allowedValuesList;

  /**
   * @param anindex index
   * @param thefielddata data
   * @param eeprofile profile
   * @param dnAltType type
   */
  public DNFieldDescriber(
      final int anindex,
      final int[] thefielddata,
      final EndEntityProfile eeprofile,
      final int dnAltType) {
    this.index = anindex;
    this.fielddata = thefielddata;
    final int fieldType = thefielddata[EndEntityProfile.FIELDTYPE];
    final int fieldNumber = thefielddata[EndEntityProfile.NUMBER];
    this.fieldModifiable = eeprofile.isModifyable(fieldType, fieldNumber);
    this.fieldRequired = eeprofile.isRequired(fieldType, fieldNumber);
    this.fieldUse = eeprofile.getUse(fieldType, fieldNumber);
    this.name = fieldTypeToString(fieldType, dnAltType);

    String value = eeprofile.getValue(fieldType, fieldNumber);
    if (fieldModifiable) {
      // A text entry is used in this case
      this.defaultValue = value.trim();
      this.allowedValuesMap = null;
      this.allowedValuesList = null;
    } else {
      // A select field with restricted choices
      this.defaultValue = null;
      this.allowedValuesMap = new HashMap<String, Boolean>();
      this.allowedValuesList = new ArrayList<String>();

      if (!eeprofile.isRequired(fieldType, fieldNumber)) {
        allowedValuesMap.put("", true);
        allowedValuesList.add("");
      }

      for (String allowed : value.split(";")) {
        allowed = allowed.trim();
        allowedValuesMap.put(allowed, true);
        allowedValuesList.add(allowed);
      }
    }
  }


  private static String fieldTypeToString(
      final int fieldType, final int dnAltType) {
    String name =
        DNFieldExtractor.getFieldComponent(
            DnComponents.profileIdToDnId(fieldType), dnAltType);
    return (name != null
        ? name.replaceAll("=", "").toLowerCase(Locale.ROOT)
        : null);
  }

  /**
   * @return bool
   */
  public boolean isModifiable() {
    return fieldModifiable;
  }

  /**
   * @return bool
   */
  public boolean isRequired() {
    return fieldRequired;
  }


  /**
   * @return bool
   */
  public boolean isUse() {
    return fieldUse;
  }

  /** @return Marker. */
  public String getRequiredMarker() {
    return fieldRequired ? " *" : "";
  }

  /**
   * @return Values
   */
  public Map<String, Boolean> getAllowedValuesMap() {
    return allowedValuesMap;
  }

  /**
   * @return values
   */
  public List<String> getAllowedValuesList() {
    return allowedValuesList;
  }

  /**
   * @return name
   */
  public String getName() {
    return name;
  }

  /**
   * @return ID
   */
  public String getId() {
    return String.valueOf(index);
  }

  /**
   * @param id ID
   * @return Index
   */
  public static int extractIndexFromId(final String id) {
    return Integer.parseInt(id.split(":")[0]);
  }

  /**
   * @param eeprofile prfile
   * @param id ID
   * @return DN
   */
  public static String extractSubjectDnNameFromId(
      final EndEntityProfile eeprofile, final String id) {
    int i = extractIndexFromId(id);
    return fieldTypeToString(
        eeprofile.getSubjectDNFieldsInOrder(i)[EndEntityProfile.FIELDTYPE],
        DNFieldExtractor.TYPE_SUBJECTDN);
  }

  /**
   * @param eeprofile profile
   * @param id id
   * @return name
   */
  public static String extractSubjectAltNameFromId(
      final EndEntityProfile eeprofile, final String id) {
    int i = extractIndexFromId(id);
    return fieldTypeToString(
        eeprofile.getSubjectAltNameFieldsInOrder(i)[EndEntityProfile.FIELDTYPE],
        DNFieldExtractor.TYPE_SUBJECTALTNAME);
  }

  /**
   * @param eeprofile Prifile
   * @param id ID
   * @return Dir
   */
  public static String extractSubjectDirAttrFromId(
      final EndEntityProfile eeprofile, final String id) {
    int i = extractIndexFromId(id);
    return fieldTypeToString(
        eeprofile.getSubjectDirAttrFieldsInOrder(i)[EndEntityProfile.FIELDTYPE],
        DNFieldExtractor.TYPE_SUBJECTDIRATTR);
  }

  /**
   * @param str String
   * @param prefixes Prefixes
   * @return String
   */
  public String removePrefixes(final String str, final String... prefixes) {
    String s = str;
      for (String prefix : prefixes) {
      if (s.startsWith(prefix)) {
          s = s.substring(prefix.length());
      }
    }
    return s;
  }

  /**
   * @return Name
   */
  public String getHumanReadableName() {
    String langconst =
        DnComponents.getLanguageConstantFromProfileId(
            fielddata[EndEntityProfile.FIELDTYPE]);
    if (langconst.equals("DN_PKIX_COMMONNAME")) {
      return "Name";
    }
    if (langconst.equals("DN_PKIX_ORGANIZATION")) {
      return "Organization";
    }
    if (langconst.equals("DN_PKIX_COUNTRY")) {
      return "Country";
    }
    if (langconst.equals("DN_PKIX_EMAILADDRESS")) {
      return "E-mail";
    }
    if (langconst.equals("ALT_PKIX_DNSNAME")) {
      return "DNS Name";
    }
    if (langconst.equals("ALT_PKIX_IPADDRESS")) {
      return "IP Address";
    }
    if (langconst.equals("ALT_PKIX_RFC822NAME")) {
      return "RFC822 Name (e-mail)";
    } else {
      return removePrefixes(
              langconst, "DN_PKIX_", "ALT_PKIX_", "DN_", "ALT_", "SDA_")
          .toLowerCase(Locale.ROOT);
    }
  }

  /**
   * @return Description
   */
  public String getDescription() {
    if (name != null) {
      return getHumanReadableName()
          + " ("
          + name.toUpperCase(Locale.ROOT)
          + ")";
    } else {
      return getHumanReadableName();
    }
  }

  /**
   * @return value
   */
  public String getDefaultValue() {
    return defaultValue;
  }
}
