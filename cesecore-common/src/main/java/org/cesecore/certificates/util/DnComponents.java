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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.cesecore.util.CeSecoreNameStyle;

/**
 * Class holding information and utilities for handling different DN components,
 * CN, O etc
 *
 * <p>This is a very complex class with lots of maps and stuff. It is because it
 * is a first step of refactoring the DN/AltName/DirAttr handling. This
 * previously consisted of lots of different arrays spread out all over the
 * place, now it's gathered here in order to be able to get a view of it. The
 * underlying implementations have not changed much though, in order to still
 * have things working, therefore there are lots of different maps and arrays,
 * with seemingly similar contents.
 *
 * @version $Id: DnComponents.java 27374 2017-12-01 12:37:30Z anatom $
 */
public final class DnComponents {


    /** Logger. */
  private static Logger log = Logger.getLogger(DnComponents.class);

  /** This class should be instantiated immediately. */
  private static DnComponents obj = new DnComponents();

  /**
   * BC X500Name contains some lookup tables that could maybe be used here.
   *
   * <p>This map is used in CertTools so sort and order DN strings so they all
   * look the same in the database.
   */
  private static HashMap<String, ASN1ObjectIdentifier> oids =
      new HashMap<String, ASN1ObjectIdentifier>();
  // Default values
  static {
    oids.put("c", CeSecoreNameStyle.C);
    oids.put("dc", CeSecoreNameStyle.DC);
    oids.put("st", CeSecoreNameStyle.ST);
    oids.put("l", CeSecoreNameStyle.L);
    oids.put("o", CeSecoreNameStyle.O);
    oids.put("ou", CeSecoreNameStyle.OU);
    oids.put("t", CeSecoreNameStyle.T);
    oids.put("surname", CeSecoreNameStyle.SURNAME);
    oids.put("initials", CeSecoreNameStyle.INITIALS);
    oids.put("givenname", CeSecoreNameStyle.GIVENNAME);
    oids.put("gn", CeSecoreNameStyle.GIVENNAME);
    oids.put("sn", CeSecoreNameStyle.SN);
    oids.put("serialnumber", CeSecoreNameStyle.SERIALNUMBER);
    oids.put("cn", CeSecoreNameStyle.CN);
    oids.put("uid", CeSecoreNameStyle.UID);
    oids.put("dn", CeSecoreNameStyle.DN_QUALIFIER);
    oids.put("emailaddress", CeSecoreNameStyle.EmailAddress);
    oids.put("e", CeSecoreNameStyle.EmailAddress);
    oids.put("email", CeSecoreNameStyle.EmailAddress);
    oids.put(
        "unstructuredname",
        CeSecoreNameStyle.UnstructuredName); // unstructuredName
    oids.put(
        "unstructuredaddress",
        CeSecoreNameStyle.UnstructuredAddress); // unstructuredAddress
    oids.put("postalcode", CeSecoreNameStyle.POSTAL_CODE);
    oids.put("businesscategory", CeSecoreNameStyle.BUSINESS_CATEGORY);
    oids.put("postaladdress", CeSecoreNameStyle.POSTAL_ADDRESS);
    oids.put("telephonenumber", CeSecoreNameStyle.TELEPHONE_NUMBER);
    oids.put("pseudonym", CeSecoreNameStyle.PSEUDONYM);
    oids.put("street", CeSecoreNameStyle.STREET);
    oids.put("name", CeSecoreNameStyle.NAME);
    oids.put("description", CeSecoreNameStyle.DESCRIPTION);
    oids.put("jurisdictionlocality", CeSecoreNameStyle.JURISDICTION_LOCALITY);
    oids.put("jurisdictionstate", CeSecoreNameStyle.JURISDICTION_STATE);
    oids.put("jurisdictioncountry", CeSecoreNameStyle.JURISDICTION_COUNTRY);
    oids.put(
        "organizationidentifier", CeSecoreNameStyle.ORGANIZATION_IDENTIFIER);
  }
  /**
   * Default values used when constructing DN strings that are put in the
   * database.
   */
  private static String[] dNObjectsForward = {
    "description",
    "jurisdictioncountry",
    "jurisdictionstate",
    "jurisdictionlocality",
    "street",
    "pseudonym",
    "telephonenumber",
    "postaladdress",
    "businesscategory",
    "postalcode",
    "unstructuredaddress",
    "unstructuredname",
    "emailaddress",
    "e",
    "email",
    "dn",
    "uid",
    "cn",
    "name",
    "sn",
    "serialnumber",
    "gn",
    "givenname",
    "initials",
    "surname",
    "t",
    "ou",
    "organizationidentifier",
    "o",
    "l",
    "st",
    "dc",
    "c"
  };
  /** Default values. */
  private static String[] dNObjectsReverse = null;

  /*
   * These maps and constants are used in the admin-GUI and in End Entity
   * profiles
   */

  /*
   * These constants can be used when referring to standard,
   * build in components.
   */
  // DN components
  /** Email. */
  public static final String DNEMAILADDRESS = "EMAILADDRESS";

  /** Qual.*/
  public static final String DNQUALIFIER = "DNQUALIFIER";
  /** UID. */
  public static final String UID = "UID";
  /** CN. */
  public static final String COMMONNAME = "COMMONNAME";
  /** SN. */
  public static final String DNSERIALNUMBER = "SERIALNUMBER";
  /** Given. */
  public static final String GIVENNAME = "GIVENNAME";
  /** Given. */
  public static final String INITIALS = "INITIALS";
  /** Surname. */
  public static final String SURNAME = "SURNAME";
  /** Title. */
  public static final String TITLE = "TITLE";
  /** Unit. */
  public static final String ORGANIZATIONALUNIT = "ORGANIZATIONALUNIT";
  /** Org. */
  public static final String ORGANIZATION = "ORGANIZATION";
  /** Locality. */
  public static final String LOCALITY = "LOCALITY";
  /** State. */
  public static final String STATEORPROVINCE = "STATEORPROVINCE";
  /** Domain. */
  public static final String DOMAINCOMPONENT = "DOMAINCOMPONENT";
  /** Country. */
  public static final String COUNTRY = "COUNTRY";
  /** Address. */
  public static final String UNSTRUCTUREDADDRESS = "UNSTRUCTUREDADDRESS";
  /** Name. */
  public static final String UNSTRUCTUREDNAME = "UNSTRUCTUREDNAME";
  /** Postcode. */
  public static final String POSTALCODE = "POSTALCODE";
  /** Category. */
  public static final String BUSINESSCATEGORY = "BUSINESSCATEGORY";
  /** Address. */
  public static final String POSTALADDRESS = "POSTALADDRESS";
  /** Tel. */
  public static final String TELEPHONENUMBER = "TELEPHONENUMBER";
  /** Pseud. */
  public static final String PSEUDONYM = "PSEUDONYM";
  /** Address. */
  public static final String STREETADDRESS = "STREETADDRESS";
  /** Name. */
  public static final String NAME = "NAME";
  /** Desc. */
  public static final String DESCRIPTION = "DESCRIPTION";
  /** Locality. */
  public static final String JURISDICTIONLOCALITY = "JURISDICTIONLOCALITY";
  /** State. */
  public static final String JURISDICTIONSTATE = "JURISDICTIONSTATE";
  /** Country. */
  public static final String JURISDICTIONCOUNTRY = "JURISDICTIONCOUNTRY";
  /** Org. */
  public static final String ORGANIZATIONIDENTIFIER = "ORGANIZATIONIDENTIFIER";

  // AltNames
  /** Email. */
  public static final String RFC822NAME = "RFC822NAME";
  /** DNS. */
  public static final String DNSNAME = "DNSNAME";
  /** IP. */
  public static final String IPADDRESS = "IPADDRESS";
  /** URI. */
  public static final String UNIFORMRESOURCEID = "UNIFORMRESOURCEID";
  /** Dir. */
  public static final String DIRECTORYNAME = "DIRECTORYNAME";
  /** UPN. */
  public static final String UPN = "UPN";
  /** XMPP. */
  public static final String XMPPADDR = "XMPPADDR";
  /** Server. */
  public static final String SRVNAME = "SRVNAME";
  /** FASCN. */
  public static final String FASCN = "FASCN";
  /** GUID. */
  public static final String GUID = "GUID";
  /** Kerberos. */
  public static final String KRB5PRINCIPAL = "KRB5PRINCIPAL";
  /** ID. */
  public static final String PERMANENTIDENTIFIER = "PERMANENTIDENTIFIER";
  /** Method. */
  public static final String SUBJECTIDENTIFICATIONMETHOD =
      "SUBJECTIDENTIFICATIONMETHOD";
  // Below are altNames that are not implemented yet
  /** Name. */
  public static final String OTHERNAME = "OTHERNAME";
  /** X400. */
  public static final String X400ADDRESS = "X400ADDRESS";
  /** Name. */
  public static final String EDIPARTYNAME = "EDIPARTYNAME";
  /// RegisteredID is a standard (rfc5280 otherName that we implement)
  /** ID. */
  public static final String REGISTEREDID = "REGISTEREDID";

  // Subject directory attributes
  /** DOB. */
  public static final String DATEOFBIRTH = "DATEOFBIRTH";
  /** POB. */
  public static final String PLACEOFBIRTH = "PLACEOFBIRTH";
  /** Gender. */
  public static final String GENDER = "GENDER";
  /** Location. */
  public static final String COUNTRYOFCITIZENSHIP = "COUNTRYOFCITIZENSHIP";
  /** Location. */
  public static final String COUNTRYOFRESIDENCE = "COUNTRYOFRESIDENCE";

  /** Names. */
  private static HashMap<String, Integer> dnNameToIdMap = new HashMap<>();
  /** Names. */
  private static HashMap<String, Integer> altNameToIdMap = new HashMap<>();
  /** IDs. */
  private static HashMap<String, Integer> dirAttrToIdMap = new HashMap<>();
  /** IDs. */
  private static HashMap<String, Integer> profileNameIdMap = new HashMap<>();
  /** Names. */
  private static HashMap<Integer, String> dnIdToProfileNameMap =
      new HashMap<>();
  /** Profiles. */
  private static HashMap<Integer, Integer> dnIdToProfileIdMap = new HashMap<>();
  /** IDs. */
  private static HashMap<Integer, Integer> profileIdToDnIdMap = new HashMap<>();
  /** Errors. */
  private static HashMap<Integer, String> dnErrorTextMap = new HashMap<>();
  /** Languages. */
  private static HashMap<String, String> profileNameLanguageMap =
      new HashMap<>();
  /** Profiles. */
  private static HashMap<Integer, String> profileIdLanguageMap =
      new HashMap<>();
  /** Errors. */
  private static HashMap<Integer, String> dnIdErrorMap = new HashMap<>();
  /** IDs. */
  private static HashMap<Integer, String> dnIdToExtractorFieldMap =
      new HashMap<>();
  /** Names. */
  private static HashMap<Integer, String> altNameIdToExtractorFieldMap =
      new HashMap<>();
  /** Attrs. */
  private static HashMap<Integer, String> dirAttrIdToExtractorFieldMap =
      new HashMap<>();
  /** Fields. */
  private static ArrayList<String> dnProfileFields = new ArrayList<>();
  /** Profile fields. */
  private static final TreeSet<String> DN_PROFILE_FIELDS_SET = new TreeSet<>();
  /** Languages. */
  private static ArrayList<String> dnLanguageTexts = new ArrayList<>();
  /** IDs. */
  private static ArrayList<Integer> dnDnIds = new ArrayList<>();
  /** Names. */
  private static ArrayList<String> altNameFields = new ArrayList<>();
  /** Names. */
  private static final TreeSet<String> ALT_NAME_FIELDS_SET = new TreeSet<>();
  /** Names. */
  private static ArrayList<String> altNameLanguageTexts = new ArrayList<>();
  /** IDs. */
  private static ArrayList<Integer> altNameDnIds = new ArrayList<>();
  /** Fields. */
  private static ArrayList<String> dirAttrFields = new ArrayList<>();
  /** Fields.  */
  private static final TreeSet<String> DIR_ATTR_FIELDS_SET = new TreeSet<>();
  /** Languages. */
  private static ArrayList<String> dirAttrLanguageTexts = new ArrayList<>();
  /** IDs. */
  private static ArrayList<Integer> dirAttrDnIds = new ArrayList<>();
  /** Fields. */
  private static ArrayList<String> dnExtractorFields = new ArrayList<>();
  /** Names. */
  private static ArrayList<String> altNameExtractorFields = new ArrayList<>();
  /** Attrs. */
  private static ArrayList<String> dirAttrExtractorFields = new ArrayList<>();

  // Load values from a properties file, if it exists
  static {
    DnComponents.load();
  }

  private DnComponents() { }
  /**
   * @param dnName name
   * @return id
   */
  public static Integer getDnIdFromDnName(final String dnName) {
    return dnNameToIdMap.get(dnName.toUpperCase(Locale.ROOT));
  }

  /**
   * @param altName name
   * @return id
   */
  public static Integer getDnIdFromAltName(final String altName) {
    return altNameToIdMap.get(altName.toUpperCase(Locale.ROOT));
  }

  /**
   * @param dirAttr attr
   * @return id
   */
  public static Integer getDnIdFromDirAttr(final String dirAttr) {
    return dirAttrToIdMap.get(dirAttr.toUpperCase(Locale.ROOT));
  }
  /**
   * @param o OID
   * @return ASN1
   */
  public static ASN1ObjectIdentifier getOid(final String o) {
    return oids.get(o.toLowerCase(Locale.ROOT));
  }
  /**
   * @return list
   */
  public static ArrayList<String> getDnProfileFields() {
    return dnProfileFields;
  }
  /**
   * @param field field
   * @return bool
   */
  public static boolean isDnProfileField(final String field) {
    return DN_PROFILE_FIELDS_SET.contains(field);
  }
  /**
   * @return list
   */
  public static ArrayList<String> getDnLanguageTexts() {
    return dnLanguageTexts;
  }
  /**
   * @return list
   */
  public static ArrayList<String> getAltNameFields() {
    return altNameFields;
  }

  /**
   * @param field field
   * @return bool
   */
  public static boolean isAltNameField(final String field) {
    return ALT_NAME_FIELDS_SET.contains(field);
  }

  /**
   * @return list
   */
  public static ArrayList<String> getAltNameLanguageTexts() {
    return altNameLanguageTexts;
  }

 /**
  * @return list
  */
  public static ArrayList<String> getDirAttrFields() {
    return dirAttrFields;
  }

  /**
   * @param field field
   * @return bool
   */
  public static boolean isDirAttrField(final String field) {
    return DIR_ATTR_FIELDS_SET.contains(field);
  }

  /** Used by DNFieldExtractor and EntityProfile, don't USE.
 * @return List
   * */
  public static ArrayList<Integer> getDirAttrDnIds() {
    return dirAttrDnIds;
  }


  /**
   * Used by DNFieldExtractor and EntityProfile, don't USE.
   * @return list
   */
  public static ArrayList<Integer> getAltNameDnIds() {
    return altNameDnIds;
  }


  /** Used by DNFieldExtractor and EntityProfile, don't USE.
   * @return list
   */
  public static ArrayList<Integer> getDnDnIds() {
    return dnDnIds;
  }

  // Used only by DNFieldExtractor, don't USE
  protected static ArrayList<String> getDnExtractorFields() {
    return dnExtractorFields;
  }

  protected static String getDnExtractorFieldFromDnId(final int field) {
    String val = (String) dnIdToExtractorFieldMap.get(Integer.valueOf(field));
    return val;
  }

  // Used only by DNFieldExtractor, don't USE
  protected static ArrayList<String> getAltNameExtractorFields() {
    return altNameExtractorFields;
  }

  protected static String getAltNameExtractorFieldFromDnId(final int field) {
    String val =
        (String) altNameIdToExtractorFieldMap.get(Integer.valueOf(field));
    return val;
  }

  // Used only by DNFieldExtractor, don't USE
  protected static ArrayList<String> getDirAttrExtractorFields() {
    return dirAttrExtractorFields;
  }

  protected static String getDirAttrExtractorFieldFromDnId(final int field) {
    String val =
        (String) dirAttrIdToExtractorFieldMap.get(Integer.valueOf(field));
    return val;
  }

  /**
   * @param dnid DN
   * @return Name
   */
  public static String dnIdToProfileName(final int dnid) {
    String val = (String) dnIdToProfileNameMap.get(Integer.valueOf(dnid));
    return val;
  }

  /**
   * @param dnid DN
   * @return ID
   */
  public static int dnIdToProfileId(final int dnid) {
    Integer val = (Integer) dnIdToProfileIdMap.get(Integer.valueOf(dnid));
    return val.intValue();
  }

  /**
   * Method to get a language error constant for the admin-GUI from a profile
   * name.
   *
   * @param name name
   * @return language
   */
  public static String getLanguageConstantFromProfileName(final String name) {
    String ret = (String) profileNameLanguageMap.get(name);
    return ret;
  }

  /**
   * Method to get a language error constant for
   * the admin-GUI from a profile id.
   *
   * @param id ID
   * @return language
   */
  public static String getLanguageConstantFromProfileId(final int id) {
    String ret = (String) profileIdLanguageMap.get(Integer.valueOf(id));
    return ret;
  }

  /**
   * Method to get a clear text error msg for the admin-GUI from a dn id.
   *
   * @param id ID
   * @return error text
   */
  public static String getErrTextFromDnId(final int id) {
    String ret = (String) dnIdErrorMap.get(Integer.valueOf(id));
    return ret;
  }

  /**
   * This method is only used to initialize EndEntityProfile, because of legacy
   * baggage. Should be refactored sometime! Please don't use this whatever you
   * do!
   *
   * @return map
   */
  public static HashMap<String, Integer> getProfilenameIdMap() {
    return profileNameIdMap;
  }

  /**
   * A function that takes an fieldId pointing to a corresponding id in UserView
   * and DnFieldExctractor. For example :
   * profileFieldIdToUserFieldIdMapper(EndEntityProfile.COMMONNAME) returns
   * DnFieldExctractor.COMMONNAME.
   *
   * <p>Should only be used with subjectDN, Subject Alternative Names and
   * subject directory attribute fields.
   *
   * @param profileid ID
   * @return DN ID
   */
  public static int profileIdToDnId(final int profileid) {
    Integer val = (Integer) profileIdToDnIdMap.get(Integer.valueOf(profileid));
    if (val == null) {
      log.error("No dn id mapping from profile id " + profileid);
      // We allow it to fail here
    }
    return val.intValue();
  }

  /**
   * Returns the dnObjects (forward or reverse). ldaporder = true is the default
   * order in EJBCA.
   *
   * @param ldaporder boolean
   * @return objects
   */
  public static String[] getDnObjects(final boolean ldaporder) {
    if (ldaporder) {
      return dNObjectsForward;
    }
    return getDnObjectsReverse();
  }

  /**
   * Returns the reversed dnObjects. Protected to allow testing
   *
   * @return objects
   */
  protected static String[] getDnObjectsReverse() {
    // Create and reverse the order if it has not been initialized already
    if (dNObjectsReverse == null) {
      // this cast is not needed in java 5, but is needed for java 1.4
      dNObjectsReverse = (String[]) dNObjectsForward.clone();
      ArrayUtils.reverse(dNObjectsReverse);
    }
    return dNObjectsReverse;
  }

  private static void load() {
    loadOrdering();
    loadMappings();
  }

  /**
   * Load DN ordering used in CertTools.stringToBCDNString etc. Loads from file
   * placed in src/dncomponents.properties
   *
   * <p>A line is:
   * DNName;DNid;ProfileName;ProfileId,ErrorString,LanguageConstant
   */
  private static void loadMappings() {
    loadProfileMappingsFromFile("/profilemappings.properties");
    loadProfileMappingsFromFile("/profilemappings_enterprise.properties");
  }

  /**
   * @return bool
   */
  public static boolean enterpriseMappingsExist() {
    return obj.getClass()
            .getResourceAsStream("/profilemappings_enterprise.properties")
        != null;
  }

  /**
   * Reads properties from a properties file. Fails nicely if file wasn't found.
   *
   * @param propertiesFile File
   */
  private static void loadProfileMappingsFromFile(// NOPMD: length
          final String propertiesFile) {
    // Read the file to an array of lines
    String line;

    BufferedReader in = null;
    InputStreamReader inf = null;
    try {
      InputStream is = obj.getClass().getResourceAsStream(propertiesFile);
      if (is != null) {
        inf = new InputStreamReader(is);
        in = new BufferedReader(inf);
        if (!in.ready()) {
          throw new IOException("Couldn't read " + propertiesFile);
        }
        String[] splits = null;
        int lines = 0;
        ArrayList<Integer> dnids = new ArrayList<Integer>();
        ArrayList<Integer> profileids = new ArrayList<Integer>();
        while ((line = in.readLine()) != null) {
          if (!line.startsWith("#")) { // # is a comment line
            splits = StringUtils.split(line, ';');
            if (splits != null && splits.length > 5) {
              String type = splits[0];
              String dnname = splits[1];
              Integer dnid = Integer.valueOf(splits[2]);
              String profilename = splits[3];
              Integer profileid = Integer.valueOf(splits[4]);
              String errstr = splits[5];
              String langstr = splits[6];
              if (dnids.contains(dnid)) {
                log.error(
                    "Duplicated DN Id " + dnid + " detected in mapping file.");
              } else {
                dnids.add(dnid);
              }
              if (profileids.contains(profileid)) {
                log.error(
                    "Duplicated Profile Id "
                        + profileid
                        + " detected in mapping file.");
              } else {
                profileids.add(profileid);
              }
              // Fill maps
              profileNameIdMap.put(profilename, profileid);
              dnIdToProfileNameMap.put(dnid, profilename);
              dnIdToProfileIdMap.put(dnid, profileid);
              dnIdErrorMap.put(dnid, errstr);
              profileIdToDnIdMap.put(profileid, dnid);
              dnErrorTextMap.put(dnid, errstr);
              profileNameLanguageMap.put(profilename, langstr);
              profileIdLanguageMap.put(profileid, langstr);
              if (type.equals("DN")) {
                dnNameToIdMap.put(dnname, dnid);
                dnProfileFields.add(profilename);
                DN_PROFILE_FIELDS_SET.add(profilename);
                dnLanguageTexts.add(langstr);
                dnDnIds.add(dnid);
                dnExtractorFields.add(dnname + "=");
                dnIdToExtractorFieldMap.put(dnid, dnname + "=");
              }
              if (type.equals("ALTNAME")) {
                altNameToIdMap.put(dnname, dnid);
                altNameFields.add(dnname);
                ALT_NAME_FIELDS_SET.add(dnname);
                altNameLanguageTexts.add(langstr);
                altNameDnIds.add(dnid);
                altNameExtractorFields.add(dnname + "=");
                altNameIdToExtractorFieldMap.put(dnid, dnname + "=");
              }
              if (type.equals("DIRATTR")) {
                dirAttrToIdMap.put(dnname, dnid);
                dirAttrFields.add(dnname);
                DIR_ATTR_FIELDS_SET.add(dnname);
                dirAttrLanguageTexts.add(langstr);
                dirAttrDnIds.add(dnid);
                dirAttrExtractorFields.add(dnname + "=");
                dirAttrIdToExtractorFieldMap.put(dnid, dnname + "=");
              }
              lines++;
            }
          }
        }
        in.close();
        if (log.isDebugEnabled()) {
          log.debug("Read profile maps with " + lines + " lines.");
        }
      } else {
        if (log.isDebugEnabled()) {
          log.debug("Properties file " + propertiesFile + " was not found.");
        }
      }
    } catch (IOException e) {
      log.error("Can not load profile mappings: ", e);
    } finally {
      try {
        if (inf != null) {
          inf.close();
        }
        if (in != null) {
          in.close();
        }
      } catch (IOException e) { // NOPMD: no-op
      }
    }
  }

  /**
   * Load DN ordering used in CertTools.stringToBCDNString etc. Loads from file
   * placed in src/dncomponents.properties
   */
  private static void loadOrdering() {
    // Read the file to an array of lines
    String line;
    LinkedHashMap<String, ASN1ObjectIdentifier> map =
        new LinkedHashMap<String, ASN1ObjectIdentifier>();
    BufferedReader in = null;
    InputStreamReader inf = null;
    try {
      InputStream is =
          obj.getClass().getResourceAsStream("/dncomponents.properties");
      // log.info("is is: " + is);
      if (is != null) {
        inf = new InputStreamReader(is);
        // inf = new FileReader("c:\\foo.properties");
        in = new BufferedReader(inf);
        if (!in.ready()) {
          throw new IOException();
        }
        String[] splits = null;
        while ((line = in.readLine()) != null) {
          if (!line.startsWith("#")) { // # is a comment line
            splits = StringUtils.split(line, '=');
            if (splits != null && splits.length > 1) {
              String name = splits[0].toLowerCase(Locale.ROOT);
              ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(splits[1]);
              map.put(name, oid);
            }
          }
        }
        in.close();
        // Now we have read it in, transfer it to the main oid map
        log.info("Using DN components from properties file");
        oids.clear();
        oids.putAll(map);
        Set<String> keys = map.keySet();
        // Set the maps to the desired ordering
        dNObjectsForward = (String[]) keys.toArray(new String[keys.size()]);
      } else {
        log.debug("Using default values for DN components");
      }
    } catch (IOException e) {
      log.debug("Using default values for DN components");
    } finally {
      try {
        if (inf != null) {
          inf.close();
        }
        if (in != null) {
          in.close();
        }
      } catch (IOException e) { // NOPMD: no-op
      }
    }
  }
}
