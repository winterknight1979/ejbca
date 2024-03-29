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

package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.Base64Util;
import org.cesecore.util.StringUtil;
import org.cesecore.util.ValidityDateUtil;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * The model representation of an end entity profile.
 *
 * <p>The algorithm for constants in the EndEntityProfile is: Values are stored
 * as 100*parameternumber+parameter, so the first COMMONNAME value is 105, the
 * second 205 etc. Use flags are stored as 10000+100*parameternumber+parameter,
 * so the first USE_COMMONNAME value is 10105, the second 10205 etc. Required
 * flags are stored as 20000+100*parameternumber+parameter, so the first
 * REQUIRED_COMMONNAME value is 20105, the second 20205 etc. Modifyable flags
 * are stored as 30000+100*parameternumber+parameter, so the first
 * MODIFYABLE_COMMONNAME value is 30105, the second 30205 etc.
 *
 * <p>Parsing an exported End Entity Profile XML (or from the getProfile method
 * in the web service): The End Entity Profile XML data is encoded using the
 * standard Java XMLEncoder. To decode it you can use the SecureXMLDecoder
 * class, which is part of CESeCore. The result will be a
 * Map&lt;Object,Object&gt;.
 *
 * <p>In the map there's for example a field SUBJECTDNFIELDORDER which contains
 * a list of defined DN components, as integers. The algorithm is: 100*parameter
 * + index
 *
 * <p>So for example if SUBJECTDNFIELDORDER contains the two values "500, 1100"
 * this means there is one CN and one OU. Numbers are defined in
 * src/java/profilemappings.properties and CN=5 and OU=11, so 100*5+0 = 500 and
 * 100*11+0 = 1100. If there would be two OU fields there would also be one 1101
 * (100*11+1) in the SUBJECTDNFIELDORDER.
 *
 * <p>For getting more detailed information (e.g. whether the field is required)
 * or to look up a non-DN field (such as username), you will need to compute and
 * index and get that key from the map (instead of SUBJECTDNFIELDORDER). For
 * example you can see if the first CN field is required by finding a key in the
 * XML with the formula: 20000+100*0+5 = 20005 if the value of this key is true,
 * the first CN field is required and not optional. etc, for the second CN field
 * (if there was a second one in SUBJECTDNFIELDORDER) it would be 20000+100*1+5.
 *
 * <p>Instead of 20000 you may use the values X*10000 where X may be (0 = value,
 * 1 = use, 2 = required, 3 = modifiable, 4 = validation regexp). If you want to
 * access a field which is not a DN field, see the "dataConstants.put" lines
 * below (e.g. Available CAs = 38)
 *
 * @version $Id: EndEntityProfile.java 28619 2018-04-03 12:57:23Z mikekushner $
 */
public class EndEntityProfile extends UpgradeableDataHashMap
    implements Serializable, Cloneable {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(EndEntityProfile.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Version. */
  public static final float LATEST_VERSION = 14;

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = -8356152324295231463L;

  /** Constant values for end entity profile. */
  private static final HashMap<String, Integer> DATA_CONSTANTS =
          new HashMap<>();

  // Field constants, used in the map below
  /** Config. */
  public static final String USERNAME = "USERNAME";
  /** Config. */
  public static final String PASSWORD = "PASSWORD";
  /** Config. */
  public static final String CLEARTEXTPASSWORD = "CLEARTEXTPASSWORD";
  /** Config. */
  public static final String AUTOGENPASSWORDTYPE = "AUTOGENPASSWORDTYPE";
  /** Config. */
  public static final String AUTOGENPASSWORDLENGTH = "AUTOGENPASSWORDLENGTH";
  /** Config. */
  public static final String EMAIL = "EMAIL";
  /** Config. */
  public static final String KEYRECOVERABLE = "KEYRECOVERABLE";
  /** Config. */
  public static final String DEFAULTCERTPROFILE = "DEFAULTCERTPROFILE";
  /**
   * A list of available certificate profile names can be retrieved with
   * getAvailableCertificateProfileNames().
   */
  public static final String AVAILCERTPROFILES = "AVAILCERTPROFILES";
  /** Config. */

  public static final String DEFKEYSTORE = "DEFKEYSTORE";
  /** Config. */
  public static final String AVAILKEYSTORE = "AVAILKEYSTORE";
  /** Config. */
  public static final String DEFAULTTOKENISSUER = "DEFAULTTOKENISSUER";
  /** Config. */
  public static final String AVAILTOKENISSUER = "AVAILTOKENISSUER";
  /** Config. */
  public static final String SENDNOTIFICATION = "SENDNOTIFICATION";
  /** Config. */
  public static final String CARDNUMBER = "CARDNUMBER";
  /** Config. */
  public static final String DEFAULTCA = "DEFAULTCA";
  /** Config. */
  public static final String AVAILCAS = "AVAILCAS";
  /** Config. */
  public static final String STARTTIME =
      ExtendedInformation.CUSTOM_STARTTIME; // "STARTTIME"
  /** Config. */
  public static final String ENDTIME =
      ExtendedInformation.CUSTOM_ENDTIME; // "ENDTIME"
  /** Config. */
  public static final String CERTSERIALNR = "CERTSERIALNR";
  /** Config. */
  public static final String NAMECONSTRAINTS_PERMITTED =
      "NAMECONSTRAINTS_PERMITTED";
  /** Config. */
  public static final String NAMECONSTRAINTS_EXCLUDED =
      "NAMECONSTRAINTS_EXCLUDED";
  /**
   * A maximum value of the (optional) counter specifying how many certificate
   * requests can be processed before user is finalized (status set to
   * GENERATED). Counter is only used when finishUser is enabled in the CA (by
   * default it is)
   */
  public static final String ALLOWEDREQUESTS = "ALLOWEDREQUESTS";
  /**
   * A revocation reason that will be applied immediately to certificates issued
   * to a user. With this we can issue a certificate that is "on hold" directly
   * when the user gets the certificate.
   */
  public static final String ISSUANCEREVOCATIONREASON =
      "ISSUANCEREVOCATIONREASON";

  /** Config. */
  public static final String MAXFAILEDLOGINS = "MAXFAILEDLOGINS";

  /** Minimum password strength in bits. */
  public static final String MINPWDSTRENGTH = "MINPWDSTRENGTH";

  // Default values
  // These must be in a strict order that can never change
  // Custom values configurable in a properties file
  // (profilemappings.properties)
  static {
    DATA_CONSTANTS.put(USERNAME, Integer.valueOf(0));
    DATA_CONSTANTS.put(PASSWORD, Integer.valueOf(1));
    DATA_CONSTANTS.put(CLEARTEXTPASSWORD, Integer.valueOf(2));
    DATA_CONSTANTS.put(AUTOGENPASSWORDTYPE, Integer.valueOf(95));
    DATA_CONSTANTS.put(AUTOGENPASSWORDLENGTH, Integer.valueOf(96));
    // DN components

    DATA_CONSTANTS.put(EMAIL, Integer.valueOf(26));
    DATA_CONSTANTS.put(KEYRECOVERABLE, Integer.valueOf(28));
    DATA_CONSTANTS.put(DEFAULTCERTPROFILE, Integer.valueOf(29));
    DATA_CONSTANTS.put(AVAILCERTPROFILES, Integer.valueOf(30));
    DATA_CONSTANTS.put(DEFKEYSTORE, Integer.valueOf(31));
    DATA_CONSTANTS.put(AVAILKEYSTORE, Integer.valueOf(32));
    DATA_CONSTANTS.put(DEFAULTTOKENISSUER, Integer.valueOf(33));
    DATA_CONSTANTS.put(AVAILTOKENISSUER, Integer.valueOf(34));
    DATA_CONSTANTS.put(SENDNOTIFICATION, Integer.valueOf(35));

    DATA_CONSTANTS.put(DEFAULTCA, Integer.valueOf(37));
    DATA_CONSTANTS.put(AVAILCAS, Integer.valueOf(38));

    // Load all DN, altName and directoryAttributes from DnComponents.
    DATA_CONSTANTS.putAll(DnComponents.getProfilenameIdMap());

    DATA_CONSTANTS.put(ISSUANCEREVOCATIONREASON, Integer.valueOf(94));
    DATA_CONSTANTS.put(ALLOWEDREQUESTS, Integer.valueOf(97));
    DATA_CONSTANTS.put(STARTTIME, Integer.valueOf(98));
    DATA_CONSTANTS.put(ENDTIME, Integer.valueOf(99));
    DATA_CONSTANTS.put(CARDNUMBER, Integer.valueOf(91));
    DATA_CONSTANTS.put(MAXFAILEDLOGINS, Integer.valueOf(93));
    DATA_CONSTANTS.put(CERTSERIALNR, Integer.valueOf(92));
    DATA_CONSTANTS.put(MINPWDSTRENGTH, Integer.valueOf(90));
    DATA_CONSTANTS.put(NAMECONSTRAINTS_PERMITTED, Integer.valueOf(89));
    DATA_CONSTANTS.put(NAMECONSTRAINTS_EXCLUDED, Integer.valueOf(88));
  }
  // The max value in dataConstants (we only want to do this once)
  /** Config. */
  private static final int DATA_CONSTANTS_MAX_VALUE =
      Collections.max(DATA_CONSTANTS.values()).intValue();
  // The keys used when we create an empty profile (we only want to do this
  // once)
  /** Config. */
  private static final List<String> DATA_CONSTANTS_USED_IN_EMPTY =
      new LinkedList<>(DATA_CONSTANTS.keySet());

  static {
    DATA_CONSTANTS_USED_IN_EMPTY.remove(SENDNOTIFICATION);
    DATA_CONSTANTS_USED_IN_EMPTY.remove(DnComponents.OTHERNAME);
    DATA_CONSTANTS_USED_IN_EMPTY.remove(DnComponents.X400ADDRESS);
    DATA_CONSTANTS_USED_IN_EMPTY.remove(DnComponents.EDIPARTYNAME);
  }

  // Type of data constants.
  /** Config. */
  private static final int VALUE = 0;
  /** Config. */
  private static final int USE = 1;
  /** Config. */
  private static final int ISREQUIRED = 2;
  /** Config. */
  private static final int MODIFYABLE = 3;
  /** Config. */
  private static final int VALIDATION = 4;

  // Private Constants.
  /** Config. */
  private static final int FIELDBOUNDRARY = 10000;
  /** Config. */
  private static final int NUMBERBOUNDRARY = 100;

  // Pre-calculated constants
  /** Config. */
  private static final int FIELDBOUNDRARY_VALUE = FIELDBOUNDRARY * VALUE;
  /** Config. */
  private static final int FIELDBOUNDRARY_USE = FIELDBOUNDRARY * USE;
  /** Config. */
  private static final int FIELDBOUNDRARY_ISREQUIRED =
      FIELDBOUNDRARY * ISREQUIRED;
  /** Config. */
  private static final int FIELDBOUNDRARY_MODIFYABLE =
      FIELDBOUNDRARY * MODIFYABLE;
  /** Config. */
  private static final int FIELDBOUNDRARY_VALIDATION =
      FIELDBOUNDRARY * VALIDATION;

  /** Config. */
  public static final String SPLITCHAR = ";";

  /** Config. */
  public static final String TRUE = "true";
  /** Config. */
  public static final String FALSE = "false";

  // Constants used with field ordering
  /** Config. */
  public static final int FIELDTYPE = 0;
  /** Config. */
  public static final int NUMBER = 1;

  /**
   * Number array keeps track of how many fields there are of a specific type,
   * for example 2 OranizationUnits, 0 TelephoneNumber.
   */
  private static final String NUMBERARRAY = "NUMBERARRAY";

  /** Config. */
  private static final String SUBJECTDNFIELDORDER = "SUBJECTDNFIELDORDER";
  /** Config. */
  private static final String SUBJECTALTNAMEFIELDORDER =
      "SUBJECTALTNAMEFIELDORDER";
  /** Config. */
  private static final String SUBJECTDIRATTRFIELDORDER =
      "SUBJECTDIRATTRFIELDORDER";

  /** Config. */
  private static final String USERNOTIFICATIONS = "USERNOTIFICATIONS";

  /** Config. */
  private static final String REUSECERTIFICATE = "REUSECERTIFICATE";
  /** Config. */
  private static final String REVERSEFFIELDCHECKS = "REVERSEFFIELDCHECKS";
  /** Config. */
  private static final String ALLOW_MERGEDN_WEBSERVICES =
      "ALLOW_MERGEDN_WEBSERVICES";

  /** Config. */
  private static final String PRINTINGUSE = "PRINTINGUSE";
  /** Config. */
  private static final String PRINTINGDEFAULT = "PRINTINGDEFAULT";
  /** Config. */
  private static final String PRINTINGREQUIRED = "PRINTINGREQUIRED";
  /** Config. */
  private static final String PRINTINGCOPIES = "PRINTINGCOPIES";
  /** Config. */
  private static final String PRINTINGPRINTERNAME = "PRINTINGPRINTERNAME";
  /** Config. */
  private static final String PRINTINGSVGFILENAME = "PRINTINGSVGFILENAME";
  /** Config. */
  private static final String PRINTINGSVGDATA = "PRINTINGSVGDATA";

  /**
   * If it should be possible to add/edit certificate extension data when
   * adding/editing an end entity using the admin web or not.
   */
  private static final String USEEXTENSIONDATA = "USEEXTENSIONDATA";

  // String constants that never change, so we can do the String
  // concat/conversion once
  /** Config. */
  private static final String CONST_DEFAULTCERTPROFILE =
      Integer.toString(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
  /** Config. */
  private static final String CONST_AVAILCERTPROFILES1 =
      CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER
          + ";"
          + CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER
          + ";"
          + CertificateProfileConstants.CERTPROFILE_FIXED_SERVER;
  /** Config. */
  private static final String CONST_DEFKEYSTORE =
      Integer.toString(SecConst.TOKEN_SOFT_BROWSERGEN);
  /** Config. */
  private static final String CONST_AVAILKEYSTORE =
      SecConst.TOKEN_SOFT_BROWSERGEN
          + ";"
          + SecConst.TOKEN_SOFT_P12
          + ";"
          + SecConst.TOKEN_SOFT_JKS
          + ";"
          + SecConst.TOKEN_SOFT_PEM;
  /** Config. */
  private static final String CONST_AVAILCAS =
      Integer.toString(SecConst.ALLCAS);
  /** Config. */
  private static final String CONST_ISSUANCEREVOCATIONREASON =
      Integer.toString(RevokedCertInfo.NOT_REVOKED);
  /** Config. */
  private static final String CONST_AVAILCERTPROFILES2 =
      CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER
          + ";"
          + CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA
          + ";"
          + CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;

  /**
   * Creates a new instance of EndEntity Profile with the default fields set.
   */
  public EndEntityProfile() {
    super();
    init(false);
  }

  /**
   * Creates a default empty end entity profile with all standard fields added
   * to it.
   *
   * @param emptyprofile profile
   */
  public EndEntityProfile(final boolean emptyprofile) {
    super();
    init(emptyprofile);
  }
  /**
   * Creates a new instance of EndEntity Profile used during cloning or when we
   * load all the data from the database.
   *
   * @param unused unused
   */
  public EndEntityProfile(final int unused) { }

  private void init(final boolean emptyprofile) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
        "The highest number in dataConstants is: " + DATA_CONSTANTS_MAX_VALUE);
    }
    // Common initialization of profile
    final List<Integer> numberoffields =
            new ArrayList<>(DATA_CONSTANTS_MAX_VALUE);
    Collections.fill(numberoffields, Integer.valueOf(0));
    data.put(NUMBERARRAY, numberoffields);
    data.put(SUBJECTDNFIELDORDER, new ArrayList<Integer>());
    data.put(SUBJECTALTNAMEFIELDORDER, new ArrayList<Integer>());
    data.put(SUBJECTDIRATTRFIELDORDER, new ArrayList<Integer>());

    if (emptyprofile) {
      for (final String key : DATA_CONSTANTS_USED_IN_EMPTY) {
        addFieldWithDefaults(
            key, "", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);
      }
      // Add another DC-field since (if used) more than one is always used
      addFieldWithDefaults(
          DnComponents.DOMAINCOMPONENT,
          "",
          Boolean.FALSE,
          Boolean.TRUE,
          Boolean.TRUE);
      // Add another SAN DNSname field, for the server certificates (ref. RFC
      // 6125)
      addFieldWithDefaults(
          DnComponents.DNSNAME, "", Boolean.FALSE, Boolean.TRUE, Boolean.TRUE);
      // Set required fields
      setRequired(USERNAME, 0, true);
      setRequired(PASSWORD, 0, true);
      setRequired(DnComponents.COMMONNAME, 0, true);
      setRequired(DEFAULTCERTPROFILE, 0, true);
      setRequired(AVAILCERTPROFILES, 0, true);
      setRequired(DEFKEYSTORE, 0, true);
      setRequired(AVAILKEYSTORE, 0, true);
      setRequired(DEFAULTCA, 0, true);
      setRequired(AVAILCAS, 0, true);
      setRequired(ISSUANCEREVOCATIONREASON, 0, false);
      setRequired(STARTTIME, 0, false);
      setRequired(ENDTIME, 0, false);
      setRequired(ALLOWEDREQUESTS, 0, false);
      setRequired(CARDNUMBER, 0, false);
      setRequired(MAXFAILEDLOGINS, 0, false);
      setRequired(NAMECONSTRAINTS_EXCLUDED, 0, false);
      setRequired(NAMECONSTRAINTS_PERMITTED, 0, false);
      setValue(DEFAULTCERTPROFILE, 0, CONST_DEFAULTCERTPROFILE);
      setValue(AVAILCERTPROFILES, 0, CONST_AVAILCERTPROFILES1);
      setValue(DEFKEYSTORE, 0, CONST_DEFKEYSTORE);
      setValue(AVAILKEYSTORE, 0, CONST_AVAILKEYSTORE);
      setValue(AVAILCAS, 0, CONST_AVAILCAS);
      setValue(ISSUANCEREVOCATIONREASON, 0, CONST_ISSUANCEREVOCATIONREASON);
      // Do not use hard token issuers by default.
      setUse(AVAILTOKENISSUER, 0, false);
      setUse(STARTTIME, 0, false);
      setUse(ENDTIME, 0, false);
      setUse(ALLOWEDREQUESTS, 0, false);
      setUse(CARDNUMBER, 0, false);
      setUse(ISSUANCEREVOCATIONREASON, 0, false);
      setUse(MAXFAILEDLOGINS, 0, false);
      setValue(
          MAXFAILEDLOGINS,
          0,
          Integer.toString(ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS));
      setUse(MINPWDSTRENGTH, 0, false);
      setUse(NAMECONSTRAINTS_PERMITTED, 0, false);
      setUse(NAMECONSTRAINTS_EXCLUDED, 0, false);
    } else {
      // initialize profile data
      addFieldWithDefaults(
          USERNAME, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
      addFieldWithDefaults(
          PASSWORD, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
      addField(AUTOGENPASSWORDTYPE);
      addFieldWithDefaults(
          AUTOGENPASSWORDLENGTH,
          "8",
          Boolean.FALSE,
          Boolean.TRUE,
          Boolean.TRUE);
      addFieldWithDefaults(
          DnComponents.COMMONNAME,
          "",
          Boolean.TRUE,
          Boolean.TRUE,
          Boolean.TRUE);
      addField(EMAIL);
      addFieldWithDefaults(
          DEFAULTCERTPROFILE,
          CONST_DEFAULTCERTPROFILE,
          Boolean.TRUE,
          Boolean.TRUE,
          Boolean.TRUE);
      addFieldWithDefaults(
          AVAILCERTPROFILES,
          CONST_AVAILCERTPROFILES2,
          Boolean.TRUE,
          Boolean.TRUE,
          Boolean.TRUE);
      addFieldWithDefaults(
          DEFKEYSTORE,
          CONST_DEFKEYSTORE,
          Boolean.TRUE,
          Boolean.TRUE,
          Boolean.TRUE);
      addFieldWithDefaults(
          AVAILKEYSTORE,
          CONST_AVAILKEYSTORE,
          Boolean.TRUE,
          Boolean.TRUE,
          Boolean.TRUE);
      addField(DEFAULTTOKENISSUER);
      // Do not use hard token issuers by default.
      addFieldWithDefaults(
          AVAILTOKENISSUER, "", Boolean.TRUE, Boolean.FALSE, Boolean.TRUE);
      addFieldWithDefaults(
          AVAILCAS, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
      addFieldWithDefaults(
          DEFAULTCA, "", Boolean.TRUE, Boolean.TRUE, Boolean.TRUE);
      addFieldWithDefaults(
          STARTTIME, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
      addFieldWithDefaults(
          ENDTIME, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
      addFieldWithDefaults(
          ALLOWEDREQUESTS, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
      addFieldWithDefaults(
          CARDNUMBER, "", Boolean.FALSE, Boolean.FALSE, Boolean.TRUE);
      addFieldWithDefaults(
          ISSUANCEREVOCATIONREASON,
          CONST_ISSUANCEREVOCATIONREASON,
          Boolean.FALSE,
          Boolean.FALSE,
          Boolean.TRUE);
      addFieldWithDefaults(
          MAXFAILEDLOGINS,
          Integer.toString(ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS),
          Boolean.FALSE,
          Boolean.FALSE,
          Boolean.TRUE);
      addFieldWithDefaults(
          NAMECONSTRAINTS_PERMITTED,
          "",
          Boolean.FALSE,
          Boolean.FALSE,
          Boolean.TRUE);
      addFieldWithDefaults(
          NAMECONSTRAINTS_EXCLUDED,
          "",
          Boolean.FALSE,
          Boolean.FALSE,
          Boolean.TRUE);
    }
  }

  /**
   * Add a field with value="", required=false, use=true, modifyable=true, if
   * the parameter exists, ignored otherwise.
   *
   * @param parameter param
   */
  public void addField(final String parameter) {
    final int num = getParameterNumber(parameter);
    if (num > 0) {
      addField(num, parameter);
    } else {
      LOG.debug(
          "Parameter does not exist (0 returned as parameter number; "
              + parameter);
    }
  }

  /**
   * Function that adds a field to the profile.
   *
   * @param parameter is the field and one of the field constants.
   */
  public void addField(final int parameter) {
    addField(parameter, getParameter(parameter));
  }

  /**
   * Add a field with value="", required=false, use=true, modifyable=true.
   *
   * @param parameter param
   * @param parameterName name
   */
  private void addField(final int parameter, final String parameterName) {
    addFieldWithDefaults(
        parameter,
        parameterName,
        "",
        Boolean.FALSE,
        Boolean.TRUE,
        Boolean.TRUE,
        null);
  }

  private void addFieldWithDefaults(
      final String parameterName,
      final String value,
      final Boolean required,
      final Boolean use,
      final Boolean modifyable) {
    addFieldWithDefaults(
        getParameterNumber(parameterName),
        parameterName,
        value,
        required,
        use,
        modifyable,
        null);
  }

  private void addFieldWithDefaults(
      final int parameter,
      final String parameterName,
      final String value,
      final Boolean required,
      final Boolean use,
      final Boolean modifyable,
      final LinkedHashMap<String, Object> validation) {
    final int size = getNumberOfField(parameter);
    // Perform operations directly on "data" to save some cycles..
    final int offset = (NUMBERBOUNDRARY * size) + parameter;
    data.put(Integer.valueOf(FIELDBOUNDRARY_VALUE + offset), value);
    data.put(Integer.valueOf(FIELDBOUNDRARY_ISREQUIRED + offset), required);
    data.put(Integer.valueOf(FIELDBOUNDRARY_USE + offset), use);
    data.put(Integer.valueOf(FIELDBOUNDRARY_MODIFYABLE + offset), modifyable);
    if (validation != null) {
      // validation should be a map of a validator class name (excluding package
      // name) and a validator-specific object.
      data.put(Integer.valueOf(FIELDBOUNDRARY_VALIDATION + offset), validation);
    } else {
      data.remove(Integer.valueOf(FIELDBOUNDRARY_VALIDATION + offset));
    }
    if (DnComponents.isDnProfileField(parameterName)) {
      @SuppressWarnings("unchecked")
      final ArrayList<Integer> fieldorder =
          (ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER);
      final Integer val = Integer.valueOf((NUMBERBOUNDRARY * parameter) + size);
      fieldorder.add(val);
    } else if (DnComponents.isAltNameField(parameterName)) {
      @SuppressWarnings("unchecked")
      final ArrayList<Integer> fieldorder =
          (ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER);
      final Integer val = Integer.valueOf((NUMBERBOUNDRARY * parameter) + size);
      fieldorder.add(val);
    } else if (DnComponents.isDirAttrField(parameterName)) {
      @SuppressWarnings("unchecked")
      final ArrayList<Integer> fieldorder =
          (ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER);
      final Integer val = Integer.valueOf((NUMBERBOUNDRARY * parameter) + size);
      fieldorder.add(val);
    }
    incrementFieldnumber(parameter);
  }

  /**
   * @param parameter Param
   * @param number Num
   */
  public void removeField(final String parameter, final int number) {
    removeField(getParameterNumber(parameter), number);
  }

  /**
   * Function that removes a field from the end entity profile.
   *
   * @param parameter is the field to remove.
   * @param number is the number of field.
   */
  public void removeField(final int parameter, final int number) {
    // Remove field and move all file ids above.
    final int size = getNumberOfField(parameter);
    if (size > 0) {
      for (int n = number; n < size - 1; n++) {
        setValue(parameter, n, getValue(parameter, n + 1));
        setRequired(parameter, n, isRequired(parameter, n + 1));
        setUse(parameter, n, getUse(parameter, n + 1));
        setModifyable(parameter, n, isModifyable(parameter, n + 1));
      }
      final String param = getParameter(parameter);
      // Remove last element from Subject DN order list.
      if (DnComponents.isDnProfileField(param)) {
        @SuppressWarnings("unchecked")
        final ArrayList<Integer> fieldorder =
            (ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER);
        final int value = (NUMBERBOUNDRARY * parameter) + size - 1;
        fieldorder.remove(Integer.valueOf(value));
      }
      // Remove last element from Subject AltName order list.
      if (DnComponents.isAltNameField(param)) {
        @SuppressWarnings("unchecked")
        final ArrayList<Integer> fieldorder =
            (ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER);
        final int value = (NUMBERBOUNDRARY * parameter) + size - 1; // number;
        fieldorder.remove(Integer.valueOf(value));
      }
      // Remove last element from Subject DirAttr order list.
      if (DnComponents.isDirAttrField(param)) {
        @SuppressWarnings("unchecked")
        final ArrayList<Integer> fieldorder =
            (ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER);
        final int value = (NUMBERBOUNDRARY * parameter) + size - 1; // number;
        fieldorder.remove(Integer.valueOf(value));
      }
      // Remove last element of the type from hashmap
      data.remove(
          Integer.valueOf(
              FIELDBOUNDRARY_VALUE
                  + (NUMBERBOUNDRARY * (size - 1))
                  + parameter));
      data.remove(
          Integer.valueOf(
              FIELDBOUNDRARY_USE + (NUMBERBOUNDRARY * (size - 1)) + parameter));
      data.remove(
          Integer.valueOf(
              FIELDBOUNDRARY_ISREQUIRED
                  + (NUMBERBOUNDRARY * (size - 1))
                  + parameter));
      data.remove(
          Integer.valueOf(
              FIELDBOUNDRARY_MODIFYABLE
                  + (NUMBERBOUNDRARY * (size - 1))
                  + parameter));
      decrementFieldnumber(parameter);
    }
  }

  /**
   * @param parameter the name of a field from profilemappings.properties, see
   *     DnComponents
   * @return the number of one kind of field in the profile, or 0 if it does not
   *     exist.
   * @see DnComponents
   */
  public int getNumberOfField(final String parameter) {
    final int num = getParameterNumber(parameter);
    if (num != -1) {
      return getNumberOfField(num);
    } else {
      return 0;
    }
  }
  /**
   * @param parameter the number of a field from profilemappings.properties
   * @return the number of one kind of field in the profile.
   */
  public int getNumberOfField(final int parameter) {
    final ArrayList<Integer> arr = checkAndUpgradeWithNewFields(parameter);
    return arr.get(parameter).intValue();
  }

  private ArrayList<Integer> checkAndUpgradeWithNewFields(final int parameter) {
    @SuppressWarnings("unchecked")
    final ArrayList<Integer> arr = (ArrayList<Integer>) data.get(NUMBERARRAY);
    // This is an automatic upgrade function, if we have dynamically added new
    // fields
    if (parameter >= arr.size()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            INTRES.getLocalizedMessage(
                "ra.eeprofileaddfield", Integer.valueOf(parameter)));
      }
      for (int i = arr.size(); i <= parameter; i++) {
        arr.add(Integer.valueOf(0));
      }
      data.put(NUMBERARRAY, arr);
    }
    return arr;
  }

  /**
   * @param parameter param
   * @param number num
   * @param value val
   */
  public void setValue(
      final int parameter, final int number, final String value) {
    if (value != null) {
      data.put(
          Integer.valueOf(
              FIELDBOUNDRARY_VALUE + (NUMBERBOUNDRARY * number) + parameter),
          value.trim());
    } else {
      data.put(
          Integer.valueOf(
              FIELDBOUNDRARY_VALUE + (NUMBERBOUNDRARY * number) + parameter),
          "");
    }
  }

  /**
   * @param parameter param
   * @param number num
   * @param value val
   */
  public void setValue(
      final String parameter, final int number, final String value) {
    setValue(getParameterNumber(parameter), number, value);
  }

  /**
   * @param parameter param
   * @param number num
   * @param use bool
   */
  public void setUse(final int parameter, final int number, final boolean use) {
    data.put(
        Integer.valueOf(
            FIELDBOUNDRARY_USE + (NUMBERBOUNDRARY * number) + parameter),
        Boolean.valueOf(use));
  }
  /**
   * @param parameter param
   * @param number num
   * @param use bool
   */
  public void setUse(
      final String parameter, final int number, final boolean use) {
    setUse(getParameterNumber(parameter), number, use);
  }
  /**
   * @param parameter param
   * @param number num
   * @param isrequired bool
   */
  public void setRequired(
      final int parameter, final int number, final boolean isrequired) {
    data.put(
        Integer.valueOf(
            FIELDBOUNDRARY_ISREQUIRED + (NUMBERBOUNDRARY * number) + parameter),
        Boolean.valueOf(isrequired));
  }

  /**
   * @param parameter param
   * @param number num
   * @param isrequired bool
   */
  public void setRequired(
      final String parameter, final int number, final boolean isrequired) {
    setRequired(getParameterNumber(parameter), number, isrequired);
  }
  /**
   * @param parameter param
   * @param number num
   * @param changeable bool
   */
  public void setModifyable(
      final int parameter, final int number, final boolean changeable) {
    data.put(
        Integer.valueOf(
            FIELDBOUNDRARY_MODIFYABLE + (NUMBERBOUNDRARY * number) + parameter),
        Boolean.valueOf(changeable));
  }

  /**
   * @param parameter param
   * @param number num
   * @param changeable bool
   */
  public void setModifyable(
      final String parameter, final int number, final boolean changeable) {
    setModifyable(getParameterNumber(parameter), number, changeable);
  }
  /**
   * @param parameter param
   * @param number num
   * @param validation map
   */
  public void setValidation(
      final int parameter,
      final int number,
      final Map<String, Serializable> validation) {
    Integer paramNum =
        Integer.valueOf(
            FIELDBOUNDRARY_VALIDATION + (NUMBERBOUNDRARY * number) + parameter);
    if (validation != null) {
      data.put(paramNum, new LinkedHashMap<>(validation));
    } else {
      data.remove(paramNum);
    }
  }

  /**
   * @param parameter param
   * @param number num
   * @param validation map
   */
  public void setValidation(
      final String parameter,
      final int number,
      final LinkedHashMap<String, Serializable> validation) {
    setValidation(getParameterNumber(parameter), number, validation);
  }

  /**
   * @return bool
   */
  public boolean isPasswordPreDefined() {
    return getPredefinedPassword() != null
        && !getPredefinedPassword().trim().equals("");
  }

  /**
   * @return pass
   */
  public String getPredefinedPassword() {
    return getValue(EndEntityProfile.PASSWORD, 0);
  }

  /**
   * @param parameter param
   * @param number num
   * @return value
   */
  public String getValue(final int parameter, final int number) {
    return getValueDefaultEmpty(
        Integer.valueOf(
            FIELDBOUNDRARY_VALUE + (NUMBERBOUNDRARY * number) + parameter));
  }

  /**
   * Semi-internal method to get a default value, or list of allowed values.
   *
   * <p><b>Note:</b> Consider calling the appropriate getters instead of this
   * method. For example <code>getAvailableCertificateProfileIds()</code>
   * instead of calling <code>getValue(AVAILCERTPROFILES,0)</code>
   *
   * @param parameter param
   * @param number number
   * @return value
   */
  public String getValue(final String parameter, final int number) {
    return getValue(getParameterNumber(parameter), number);
  }

  /**
   * @param parameter param
   * @param number num
   * @return bool
   */
  public boolean getUse(final int parameter, final int number) {
    return getValueDefaultFalse(
        Integer.valueOf(
            FIELDBOUNDRARY_USE + (NUMBERBOUNDRARY * number) + parameter));
  }

  /**
   * Semi-internal method to get the "use" (enabled or disabled) state of a
   * parameter.
   *
   * <p><b>Note:</b> Consider calling the appropriate getters instead of this
   * method. For example <code>getCustomSerialNumberUsed()</code> instead of
   * calling <code>getUse(CERTSERIALNR, 0)</code>
   *
   * @param parameter param
   * @param number number
   * @return bool
   */
  public boolean getUse(final String parameter, final int number) {
    return getUse(getParameterNumber(parameter), number);
  }

  /**
   * @param parameter param
   * @param number num
   * @return bool
   */
  public boolean isRequired(final int parameter, final int number) {
    return getValueDefaultFalse(
        Integer.valueOf(
            FIELDBOUNDRARY_ISREQUIRED
                + (NUMBERBOUNDRARY * number)
                + parameter));
  }

  /**
   * Semi-internal method to get the "is required" state of a parameter.
   *
   * <p><b>Note:</b> Consider calling the appropriate getters instead of this
   * method. For example <code>getEmailDomainRequired()</code> instead of
   * calling <code>isRequired(EMAIL, 0)</code>
   *
   * @param parameter param
   * @param number number
   * @return bool
   */
  public boolean isRequired(final String parameter, final int number) {
    return isRequired(getParameterNumber(parameter), number);
  }

  /**
   * @param parameter param
   * @param number num
   * @return bool
   */
  public boolean isModifyable(final int parameter, final int number) {
    return getValueDefaultFalse(
        Integer.valueOf(
            FIELDBOUNDRARY_MODIFYABLE
                + (NUMBERBOUNDRARY * number)
                + parameter));
  }

  /**
   * Semi-internal method to get the "is modifiable" state of a parameter.
   *
   * <p><b>Note:</b> Consider calling the appropriate getters instead of this
   * method. For example <code>getEmailDomainModifiable()</code> instead of
   * calling <code>isModifyable(EMAIL, 0)</code>
   *
   * @param parameter param
   * @param number number
   * @return bool
   */
  public boolean isModifyable(final String parameter, final int number) {
    return isModifyable(getParameterNumber(parameter), number);
  }

  /**
   * @param parameter param
   * @param number num
   * @return map
   */
  @SuppressWarnings("unchecked")
  public LinkedHashMap<String, Serializable> getValidation(
      final int parameter, final int number) {
    return (LinkedHashMap<String, Serializable>)
        data.get(
            Integer.valueOf(
                FIELDBOUNDRARY_VALIDATION
                    + (NUMBERBOUNDRARY * number)
                    + parameter));
  }

  /**
   * @param parameter param
   * @param number num
   * @return map
   */
  public LinkedHashMap<String, Serializable> getValidation(
      final String parameter, final int number) {
    return getValidation(getParameterNumber(parameter), number);
  }
  /**
   * @return length
   */
  @SuppressWarnings("unchecked")
  public int getSubjectDNFieldOrderLength() {
    return ((ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER)).size();
  }
  /**
   * @return length
   */
  @SuppressWarnings("unchecked")
  public int getSubjectAltNameFieldOrderLength() {
    return ((ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER)).size();
  }

  /**
   * @return length
   */
  @SuppressWarnings("unchecked")
  public int getSubjectDirAttrFieldOrderLength() {
    return ((ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER)).size();
  }

  /**
   * Returns the number of Subject DN, SAN or Subject Directory Attributes
   * fields in this profile.
   *
   * @param dnType DNFieldExtractor.TYPE_*
   * @return Number of fields for the given field type
   */
  public int getFieldOrderLengthForDnType(final int dnType) {
    switch (dnType) {
      case DNFieldExtractor.TYPE_SUBJECTDN:
        return getSubjectDNFieldOrderLength();
      case DNFieldExtractor.TYPE_SUBJECTALTNAME:
        return getSubjectAltNameFieldOrderLength();
      case DNFieldExtractor.TYPE_SUBJECTDIRATTR:
        return getSubjectDirAttrFieldOrderLength();
      default:
        throw new IllegalArgumentException("Invalid DN type");
    }
  }

  /**
   * @return two int : the first is the DN field which is a constant in DN field
   *     extractor, the second is in which order the attribute is, 0 is first OU
   *     and 1 can mean second OU (if OU is specified in the first value).
   * @param index index
   */
  public int[] getSubjectDNFieldsInOrder(final int index) {
    final int[] returnval = new int[2];
    @SuppressWarnings("unchecked")
    final ArrayList<Integer> fieldorder =
        (ArrayList<Integer>) data.get(SUBJECTDNFIELDORDER);
    final int i = fieldorder.get(index).intValue();
    returnval[NUMBER] = i % NUMBERBOUNDRARY;
    returnval[FIELDTYPE] = i / NUMBERBOUNDRARY;
    return returnval;
  }

  /**
   * @param index index
   * @return fields
   */
  public int[] getSubjectAltNameFieldsInOrder(final int index) {
    int[] returnval = new int[2];
    @SuppressWarnings("unchecked")
    final ArrayList<Integer> fieldorder =
        (ArrayList<Integer>) data.get(SUBJECTALTNAMEFIELDORDER);
    final int i = fieldorder.get(index).intValue();
    returnval[NUMBER] = i % NUMBERBOUNDRARY;
    returnval[FIELDTYPE] = i / NUMBERBOUNDRARY;
    return returnval;
  }

  /**
   * @param index iundex
   * @return fields
   */
  public int[] getSubjectDirAttrFieldsInOrder(final int index) {
    final int[] returnval = new int[2];
    @SuppressWarnings("unchecked")
    final ArrayList<Integer> fieldorder =
        (ArrayList<Integer>) data.get(SUBJECTDIRATTRFIELDORDER);
    final int i = fieldorder.get(index).intValue();
    returnval[NUMBER] = i % NUMBERBOUNDRARY;
    returnval[FIELDTYPE] = i / NUMBERBOUNDRARY;
    return returnval;
  }

  /**
   * Returns the Subject DN, SAN or Subject Directory Attributes field of the
   * given index in the profile.
   *
   * @param dnType DNFieldExtractor.TYPE_*
   * @param index Zero based index of field, up to and including
   *     getFieldOrderLengthForDnType(dnType)-1.
   * @return Number of fields for the given field type
   */
  public int[] getFieldsInOrderForDnType(final int dnType, final int index) {
    switch (dnType) {
      case DNFieldExtractor.TYPE_SUBJECTDN:
        return getSubjectDNFieldsInOrder(index);
      case DNFieldExtractor.TYPE_SUBJECTALTNAME:
        return getSubjectAltNameFieldsInOrder(index);
      case DNFieldExtractor.TYPE_SUBJECTDIRATTR:
        return getSubjectDirAttrFieldsInOrder(index);
      default:
        throw new IllegalArgumentException("Invalid DN type");
    }
  }

  /**
   * Gets a Collection of available CA Ids (as Integers). Use
   * String.valueOf(caidstring) to get the int value of the CA id.
   *
   * @return a Collection of CA Ids (never null).
   */
  public List<Integer> getAvailableCAs() {
    final ArrayList<Integer> ids = new ArrayList<>();
    final String idsAsstring = getValue(AVAILCAS, 0);
    if (!StringUtils.isBlank(idsAsstring)) {
      for (final String idString : idsAsstring.split(SPLITCHAR)) {
        ids.add(Integer.parseInt(idString));
      }
    }
    return ids;
  }

  /**
   * Like {@link #getAvailableCAs}, but returns the Ids as strings.
   *
   * @return IDs
   */
  public Collection<String> getAvailableCAsAsStrings() {
    final ArrayList<String> availablecaids = new ArrayList<>();
    availablecaids.addAll(
        Arrays.asList(getValue(AVAILCAS, 0).split(SPLITCHAR)));
    return availablecaids;
  }

  /**
   * Sets available CA ids. These are stored as a ; separated string in the end
   * entity profile
   *
   * @param ids Collection of CA ids
   */
  public void setAvailableCAs(final Collection<Integer> ids) {
    StringBuilder builder = new StringBuilder();
    for (Integer id : ids) {
      if (builder.length() == 0) {
        builder.append(id);
      } else {
        builder.append(';').append(id);
      }
    }
    setValue(AVAILCAS, 0, builder.toString());
  }

  /**
   * Sets available CA ids. These are stored as a ; separated string in the end
   * entity profile
   *
   * @param ids Collection of CA ids
   * @throws NumberFormatException on format error
   */
  public void setAvailableCAsIDsAsStrings(final Collection<String> ids)
      throws NumberFormatException {
    StringBuilder builder = new StringBuilder();
    for (String id : ids) {
      Integer.parseInt(id); // Test if it's an integer!
      if (builder.length() == 0) {
        builder.append(id);
      } else {
        builder.append(';').append(id);
      }
    }
    setValue(AVAILCAS, 0, builder.toString());
  }

  /**
   * Gets a Collection of available certificate profile ids Use
   * Integer.valueOf(idstring) to get the int value.
   *
   * @return a Collection of ids
   */
  public List<Integer> getAvailableCertificateProfileIds() {
    final ArrayList<Integer> profiles = new ArrayList<>();
    final String value = getValue(AVAILCERTPROFILES, 0);
    if (value != null) {
      final String[] arr = value.split(SPLITCHAR);
      for (final String element : arr) {
        profiles.add(Integer.parseInt(element));
      }
    }
    return profiles;
  }

  /**
   * Like {@link #getAvailableCertificateProfileIds}, but returns the Ids as
   * strings.
   *
   * @return IDs
   */
  public Collection<String> getAvailableCertificateProfileIdsAsStrings() {
    final ArrayList<String> profiles = new ArrayList<>();
    final String list = getValue(AVAILCERTPROFILES, 0);
    if (list != null) {
      profiles.addAll(Arrays.asList(list.split(SPLITCHAR)));
    }
    return profiles;
  }

  /**
   * Sets available certificate profile ids. These are stored as a ; separated
   * string in the end entity profile
   *
   * @param ids Collection of certificate profile ids
   */
  public void setAvailableCertificateProfileIds(final Collection<Integer> ids) {
    StringBuilder builder = new StringBuilder();
    for (Integer id : ids) {
      if (builder.length() == 0) {
        builder.append(id);
      } else {
        builder.append(';').append(id);
      }
    }
    setValue(AVAILCERTPROFILES, 0, builder.toString());
  }

  /**
   * @return ID
   */
  public int getDefaultCA() {
    int ret = -1;
    final String str = getValue(DEFAULTCA, 0);
    if (str != null && !StringUtils.isEmpty(str)) {
      ret = Integer.valueOf(str);
      if (ret == CAConstants.ALLCAS) {
        return -1;
      }
    }
    return ret;
  }

  /**
   * @param caId ID
   */
  public void setDefaultCA(final int caId) {
    // Might get called with caId=1 (CAConstants.ALLCAS) if the CA Id is
    // missing, and the code tries to take the first available CA (which can be
    // "All CAs" or 1)
    setValue(
        EndEntityProfile.DEFAULTCA,
        0,
        String.valueOf(caId == CAConstants.ALLCAS ? -1 : caId));
  }

  /**
   * @return the certificate profileId configured as default certificate
   *     profile, or -1 if no default certificate profile exists
   */
  public int getDefaultCertificateProfile() {
    int ret = -1;
    final String str = getValue(DEFAULTCERTPROFILE, 0);
    if (StringUtils.isNotEmpty(str)) {
      ret = Integer.parseInt(str);
    }
    return ret;
  }

  /**
   * @param certificateProfileId ID
   */
  public void setDefaultCertificateProfile(final int certificateProfileId) {
    setValue(
        EndEntityProfile.DEFAULTCERTPROFILE,
        0,
        String.valueOf(certificateProfileId));
  }

  /**
   * Returns the default token type, such as "User generated" or "PCKS#12".
   *
   * @return One of the SecConst.TOKEN_SOFT_* constants
   */
  public int getDefaultTokenType() {
    int ret = SecConst.TOKEN_SOFT_BROWSERGEN;
    final String str = getValue(EndEntityProfile.DEFKEYSTORE, 0);
    if (StringUtils.isNotEmpty(str)) {
      ret = Integer.parseInt(str);
    }
    return ret;
  }

  /**
   * @return types
   */
  public List<Integer> getAvailableTokenTypes() {
    final List<Integer> ret = new ArrayList<>();
    final String str = getValue(EndEntityProfile.AVAILKEYSTORE, 0);
    if (StringUtils.isNotEmpty(str)) {
      for (final String elem : str.split(SPLITCHAR)) {
        ret.add(Integer.parseInt(elem));
      }
    }
    return ret;
  }

  /**
   * @return User
   */
  public String getUsernameDefault() {
    return getValue(USERNAME, 0);
  }

  /**
   * @return bool
   */
  public boolean isUsernameRequired() {
    return isRequired(USERNAME, 0);
  }

  /**
   * @return bool
   */
  public boolean isAutoGeneratedUsername() {
    return !isModifyable(USERNAME, 0);
  }

  /**
   * @return bool
   */
  public boolean isPasswordRequired() {
    return isRequired(PASSWORD, 0);
  }

  /**
   * @return bool
   */
  public boolean isPasswordModifiable() {
    return isModifyable(PASSWORD, 0);
  }

  /**
   * @return bool
   */
  public boolean useAutoGeneratedPasswd() {
    return !getUse(PASSWORD, 0);
  }

  /**
   * @return type
   */
  public String getAutoGeneratedPasswdType() {
    String type = getValue(AUTOGENPASSWORDTYPE, 0);
    if (type == null || "".equals(type)) {
      type = PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
    }
    return type;
  }

  /**
   * @return length
   */
  public int getAutoGeneratedPasswdLength() {
    final String length = getValue(AUTOGENPASSWORDLENGTH, 0);
    int pwdlen = 8;
    if (!StringUtils.isEmpty(length)) {
      try {
        pwdlen = Integer.parseInt(length);
      } catch (NumberFormatException e) {
        LOG.info(
            "NumberFormatException parsing AUTOGENPASSWORDLENGTH, using"
                + " default value of 8: ",
            e);
      }
    }
    return pwdlen;
  }

  /**
   * @return pass
   */
  public String getAutoGeneratedPasswd() {
    final int pwdlen = getAutoGeneratedPasswdLength();
    return PasswordGeneratorFactory.getInstance(getAutoGeneratedPasswdType())
        .getNewPassword(pwdlen, pwdlen);
  }

  /**
   * @return strength in bits = log2(possible chars) * number of chars rounded
   *     down
   */
  public int getAutoGenPwdStrength() {
    final int numerOfDifferentChars =
        PasswordGeneratorFactory.getInstance(getAutoGeneratedPasswdType())
            .getNumerOfDifferentChars();
    return getPasswordStrength(
        numerOfDifferentChars, getAutoGeneratedPasswdLength());
  }

  /**
   * @param numerOfDifferentChars num
   * @param passwordLength Length
   * @return strength in bits = log2(possible chars) * number of chars rounded
   *     down
   */
  private int getPasswordStrength(
      final int numerOfDifferentChars, final int passwordLength) {
    return (int)
        (Math.floor(Math.log(numerOfDifferentChars) / Math.log(2))
            * passwordLength);
  }

  /** @return the minimum strength that a password is allowed to have in bits */
  public int getMinPwdStrength() {
    if (!getUse(MINPWDSTRENGTH, 0)) {
      return 0;
    }
    return Integer.parseInt(getValue(MINPWDSTRENGTH, 0));
  }

  /**
   * Set the minimum strength that a password is allowed to have in bits.
   *
   * @param minPwdStrength strength
   */
  public void setMinPwdStrength(final int minPwdStrength) {
    this.setUse(MINPWDSTRENGTH, 0, true);
    this.setValue(MINPWDSTRENGTH, 0, String.valueOf(minPwdStrength));
  }

  /**
   * @return String value with types from org.ejbca.util.passgen, example
   *     org.ejbca.util.passgen.DigitPasswordGenerator.NAME (PWGEN_DIGIT)
   */
  public static Collection<String> getAvailablePasswordTypes() {
    return PasswordGeneratorFactory.getAvailablePasswordTypes();
  }

  /**
   * @return bool
   */
  public boolean isClearTextPasswordUsed() {
    return getUse(CLEARTEXTPASSWORD, 0);
  }

  /**
   * @return bool
   */
  public boolean isClearTextPasswordDefault() {
    return TRUE.equals(getValue(CLEARTEXTPASSWORD, 0));
  }

  /**
   * @return bool
   */
  public boolean isClearTextPasswordRequired() {
    return isRequired(CLEARTEXTPASSWORD, 0);
  }

  /**
   * @return bool
   */
  public boolean getUseEmail() {
    return getUse(EMAIL, 0);
  }

  /**
   * @return email
   */
  public String getEmailDomain() {
    return getValue(EMAIL, 0);
  }

  /**
   * @return bool
   */
  public boolean getEmailDomainModifiable() {
    return isModifyable(EMAIL, 0);
  }

  /**
   * @return bool
   */
  public boolean getEmailDomainRequired() {
    return isRequired(EMAIL, 0);
  }

  /**
   * @return num
   */
  public int getAllowedRequests() {
    if (!getUse(ALLOWEDREQUESTS, 0)) {
      return -1;
    } else if (data.get(ALLOWEDREQUESTS) == null) {
      return 1;
    }
    return ((Integer) data.get(ALLOWEDREQUESTS)).intValue();
  }

  /**
   * @return bool
   */
  public boolean getMaxFailedLoginsUsed() {
    return getUse(MAXFAILEDLOGINS, 0);
  }

  /**
   * @return bool
   */
  public boolean getMaxFailedLoginsModifiable() {
    return isModifyable(MAXFAILEDLOGINS, 0);
  }

  /**
   * @return num
   */
  public int getMaxFailedLogins() {
    if (!getUse(MAXFAILEDLOGINS, 0) || data.get(MAXFAILEDLOGINS) == null) {
      return -1;
    }
    return ((Integer) data.get(MAXFAILEDLOGINS)).intValue();
  }

  /**
   * @return bool
   */
  public boolean getIssuanceRevocationReasonUsed() {
    return getUse(ISSUANCEREVOCATIONREASON, 0);
  }

  /**
   * @return bool
   */
  public boolean getIssuanceRevocationReasonModifiable() {
    return isModifyable(ISSUANCEREVOCATIONREASON, 0);
  }

  /**
   * @return reason
   */
  public RevocationReasons getIssuanceRevocationReason() {
    final String value = getValue(ISSUANCEREVOCATIONREASON, 0);
    if (value != null) {
      return RevocationReasons.getFromDatabaseValue(Integer.parseInt(value));
    } else {
      return RevocationReasons.NOT_REVOKED;
    }
  }

  /**
   * @return bool
   */
  public boolean getCustomSerialNumberUsed() {
    return getUse(CERTSERIALNR, 0);
  }

  /**
   * @return bool
   */
  public boolean getValidityStartTimeUsed() {
    return getUse(STARTTIME, 0);
  }

  /**
   * @return bool
   */
  public boolean getValidityStartTimeModifiable() {
    return isModifyable(STARTTIME, 0);
  }

  /**
   * Optional validity start time in absolute "yyyy-MM-dd HH:mm" or relative
   * "days:hours:minutes" format.
   *
   * @return Start time. Never null, but may be empty.
   */
  public String getValidityStartTime() {
    return getValue(STARTTIME, 0);
  }

  /**
   * @return bool
   */
  public boolean getValidityEndTimeUsed() {
    return getUse(ENDTIME, 0);
  }

  /**
   * @return bool
   */
  public boolean getValidityEndTimeModifiable() {
    return isModifyable(ENDTIME, 0);
  }

  /**
   * Optional validity end time in absolute "yyyy-MM-dd HH:mm" or relative
   * "days:hours:minutes" format.
   *
   * @return End time. Never null, but may be empty.
   */
  public String getValidityEndTime() {
    return getValue(ENDTIME, 0);
  }

  /**
   * @return bool
   */
  public boolean getCardNumberUsed() {
    return getUse(CARDNUMBER, 0);
  }

  /**
   * @return bool
   */
  public boolean getCardNumberRequired() {
    return isRequired(CARDNUMBER, 0);
  }

  /**
   * @return bool
   */
  public boolean getKeyRecoverableUsed() {
    return getUse(KEYRECOVERABLE, 0);
  }

  /**
   * @return bool
   */
  public boolean getKeyRecoverableDefault() {
    return TRUE.equals(getValue(KEYRECOVERABLE, 0));
  }

  /**
   * @return bool
   */
  public boolean getKeyRecoverableRequired() {
    return isRequired(KEYRECOVERABLE, 0);
  }

  /**
   * @return bool
   */
  public boolean getSendNotificationUsed() {
    return getUse(SENDNOTIFICATION, 0);
  }

  /**
   * @return bool
   */
  public boolean getSendNotificationDefault() {
    return TRUE.equals(getValue(SENDNOTIFICATION, 0));
  }

  /**
   * @return bool
   */
  public boolean getSendNotificationRequired() {
    return isRequired(SENDNOTIFICATION, 0);
  }

  /**
   * @return notifs
   */
  public List<UserNotification> getUserNotifications() {
    @SuppressWarnings("unchecked")
    List<UserNotification> l =
        (List<UserNotification>) data.get(USERNOTIFICATIONS);
    if (l == null) {
      l = new ArrayList<>();
    }
    return l;
  }

  /**
   * @param notification notif
   */
  @SuppressWarnings("unchecked")
  public void addUserNotification(final UserNotification notification) {
    if (data.get(USERNOTIFICATIONS) == null) {
      setUserNotifications(new ArrayList<UserNotification>(0));
    }
    ((List<UserNotification>) data.get(USERNOTIFICATIONS)).add(notification);
  }

  /**
   * @param notifications notifs
   */
  public void setUserNotifications(final List<UserNotification> notifications) {
    if (notifications == null) {
      data.put(USERNOTIFICATIONS, new ArrayList<UserNotification>(0));
    } else {
      data.put(USERNOTIFICATIONS, notifications);
    }
  }
/**
 * @param notification notif
 */
  @SuppressWarnings("unchecked")
  public void removeUserNotification(final UserNotification notification) {
    if (data.get(USERNOTIFICATIONS) != null) {
      ((List<UserNotification>) data.get(USERNOTIFICATIONS))
          .remove(notification);
    }
  }

  /** @return true if the key-recovered certificate should be reused. */
  public boolean getReUseKeyRecoveredCertificate() {
    return getValueDefaultFalse(REUSECERTIFICATE);
  }

  /**
   * @param reuse bool
   */
  public void setReUseKeyRecoveredCertificate(final boolean reuse) {
    data.put(REUSECERTIFICATE, Boolean.valueOf(reuse));
  }

  /**
   * @return true if the profile checks should be reversed or not. Default is
   *     false.
   */
  public boolean getReverseFieldChecks() {
    return getValueDefaultFalse(REVERSEFFIELDCHECKS);
  }

  /**
   * @param reverse bool
   */
  public void setReverseFieldChecks(final boolean reverse) {
    data.put(REVERSEFFIELDCHECKS, Boolean.valueOf(reverse));
  }

  /**
   * @return true if profile DN should be merged to webservices. Default is
   *     false.
   */
  public boolean getAllowMergeDnWebServices() {
    return getValueDefaultFalse(ALLOW_MERGEDN_WEBSERVICES);
  }

  /**
   * @param merge bool
   */
  public void setAllowMergeDnWebServices(final boolean merge) {
    data.put(ALLOW_MERGEDN_WEBSERVICES, Boolean.valueOf(merge));
  }

  /** @return true if printing of userdata should be done. default is false. */
  public boolean getUsePrinting() {
    return getValueDefaultFalse(PRINTINGUSE);
  }

  /**
   * @param use bool
   */
  public void setUsePrinting(final boolean use) {
    data.put(PRINTINGUSE, Boolean.valueOf(use));
  }

  /** @return true if printing of userdata should be done. default is false. */
  public boolean getPrintingDefault() {
    return getValueDefaultFalse(PRINTINGDEFAULT);
  }

  /**
   * @param printDefault bool
   */
  public void setPrintingDefault(final boolean printDefault) {
    data.put(PRINTINGDEFAULT, Boolean.valueOf(printDefault));
  }

  /** @return true if printing of userdata should be done. default is false. */
  public boolean getPrintingRequired() {
    return getValueDefaultFalse(PRINTINGREQUIRED);
  }

  /**
   * @param printRequired bool
   */
  public void setPrintingRequired(final boolean printRequired) {
    data.put(PRINTINGREQUIRED, Boolean.valueOf(printRequired));
  }

  /** @return the number of copies that should be printed. Default is 1. */
  public int getPrintedCopies() {
    if (data.get(PRINTINGCOPIES) == null) {
      return 1;
    }
    return ((Integer) data.get(PRINTINGCOPIES)).intValue();
  }

  /**
   * @param copies copies
   */
  public void setPrintedCopies(final int copies) {
    data.put(PRINTINGCOPIES, Integer.valueOf(copies));
  }

  /** @return the name of the printer that should be used */
  public String getPrinterName() {
    return getValueDefaultEmpty(PRINTINGPRINTERNAME);
  }
  /** @param printerName name */
  public void setPrinterName(final String printerName) {
    data.put(PRINTINGPRINTERNAME, printerName);
  }

  /** @return filename of the uploaded */
  public String getPrinterSVGFileName() {
    return getValueDefaultEmpty(PRINTINGSVGFILENAME);
  }

  /**
   * @param printerSVGFileName name
   */
  public void setPrinterSVGFileName(final String printerSVGFileName) {
    data.put(PRINTINGSVGFILENAME, printerSVGFileName);
  }

  /**
   * @return the data of the SVG file, if no content have been uploaded null is
   *     returned
   */
  public String getPrinterSVGData() {
    final String value = (String) data.get(PRINTINGSVGDATA);
    if (StringUtils.isBlank(value)) {
      return null;
    }
    return new String(Base64Util.decode(
            value.getBytes(StandardCharsets.US_ASCII)));
  }

  /**
   * @param sVGData data
   */
  public void setPrinterSVGData(final String sVGData) {
    data.put(PRINTINGSVGDATA, new String(
            Base64Util.encode(sVGData.getBytes())));
  }

  /**
   * @param key key
   * @return the boolean value or false if null. Note: Some keys need
   *     translating to integer first (e.g. those with use/value/required flags)
   */
  private boolean getValueDefaultFalse(final Object key) {
    if (data.get(key) == null) {
      return false;
    }
    return ((Boolean) data.get(key)).booleanValue();
  }

  /**
   * @param key key
   * @return the boolean value or false if null. Note: Some keys need
   *     translating to integer first (e.g. those with use/value/required flags)
   */
  private String getValueDefaultEmpty(final Object key) {
    if (data.get(key) == null) {
      return "";
    }
    return (String) data.get(key);
  }

  /**
   * @param userdata data
   * @param clearpwd pwd
   * @throws EndEntityProfileValidationException fail
   */
  public void doesUserFulfillEndEntityProfile(
      final EndEntityInformation userdata, final boolean clearpwd)
      throws EndEntityProfileValidationException {
    String subjectdirattr = "";
    final ExtendedInformation ei = userdata.getExtendedInformation();
    if (ei != null) {
      subjectdirattr = ei.getSubjectDirectoryAttributes();
    }

    doesUserFulfillEndEntityProfile(
        userdata.getUsername(),
        userdata.getPassword(),
        userdata.getDN(),
        userdata.getSubjectAltName(),
        subjectdirattr,
        userdata.getEmail(),
        userdata.getCertificateProfileId(),
        clearpwd,
        userdata.getKeyRecoverable(),
        userdata.getSendNotification(),
        userdata.getTokenType(),
        userdata.getHardTokenIssuerId(),
        userdata.getCAId(),
        userdata.getExtendedInformation());
    // Checking if the cardnumber is required and set
    if (isRequired(CARDNUMBER, 0)) {
      if (userdata.getCardNumber() == null
          || userdata.getCardNumber().isEmpty()) {
        throw new EndEntityProfileValidationException("Cardnumber is not set");
      }
    }
  }

  /**
   * @param username User
 * @param password pwd
   * @param dn DN
   * @param subjectaltname Name
   * @param subjectdirattr Attrs
   * @param email Email
   * @param certificateprofileid ID
 * @param clearpwd clear
   * @param keyrecoverable Key
   * @param sendnotification Nitif
   * @param tokentype Type
   * @param hardwaretokenissuerid Issuer
   * @param caid CA
   * @param ei Info
   * @throws EndEntityProfileValidationException fail
   */
  public void doesUserFulfillEndEntityProfile(
      final String username,
      final String password,
      final String dn,
      final String subjectaltname,
      final String subjectdirattr,
      final String email,
      final int certificateprofileid,
      final boolean clearpwd,
      final boolean keyrecoverable,
      final boolean sendnotification,
      final int tokentype,
      final int hardwaretokenissuerid,
      final int caid,
      final ExtendedInformation ei)
      throws EndEntityProfileValidationException {
    if (useAutoGeneratedPasswd()) {
      // Checks related to the use of auto generated passwords
      if (password != null) {
        throw new EndEntityProfileValidationException(
            "When using autogenerated password, the provided password must be"
                + " null.");
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "getAutoGenPwdStrength="
                + getAutoGenPwdStrength()
                + " getMinPwdStrength="
                + getMinPwdStrength());
      }
      if (getUse(MINPWDSTRENGTH, 0)
          && (getAutoGenPwdStrength() < getMinPwdStrength())) {
        throw new EndEntityProfileValidationException(
            "Generated password is not strong enough ("
                + getAutoGenPwdStrength()
                + " bits in generated password < "
                + getMinPwdStrength()
                + " bits required by end entity profile).");
      }
    } else {
      // Checks related to the use of normal hashed passwords
      if (!isPasswordModifiable()) {
        if (!password.equals(getValue(PASSWORD, 0))) {
          throw new EndEntityProfileValidationException(
              "Password didn't match requirement of it's profile.");
        }
      } else if (isPasswordRequired()) {
        if (password == null || password.trim().equals("")) {
          throw new EndEntityProfileValidationException(
              "Password cannot be empty or null.");
        }
      }
      // Assume a-zA-Z0-9 + 22 other printable chars = 72 different chars. Null
      // password has 0 bits.
      final int passwordStrengthEstimate =
          getPasswordStrength(
              72, (password == null ? 0 : password.trim().length()));
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "passwordStrengthEstimate="
                + passwordStrengthEstimate
                + " getMinPwdStrength="
                + getMinPwdStrength());
      }
      if (getUse(EndEntityProfile.MINPWDSTRENGTH, 0)
          && (passwordStrengthEstimate < getMinPwdStrength())) {
        throw new EndEntityProfileValidationException(
            "Generated password is not strong enough (~"
                + passwordStrengthEstimate
                + " bits in specific password < "
                + getMinPwdStrength()
                + " bits required by end entity profile).");
      }
    }
    // Checks related to the use of clear text passwords
    if (!getUse(CLEARTEXTPASSWORD, 0) && clearpwd) {
      throw new EndEntityProfileValidationException(
          "Clearpassword (used in batch processing) cannot be used.");
    }
    if (isRequired(CLEARTEXTPASSWORD, 0)) {
      if (getValue(CLEARTEXTPASSWORD, 0).equals(TRUE) && !clearpwd) {
        throw new EndEntityProfileValidationException(
            "Clearpassword (used in batch processing) cannot be false.");
      }
      if (getValue(CLEARTEXTPASSWORD, 0).equals(FALSE) && clearpwd) {
        throw new EndEntityProfileValidationException(
            "Clearpassword (used in batch processing) cannot be true.");
      }
    }
    doesUserFulfillEndEntityProfileWithoutPassword(
        username,
        dn,
        subjectaltname,
        subjectdirattr,
        email,
        certificateprofileid,
        keyrecoverable,
        sendnotification,
        tokentype,
        hardwaretokenissuerid,
        caid,
        ei);
  }

  /**
   * @param username User
   * @param dn DN
   * @param subjectaltname Name
   * @param subjectdirattr Attrs
   * @param oemail Email
   * @param certificateprofileid ID
   * @param keyrecoverable Key
   * @param sendnotification Nitif
   * @param tokentype Type
   * @param hardwaretokenissuerid Issuer
   * @param caid CA
   * @param ei Info
   * @throws EndEntityProfileValidationException fail
   */
  public void doesUserFulfillEndEntityProfileWithoutPassword(
      final String username,
      final String dn,
      final String subjectaltname,
      final String subjectdirattr,
      final String oemail,
      final int certificateprofileid,
      final boolean keyrecoverable,
      final boolean sendnotification,
      final int tokentype,
      final int hardwaretokenissuerid,
      final int caid,
      final ExtendedInformation ei)
      throws EndEntityProfileValidationException {
    String email = oemail;
    if (LOG.isTraceEnabled()) {
      LOG.trace(">doesUserFulfillEndEntityProfileWithoutPassword()");
    }
    final DNFieldExtractor subjectdnfields =
        new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    if (subjectdnfields.isIllegal()) {
      throw new EndEntityProfileValidationException("Subject DN is illegal.");
    }
    final DNFieldExtractor subjectaltnames =
        new DNFieldExtractor(
            subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    if (subjectaltnames.isIllegal()) {
      throw new EndEntityProfileValidationException(
          "Subject alt names are illegal.");
    }
    final DNFieldExtractor subjectdirattrs =
        new DNFieldExtractor(
            subjectdirattr, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    if (subjectdirattrs.isIllegal()) {
      throw new EndEntityProfileValidationException(
          "Subject directory attributes are illegal.");
    }
    // Check that no other than supported dn fields exists in the subject dn.
    if (subjectdnfields.existsOther()) {
      throw new EndEntityProfileValidationException(
          "Unsupported Subject DN Field found in:" + dn);
    }
    if (subjectaltnames.existsOther()) {
      throw new EndEntityProfileValidationException(
          "Unsupported Subject Alternate Name Field found in:"
              + subjectaltname);
    }
    if (subjectdirattrs.existsOther()) {
      throw new EndEntityProfileValidationException(
          "Unsupported Subject Directory Attribute Field found in:"
              + subjectdirattr);
    }
    checkIfAllRequiredFieldsExists(
        subjectdnfields, subjectaltnames, subjectdirattrs, username, email);
    // Make sure that there are enough fields to cover all required in profile
    checkIfForIllegalNumberOfFields(
        subjectdnfields, subjectaltnames, subjectdirattrs);
    // Check that all fields pass the validators (e.g. regex), if any
    checkWithValidators(subjectdnfields, subjectaltnames);
    // Check contents of username
    checkIfDataFulfillProfile(USERNAME, 0, username, "Username", null);
    // Check Email address.
    if (email == null) {
      email = "";
    }
    checkIfDomainFulfillProfile(EMAIL, 0, email, "Email");
    // Make sure that every value has a corresponding field in the entity
    // profile
    checkIfFieldsMatch(subjectdnfields, DNFieldExtractor.TYPE_SUBJECTDN, email);
    checkIfFieldsMatch(
        subjectaltnames, DNFieldExtractor.TYPE_SUBJECTALTNAME, email);
    // Check contents of Subject Directory Attributes fields.
    final HashMap<Integer, Integer> subjectdirattrnumbers =
        subjectdirattrs.getNumberOfFields();
    final List<Integer> dirattrids =
        DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    for (final Integer dirattrid : dirattrids) {
      final int nof = subjectdirattrnumbers.get(dirattrid).intValue();
      for (int j = 0; j < nof; j++) {
        checkForIllegalChars(subjectdirattrs.getField(dirattrid.intValue(), j));
        switch (dirattrid.intValue()) {
          case DNFieldExtractor.COUNTRYOFCITIZENSHIP:
            checkIfISO3166FulfillProfile(
                DnComponents.COUNTRYOFCITIZENSHIP,
                j,
                subjectdirattrs.getField(dirattrid.intValue(), j),
                "COUNTRYOFCITIZENSHIP");
            break;
          case DNFieldExtractor.COUNTRYOFRESIDENCE:
            checkIfISO3166FulfillProfile(
                DnComponents.COUNTRYOFRESIDENCE,
                j,
                subjectdirattrs.getField(dirattrid.intValue(), j),
                "COUNTRYOFRESIDENCE");
            break;
          case DNFieldExtractor.DATEOFBIRTH:
            checkIfDateFulfillProfile(
                DnComponents.DATEOFBIRTH,
                j,
                subjectdirattrs.getField(dirattrid.intValue(), j),
                "DATEOFBIRTH");
            break;
          case DNFieldExtractor.GENDER:
            checkIfGenderFulfillProfile(
                DnComponents.GENDER,
                j,
                subjectdirattrs.getField(dirattrid.intValue(), j),
                "GENDER");
            break;
          default:
            checkIfDataFulfillProfile(
                DnComponents.dnIdToProfileName(dirattrid.intValue()),
                j,
                subjectdirattrs.getField(dirattrid.intValue(), j),
                DnComponents.getErrTextFromDnId(dirattrid.intValue()),
                email);
        }
      }
    }
    // Check for keyrecoverable flag.
    if (!getUse(KEYRECOVERABLE, 0) && keyrecoverable) {
      throw new EndEntityProfileValidationException(
          "Key Recoverable cannot be used.");
    }
    if (isRequired(KEYRECOVERABLE, 0)
        && getValue(KEYRECOVERABLE, 0).equals(TRUE)) {
      if (tokentype == SecConst.TOKEN_SOFT_BROWSERGEN) {
        throw new EndEntityProfileValidationException(
            "Key Recoverable is required, but can't be used for User Generated"
                + " Tokens.");
      }
      if (getValue(KEYRECOVERABLE, 0).equals(TRUE) && !keyrecoverable) {
        throw new EndEntityProfileValidationException(
            "Key Recoverable is required for this End Entity Profile.");
      }
      if (getValue(KEYRECOVERABLE, 0).equals(FALSE) && keyrecoverable) {
        throw new EndEntityProfileValidationException(
            "Key Recoverable cannot be set in current end entity profile.");
      }
    }
    // Check for send notification flag.
    if (!getUse(SENDNOTIFICATION, 0) && sendnotification) {
      throw new EndEntityProfileValidationException(
          "Email notification cannot be used.");
    }
    if (isRequired(SENDNOTIFICATION, 0)) {
      if (getValue(SENDNOTIFICATION, 0).equals(TRUE) && !sendnotification) {
        throw new EndEntityProfileValidationException(
            "Email notification is required.");
      }
      if (getValue(SENDNOTIFICATION, 0).equals(FALSE) && sendnotification) {
        throw new EndEntityProfileValidationException(
            "Email notification cannot be set in current end entity profile.");
      }
    }
    // Check if certificate profile is among available certificate profiles.
    String[] availablecertprofiles;
    try {
      availablecertprofiles = getValue(AVAILCERTPROFILES, 0).split(SPLITCHAR);
    } catch (Exception e) {
      throw new EndEntityProfileValidationException(
          "Error parsing end entity profile.");
    }
    if (availablecertprofiles == null) {
      throw new EndEntityProfileValidationException(
          "Error Available certificate profiles is null.");
    }
    final String certificateprofileidString =
        String.valueOf(certificateprofileid);
    boolean certprofilefound = false;
    for (final String currentAvailableCertProfile : availablecertprofiles) {
      if (certificateprofileidString.equals(currentAvailableCertProfile)) {
        certprofilefound = true;
        break;
      }
    }
    if (!certprofilefound) {
      throw new EndEntityProfileValidationException(
          "Couldn't find certificate profile ("
              + certificateprofileid
              + ") among available certificate profiles.");
    }
    // Check if tokentype is among available token types.
    String[] availablesofttokentypes;
    try {
      availablesofttokentypes = getValue(AVAILKEYSTORE, 0).split(SPLITCHAR);
    } catch (Exception e) {
      throw new EndEntityProfileValidationException(
          "Error parsing end entity profile.");
    }
    if (availablesofttokentypes == null) {
      throw new EndEntityProfileValidationException(
          "Error available  token types is null.");
    }
    final String tokenTypeString = String.valueOf(tokentype);
    boolean softtokentypefound = false;
    for (final String currentAvailableSoftTokenType : availablesofttokentypes) {
      if (tokenTypeString.equals(currentAvailableSoftTokenType)) {
        softtokentypefound = true;
        break;
      }
    }
    if (!softtokentypefound) {
      throw new EndEntityProfileValidationException(
          "Soft token type is not available in End Entity Profile.");
    }
    // If soft token check for hardwaretoken issuer id = 0.
    if (tokentype <= SecConst.TOKEN_SOFT) {
      if (hardwaretokenissuerid != 0) {
        throw new EndEntityProfileValidationException(
            "Soft tokens cannot have a hardware token issuer.");
      }
    }
    // If Hard token type check if hardware token issuer is among available
    // hardware token issuers.
    if (tokentype > SecConst.TOKEN_SOFT
        && getUse(AVAILTOKENISSUER, 0)) { // Hardware token.
      String[] availablehardtokenissuers;
      try {
        availablehardtokenissuers =
            getValue(AVAILTOKENISSUER, 0).split(SPLITCHAR);
      } catch (Exception e) {
        throw new EndEntityProfileValidationException(
            "Error parsing end entity profile.");
      }
      if (availablehardtokenissuers == null) {
        throw new EndEntityProfileValidationException(
            "Error available hard token issuers is null.");
      }
      final String hardwaretokenissueridString =
          String.valueOf(hardwaretokenissuerid);
      boolean hardtokentypefound = false;
      for (final String currentAvailableHardTokenIssuer
          : availablehardtokenissuers) {
        if (hardwaretokenissueridString.equals(
            currentAvailableHardTokenIssuer)) {
          hardtokentypefound = true;
          break;
        }
      }
      if (!hardtokentypefound) {
        throw new EndEntityProfileValidationException(
            "Couldn't find hard token issuers among available hard token"
                + " issuers.");
      }
    }
    // Check if ca id is among available ca ids.
    String[] availablecaids;
    try {
      availablecaids = getValue(AVAILCAS, 0).split(SPLITCHAR);
    } catch (Exception e) {
      throw new EndEntityProfileValidationException(
          "Error parsing end entity profile.");
    }
    if (availablecaids == null) {
      throw new EndEntityProfileValidationException(
          "Error End Entity Profiles Available CAs is null.");
    }
    boolean caidfound = false;
    for (final String currentAvailableCaId : availablecaids) {
      final int tmp = Integer.parseInt(currentAvailableCaId);
      if (tmp == caid || tmp == SecConst.ALLCAS) {
        caidfound = true;
        break;
      }
    }
    if (!caidfound) {
      throw new EndEntityProfileValidationException(
          "Couldn't find CA ("
              + caid
              + ") among End Entity Profiles Available CAs.");
    }
    // Check if time constraints are valid
    String startTime = null;
    String endTime = null;
    if (ei != null) {
      startTime = ei.getCustomData(EndEntityProfile.STARTTIME);
      LOG.debug("startTime is: " + startTime);
      endTime = ei.getCustomData(EndEntityProfile.ENDTIME);
      LOG.debug("endTime is: " + endTime);
    }
    final String[] datePatterns = {"yyyy-MM-dd HH:mm"};
    final Date now = new Date();
    Date startTimeDate = null;
    if (getUse(STARTTIME, 0) && startTime != null && !startTime.equals("")) {
      if (startTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) { // relative time
        final String[] startTimeArray = startTime.split(":");
        if (Long.parseLong(startTimeArray[0]) < 0
            || Long.parseLong(startTimeArray[1]) < 0
            || Long.parseLong(startTimeArray[2]) < 0) {
          throw new EndEntityProfileValidationException(
              "Cannot use negtive relative time.");
        }
        final long relative =
            (Long.parseLong(startTimeArray[0]) * 24 * 60
                    + Long.parseLong(startTimeArray[1]) * 60
                    + Long.parseLong(startTimeArray[2]))
                * 60
                * 1000;
        startTimeDate = new Date(now.getTime() + relative);
      } else {
        try {
          startTimeDate = DateUtils.parseDate(startTime, datePatterns);
        } catch (ParseException e) {
        }
      }
      if (startTimeDate == null) {
        // If we could not parse the date string, something was awfully wrong
        throw new EndEntityProfileValidationException(
            "Invalid start time: " + startTime);
      }
    }
    Date endTimeDate = null;
    if (getUse(ENDTIME, 0) && endTime != null && !endTime.equals("")) {
      if (endTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) { // relative time
        final String[] endTimeArray = endTime.split(":");
        if (Long.parseLong(endTimeArray[0]) < 0
            || Long.parseLong(endTimeArray[1]) < 0
            || Long.parseLong(endTimeArray[2]) < 0) {
          throw new EndEntityProfileValidationException(
              "Cannot use negtive relative time.");
        }
        final long relative =
            (Long.parseLong(endTimeArray[0]) * 24 * 60
                    + Long.parseLong(endTimeArray[1]) * 60
                    + Long.parseLong(endTimeArray[2]))
                * 60
                * 1000;
        // If we haven't set a startTime, use "now"
        final Date start = (startTimeDate == null) ? new Date() : startTimeDate;
        endTimeDate = new Date(start.getTime() + relative);
      } else {
        try {
          endTimeDate = DateUtils.parseDate(endTime, datePatterns);
        } catch (ParseException e) {
        }
      }
      if (endTimeDate == null) {
        // If we could not parse the date string, something was awfulyl wrong
        throw new EndEntityProfileValidationException(
            "Invalid end time: " + endTime);
      }
    }
    if ((startTimeDate != null) && (endTimeDate != null)) {
      if (getUse(STARTTIME, 0)
          && getUse(ENDTIME, 0)
          && !startTimeDate.before(endTimeDate)) {
        throw new EndEntityProfileValidationException(
            "Dates must be in right order. "
                + startTime
                + " "
                + endTime
                + " "
                + ValidityDateUtil.formatAsUTC(startTimeDate)
                + " "
                + ValidityDateUtil.formatAsUTC(endTimeDate));
      }
    }
    // Check number of allowed requests
    String allowedRequests = null;
    if (ei != null) {
      allowedRequests =
          ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
    }
    if ((allowedRequests != null) && !getUse(ALLOWEDREQUESTS, 0)) {
      throw new EndEntityProfileValidationException(
          "Allowed requests used, but not permitted by profile.");
    }
    // Check initial issuance revocation reason
    String issuanceRevReason = null;
    if (ei != null) {
      issuanceRevReason =
          ei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
    }
    if ((issuanceRevReason != null) && !getUse(ISSUANCEREVOCATIONREASON, 0)) {
      throw new EndEntityProfileValidationException(
          "Issuance revocation reason used, but not permitted by profile.");
    }
    if (getUse(ISSUANCEREVOCATIONREASON, 0)
        && !isModifyable(ISSUANCEREVOCATIONREASON, 0)) {
      final String value = getValue(ISSUANCEREVOCATIONREASON, 0);
      if (!StringUtils.equals(issuanceRevReason, value)) {
        throw new EndEntityProfileValidationException(
            "Issuance revocation reason '"
                + issuanceRevReason
                + "' does not match required value '"
                + value
                + "'.");
      }
    }
    // Check maximum number of failed logins
    if (getUse(MAXFAILEDLOGINS, 0) && !isModifyable(MAXFAILEDLOGINS, 0)) {
      // If we MUST have MAXFAILEDLOGINS, ei can not be null
      if ((ei == null)
          || !getValue(MAXFAILEDLOGINS, 0)
              .equals(Integer.toString(ei.getMaxLoginAttempts()))) {
        throw new EndEntityProfileValidationException(
            "Max failed logins is not modifyable.");
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<doesUserFulfillEndEntityProfileWithoutPassword()");
    }
  }

  /**
   * This function tries to match each field in the profile to a corresponding
   * field in the DN/AN/AD-fields. Can not be used for
   * DNFieldExtractor.TYPE_SUBJECTDIRATTR yet.
   *
   * @param fields fiewlds
   * @param type One of DNFieldExtractor.TYPE_SUBJECTDN,
   *     DNFieldExtractor.TYPE_SUBJECTALTNAME
   * @param email The end entity's email address
   * @throws EndEntityProfileValidationException if validation fails
   */
  private void checkIfFieldsMatch(
      final DNFieldExtractor fields, final int type, final String email)
      throws EndEntityProfileValidationException {
    final int requiredField = 2;
    final int nonModifiableField = 1;
    final int matchedField = -1;
    final List<Integer> dnids = DNFieldExtractor.getUseFields(type);
    // For each type of field
    for (int i = 0; i < dnids.size(); i++) {
      final int dnid = dnids.get(i).intValue();
      final int profileID = DnComponents.dnIdToProfileId(dnid);
      final int dnFieldExtractorID = DnComponents.profileIdToDnId(profileID);
      final int nof = fields.getNumberOfFields(dnFieldExtractorID);
      final int numberOfProfileFields = getNumberOfField(profileID);
      if (nof == 0 && numberOfProfileFields == 0) {
        continue; // Nothing to see here..
      }
      // Create array with all entries of that type
      final String[] subjectsToProcess = new String[nof];
      for (int j = 0; j < nof; j++) {
        String fieldValue = fields.getField(dnFieldExtractorID, j);
        // Only keep domain for comparison of RFC822NAME, DNEMAILADDRESS and UPN
        // fields
        if (DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid))
            || DnComponents.DNEMAILADDRESS.equals(
                DnComponents.dnIdToProfileName(dnid))
            || DnComponents.UPN.equals(DnComponents.dnIdToProfileName(dnid))) {
          // Don't split RFC822NAME addresses.
          if (!DnComponents.RFC822NAME.equals(
              DnComponents.dnIdToProfileName(dnid))) {
            if (!StringUtils.contains(fieldValue, '@')) {
              throw new EndEntityProfileValidationException(
                  "Field value DNEMAIL and UPN must contain an @ character: "
                      + fieldValue);
            }
            fieldValue = fieldValue.split("@")[1];
          }
        } else {
          // Check that postalAddress has #der_encoding_in_hex format, i.e. a
          // full der sequence in hex format
          if (DnComponents.POSTALADDRESS.equals(
              DnComponents.dnIdToProfileName(dnid))) {
            if (!StringUtils.startsWith(fieldValue, "#30")) {
              throw new EndEntityProfileValidationException(
                  DnComponents.dnIdToProfileName(dnid)
                      + " ("
                      + fieldValue
                      + ") does not seem to be in #der_encoding_in_hex format."
                      + " See \"End_Entity_Profiles.html\" for more"
                      + " information about the postalAddress (2.5.4.16)"
                      + " field.");
            }
          }
        }
        subjectsToProcess[j] = fieldValue;
      }
      //    Create array with profile values 3 = required and non-mod, 2 =
      // required, 1 = non-modifiable, 0 = neither
      final int[] profileCrossOffList = new int[numberOfProfileFields];
      for (int j = 0; j < getNumberOfField(profileID); j++) {
        profileCrossOffList[j] +=
            (isModifyable(profileID, j) ? 0 : nonModifiableField)
                + (isRequired(profileID, j) ? requiredField : 0);
      }

      final int max = 3;
      // Start by matching email strings
      if (DnComponents.RFC822NAME.equals(DnComponents.dnIdToProfileName(dnid))
          || DnComponents.DNEMAILADDRESS.equals(
              DnComponents.dnIdToProfileName(dnid))) {
        for (int k = max; k >= 0; k--) {
          //    For every value in profile
          for (int l = 0; l < profileCrossOffList.length; l++) {
            if (profileCrossOffList[l] == k) {
              //    Match with every value in field-array
              for (int m = 0; m < subjectsToProcess.length; m++) {
                if (subjectsToProcess[m] != null
                    && profileCrossOffList[l] != matchedField) {
                  if (getUse(profileID, l)
                      || !DnComponents.RFC822NAME.equals(
                          DnComponents.dnIdToProfileName(dnid))) {
                    /*
                     * IF the component is E-Mail (not RFC822NAME)
                     * OR if it is RFC822NAME AND E-Mail field
                     *  from DN should be used
                     */
                    if (fields.getField(dnFieldExtractorID, m).equals(email)) {
                      subjectsToProcess[m] = null;
                      profileCrossOffList[l] = matchedField;
                    }
                  }
                }
              }
            }
          }
        }
      }
      // For every field of this type in profile (start with required and
      // non-modifiable, 2 + 1)
      for (int k = max; k >= 0; k--) {
        // For every value in profile
        for (int l = 0; l < profileCrossOffList.length; l++) {
          if (profileCrossOffList[l] == k) {
            // Match with every value in field-array
            for (int m = 0; m < subjectsToProcess.length; m++) {
              if (subjectsToProcess[m] != null
                  && profileCrossOffList[l] != matchedField) {
                // Match actual value if required + non-modifiable or
                // non-modifiable
                if ((k == (requiredField + nonModifiableField)
                    || k == (nonModifiableField))) {
                  // Try to match with all possible values
                  String[] fixedValues =
                      getValue(profileID, l).split(SPLITCHAR);
                  for (int n = 0; n < fixedValues.length; n++) {
                    if (subjectsToProcess[m] != null
                        && subjectsToProcess[m].equals(fixedValues[n])) {
                      // Remove matched pair
                      subjectsToProcess[m] = null;
                      profileCrossOffList[l] = matchedField;
                    }
                  }

                  // Otherwise just match present fields
                } else {
                  // Remove matched pair
                  subjectsToProcess[m] = null;
                  profileCrossOffList[l] = matchedField;
                }
              }
            }
          }
        }
      }
      // If not all fields in profile were found
      for (int j = 0; j < nof; j++) {
        if (subjectsToProcess[j] != null) {
          throw new EndEntityProfileValidationException(
              "End entity profile does not contain matching field for "
                  + DnComponents.dnIdToProfileName(dnid)
                  + " with value \""
                  + subjectsToProcess[j]
                  + "\".");
        }
      }
      // If not all required fields in profile were found in subject
      for (int j = 0; j < getNumberOfField(profileID); j++) {
        if (profileCrossOffList[j] >= requiredField) {
          throw new EndEntityProfileValidationException(
              "Data does not contain required "
                  + DnComponents.dnIdToProfileName(dnid)
                  + " field.");
        }
      }
    }
  } // checkIfFieldsMatch

  /**
   * @param password Pass
   * @param clearpwd Clead
   * @throws EndEntityProfileValidationException dail
   */
  public void doesPasswordFulfillEndEntityProfile(
      final String password, final boolean clearpwd)
      throws EndEntityProfileValidationException {
    boolean fulfillsprofile = true;
    if (useAutoGeneratedPasswd()) {
      if (password != null) {
        throw new EndEntityProfileValidationException(
            "Autogenerated password must have password==null");
      }
    } else {
      if (!isPasswordModifiable()) {
        if (!password.equals(getValue(EndEntityProfile.PASSWORD, 0))) {
          fulfillsprofile = false;
        }
      } else {
        if (isPasswordRequired()) {
          if ((!clearpwd && password == null)
              || (password != null && password.trim().equals(""))) {
            fulfillsprofile = false;
          }
        }
      }
    }
    if (clearpwd
        && isRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0)
        && getValue(EndEntityProfile.CLEARTEXTPASSWORD, 0)
            .equals(EndEntityProfile.FALSE)) {
      fulfillsprofile = false;
    }
    if (!fulfillsprofile) {
      throw new EndEntityProfileValidationException(
          "Password doesn't fulfill profile.");
    }
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    final EndEntityProfile clone = new EndEntityProfile(0);
    // We need to make a deep copy of the hashmap here
    clone.data = new LinkedHashMap<>(data.size());
    for (final Entry<Object, Object> entry : data.entrySet()) {
      Object value = entry.getValue();
      if (value instanceof ArrayList<?>) {
        // We need to make a clone of this object, but the stored Integers can
        // still be referenced
        value = ((ArrayList<?>) value).clone();
      }
      clone.data.put(entry.getKey(), value);
    }
    return clone;
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion. */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @Override
  public void upgrade() {
    LOG.trace(">upgrade");
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      String msg =
          INTRES.getLocalizedMessage(
              "ra.eeprofileupgrade", Float.valueOf(getVersion()));
      LOG.info(msg);
      // New version of the class, upgrade
      if (getVersion() < 1) {
        final int size = 37;
        @SuppressWarnings("unchecked")
        ArrayList<Integer> numberarray =
            (ArrayList<Integer>) data.get(NUMBERARRAY);
        while (numberarray.size() < size) {
          numberarray.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY, numberarray);
      }
      if (getVersion() < 2) {
        final int size = 39;
        @SuppressWarnings("unchecked")
        ArrayList<Integer> numberarray =
            (ArrayList<Integer>) data.get(NUMBERARRAY);
        while (numberarray.size() < size) {
          numberarray.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY, numberarray);
        addField(AVAILCAS);
        addField(DEFAULTCA);
        setRequired(AVAILCAS, 0, true);
        setRequired(DEFAULTCA, 0, true);
      }
      if (getVersion() < 3) {
        // These fields have been removed in version 8, no need for this upgrade
        // setNotificationSubject("");
        // setNotificationSender("");
        // setNotificationMessage("");
      }
      if (getVersion() < 4) {
        @SuppressWarnings("unchecked")
        ArrayList<Integer> numberoffields =
            (ArrayList<Integer>) data.get(NUMBERARRAY);
        for (int i = numberoffields.size(); i < DATA_CONSTANTS.size(); i++) {
          numberoffields.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY, numberoffields);
      }
      // Support for DirectoryName altname field in profile version 5
      if (getVersion() < 5) {
        addField(DnComponents.DIRECTORYNAME);
        setValue(DnComponents.DIRECTORYNAME, 0, "");
        setRequired(DnComponents.DIRECTORYNAME, 0, false);
        setUse(DnComponents.DIRECTORYNAME, 0, true);
        setModifyable(DnComponents.DIRECTORYNAME, 0, true);
      }
      // Support for Subject Directory Attributes field in profile version 6
      if (getVersion() < 6) {
        @SuppressWarnings("unchecked")
        ArrayList<Integer> numberoffields =
            (ArrayList<Integer>) data.get(NUMBERARRAY);
        for (int i = numberoffields.size(); i < DATA_CONSTANTS.size(); i++) {
          numberoffields.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY, numberoffields);
        data.put(SUBJECTDIRATTRFIELDORDER, new ArrayList<Integer>());

        for (int i = getParameterNumber(DnComponents.DATEOFBIRTH);
            i <= getParameterNumber(DnComponents.COUNTRYOFRESIDENCE);
            i++) {
          addField(getParameter(i));
          setValue(getParameter(i), 0, "");
          setRequired(getParameter(i), 0, false);
          setUse(getParameter(i), 0, false);
          setModifyable(getParameter(i), 0, true);
        }
      }
      // Support for Start Time and End Time field in profile version 7
      if (getVersion() < 7) {
        @SuppressWarnings("unchecked")
        ArrayList<Integer> numberoffields =
            (ArrayList<Integer>) data.get(NUMBERARRAY);
        for (int i = numberoffields.size(); i < DATA_CONSTANTS.size(); i++) {
          numberoffields.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY, numberoffields);
        addField(STARTTIME);
        setValue(STARTTIME, 0, "");
        setRequired(STARTTIME, 0, false);
        setUse(STARTTIME, 0, false);
        setModifyable(STARTTIME, 0, true);
        addField(ENDTIME);
        setValue(ENDTIME, 0, "");
        setRequired(ENDTIME, 0, false);
        setUse(ENDTIME, 0, false);
        setModifyable(ENDTIME, 0, true);
      }
      // Notifications is now a more general mechanism in version 8
      if (getVersion() < 8) {
        LOG.debug("Upgrading User Notifications");
        if (data.get(UserNotification.NOTIFICATIONSENDER) != null) {
          UserNotification not = new UserNotification();
          not.setNotificationSender(
              (String) data.get(UserNotification.NOTIFICATIONSENDER));
          if (data.get(UserNotification.NOTIFICATIONSUBJECT) != null) {
            not.setNotificationSubject(
                (String) data.get(UserNotification.NOTIFICATIONSUBJECT));
          }
          if (data.get(UserNotification.NOTIFICATIONMESSAGE) != null) {
            not.setNotificationMessage(
                (String) data.get(UserNotification.NOTIFICATIONMESSAGE));
          }
          // Add the statuschanges we used to send notifications about
          String events = UserNotification.EVENTS_EDITUSER;
          not.setNotificationEvents(events);
          // The old recipients where always the user
          not.setNotificationRecipient(UserNotification.RCPT_USER);
          addUserNotification(not);
        }
      }
      // Support for allowed requests in profile version 9
      if (getVersion() < 9) {
        @SuppressWarnings("unchecked")
        ArrayList<Integer> numberoffields =
            (ArrayList<Integer>) data.get(NUMBERARRAY);
        for (int i = numberoffields.size(); i < DATA_CONSTANTS.size(); i++) {
          numberoffields.add(Integer.valueOf(0));
        }
        data.put(NUMBERARRAY, numberoffields);
        addField(ALLOWEDREQUESTS);
        setValue(ALLOWEDREQUESTS, 0, "");
        setRequired(ALLOWEDREQUESTS, 0, false);
        setUse(ALLOWEDREQUESTS, 0, false);
        setModifyable(ALLOWEDREQUESTS, 0, true);
      }
      // Support for merging DN from WS-API with default values in profile, in
      // profile version 10
      if (getVersion() < 10) {
        setAllowMergeDnWebServices(false);
      }
      // Support for issuance revocation status in profile version 11
      if (getVersion() < 11) {
        setRequired(ISSUANCEREVOCATIONREASON, 0, false);
        setUse(ISSUANCEREVOCATIONREASON, 0, false);
        setModifyable(ISSUANCEREVOCATIONREASON, 0, true);
        setValue(ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.NOT_REVOKED);
        setRequired(CARDNUMBER, 0, false);
        setUse(CARDNUMBER, 0, false);
        setModifyable(CARDNUMBER, 0, true);
      }
      // Support for maximum number of failed login attempts in profile version
      // 12
      if (getVersion() < 12) {
        setRequired(MAXFAILEDLOGINS, 0, false);
        setUse(MAXFAILEDLOGINS, 0, false);
        setModifyable(MAXFAILEDLOGINS, 0, true);
        setValue(
            MAXFAILEDLOGINS,
            0,
            Integer.toString(ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS));
      }
      /* In EJBCA 4.0.0 we changed the date format to ISO 8601.
       * In the Admin GUI the example was:
       *     DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT,
       *      ejbcawebbean.getLocale())
       * but the only absolute format that could have worked is the same
       * enforced by the
       * doesUserFulfillEndEntityProfile check and this is what need to
       * upgrade from:
       *        DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
       *        DateFormat.SHORT, Locale.US)
       */
      if (getVersion() < 13) {
        final DateFormat oldDateFormat =
            DateFormat.getDateTimeInstance(
                DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
        final FastDateFormat newDateFormat =
            FastDateFormat.getInstance("yyyy-MM-dd HH:mm");
        try {
          final String oldStartTime = getValue(STARTTIME, 0);
          if (!isEmptyOrRelative(oldStartTime)) {
            // We use an absolute time format, so we need to upgrade
            final String newStartTime =
                newDateFormat.format(oldDateFormat.parse(oldStartTime));
            setValue(STARTTIME, 0, newStartTime);
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Upgraded "
                      + STARTTIME
                      + " from \""
                      + oldStartTime
                      + "\" to \""
                      + newStartTime
                      + "\" in EndEntityProfile.");
            }
          }
        } catch (ParseException e) {
          LOG.error(
              "Unable to upgrade "
                  + STARTTIME
                  + " in EndEntityProfile! Manual interaction is required"
                  + " (edit and verify).",
              e);
        }
        try {
          final String oldEndTime = getValue(ENDTIME, 0);
          if (!isEmptyOrRelative(oldEndTime)) {
            // We use an absolute time format, so we need to upgrade
            final String newEndTime =
                newDateFormat.format(oldDateFormat.parse(oldEndTime));
            setValue(ENDTIME, 0, newEndTime);
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Upgraded "
                      + ENDTIME
                      + " from \""
                      + oldEndTime
                      + "\" to \""
                      + newEndTime
                      + "\" in EndEntityProfile.");
            }
          }
        } catch (ParseException e) {
          LOG.error(
              "Unable to upgrade "
                  + ENDTIME
                  + " in EndEntityProfile! Manual interaction is required"
                  + " (edit and verify).",
              e);
        }
      }
      /*
       * In version 13 we converted some dates to the "yyyy-MM-dd HH:mm"
       * format using default Locale.
       * These needs to be converted to the same format but should be
       * stored in UTC, so we always know what the times are.
       */
      if (getVersion() < 14) {
        final String[] timePatterns = {"yyyy-MM-dd HH:mm"};
        final String oldStartTime = getValue(STARTTIME, 0);
        if (!isEmptyOrRelative(oldStartTime)) {
          try {
            final String newStartTime =
                ValidityDateUtil.formatAsUTC(
                    DateUtils.parseDateStrictly(oldStartTime, timePatterns));
            setValue(STARTTIME, 0, newStartTime);
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Upgraded "
                      + STARTTIME
                      + " from \""
                      + oldStartTime
                      + "\" to \""
                      + newStartTime
                      + "\" in EndEntityProfile.");
            }
          } catch (ParseException e) {
            LOG.error(
                "Unable to upgrade "
                    + STARTTIME
                    + " to UTC in EndEntityProfile! Manual interaction is"
                    + " required (edit and verify).",
                e);
          }
        }
        final String oldEndTime = getValue(ENDTIME, 0);
        if (!isEmptyOrRelative(oldEndTime)) {
          // We use an absolute time format, so we need to upgrade
          try {
            final String newEndTime =
                ValidityDateUtil.formatAsUTC(
                    DateUtils.parseDateStrictly(oldEndTime, timePatterns));
            setValue(ENDTIME, 0, newEndTime);
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Upgraded "
                      + ENDTIME
                      + " from \""
                      + oldEndTime
                      + "\" to \""
                      + newEndTime
                      + "\" in EndEntityProfile.");
            }
          } catch (ParseException e) {
            LOG.error(
                "Unable to upgrade "
                    + ENDTIME
                    + " to UTC in EndEntityProfile! Manual interaction is"
                    + " required (edit and verify).",
                e);
          }
        }
      }
      // Finally, update the version stored in the map to the current version
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
    LOG.trace("<upgrade");
  }

  /**
   * @param time time
   * @return true if argument is null, empty or in the relative time format.
   */
  private boolean isEmptyOrRelative(final String time) {
    return (time == null
        || time.length() == 0
        || time.matches("^\\d+:\\d?\\d:\\d?\\d$"));
  }

  /**
   * @param field field
   * @return bool
   */
  public static boolean isFieldImplemented(final int field) {
    final String f = getParameter(field);
    if (f == null) {
      if (LOG.isTraceEnabled()) {
        LOG.trace(
            "isFieldImplemented got call for non-implemented field: " + field);
      }
      return false;
    }
    return isFieldImplemented(f);
  }

  /**
   * @param field field
   * @return bool
   */
  public static boolean isFieldImplemented(final String field) {
    boolean ret = true;
    if (field.equals(DnComponents.OTHERNAME)
        || field.equals(DnComponents.X400ADDRESS)
        || field.equals(DnComponents.EDIPARTYNAME)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "isFieldImplemented got call for non-implemented/ignored"
                + " subjectAltName field (custom extension is required): "
                + field);
      }
      ret = false;
    }
    return ret;
  }

  /**
   * @param fieldNumber num
   * @param fieldString field
   * @return bool
   */
  public static boolean isFieldOfType(
      final int fieldNumber, final String fieldString) {
    boolean ret = false;
    final int number = getParameterNumber(fieldString);
    if (fieldNumber == number) {
      ret = true;
    }
    return ret;
  }

  //
  // Private Methods
  //

  /**
   * Verify that the field contains an address and that data of non-modifyable
   * domain-fields is available in profile Used for email, upn and rfc822
   * fields.
   *
   * @param field Field
   * @param number Number
   * @param nameAndDomain Name
   * @param text Text
   * @throws EndEntityProfileValidationException If validation fails
   */
  private void checkIfDomainFulfillProfile(
      final String field,
      final int number,
      final String nameAndDomain,
      final String text)
      throws EndEntityProfileValidationException {
    if (!nameAndDomain.trim().equals("") && nameAndDomain.indexOf('@') == -1) {
      throw new EndEntityProfileValidationException(
          "Invalid "
              + text
              + "("
              + nameAndDomain
              + "). There must be a '@' character in the field.");
    }
    final String domain =
        nameAndDomain.substring(nameAndDomain.indexOf('@') + 1);
    // All fields except RFC822NAME has to be empty if not used flag is set.
    if (!DnComponents.RFC822NAME.equals(field)
        && !getUse(field, number)
        && !nameAndDomain.trim().equals("")) {
      throw new EndEntityProfileValidationException(
          text + " cannot be used in end entity profile.");
    }
    if (!isModifyable(field, number) && !nameAndDomain.equals("")) {
      String[] values;
      try {
        values = getValue(field, number).split(SPLITCHAR);
      } catch (Exception e) {
        throw new EndEntityProfileValidationException(
            "Error parsing end entity profile.");
      }
      boolean exists = false;
      for (final String value : values) {
        if (domain.equals(value.trim())) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        throw new EndEntityProfileValidationException(
            "Field "
                + text
                + " data didn't match requirement of end entity profile.");
      }
    }
  }

  private void checkForIllegalChars(final String str)
      throws EndEntityProfileValidationException {
    Set<String> invalidCharacters = StringUtil.hasSqlStripChars(str);
    if (!invalidCharacters.isEmpty()) {
      StringBuilder sb = new StringBuilder("");
      for (String error : invalidCharacters) {
        sb.append(", " + error);
      }
      throw new EndEntityProfileValidationException(
          "Invalid "
              + str
              + ". Contains illegal characters: "
              + sb.substring(2));
    }
  }

  /**
   * Used for iso 3166 country codes.
   *
   * @param field Field
   * @param number Number
   * @param country Country
   * @param text Text
   * @throws EndEntityProfileValidationException If validation fails
   */
  private void checkIfISO3166FulfillProfile(
      final String field,
      final int number,
      final String country,
      final String text)
      throws EndEntityProfileValidationException {
    final String countryTrim = country.trim();
    final int countryTrimLength = countryTrim.length();
    if (countryTrimLength != 0 && countryTrimLength != 2) {
      throw new EndEntityProfileValidationException(
          "Invalid " + text + ". Must be of length two.");
    }
    if (!getUse(field, number) && countryTrimLength != 0) {
      throw new EndEntityProfileValidationException(
          text + " cannot be used in end entity profile.");
    }
    if (!isModifyable(field, number) && countryTrimLength != 0) {
      String[] values;
      try {
        values = getValue(field, number).split(SPLITCHAR);
      } catch (Exception e) {
        throw new EndEntityProfileValidationException(
            "Error parsing end entity profile.");
      }
      boolean exists = false;
      for (final String value : values) {
        if (country.equals(value.trim())) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        throw new EndEntityProfileValidationException(
            "Field "
                + text
                + " data didn't match requirement of end entity profile.");
      }
    }
  }

  /**
   * Used to check if it is an M or an F.
   *
   * @param field Field
   * @param number Number
   * @param gender Gender
   * @param text Text
   * @throws EndEntityProfileValidationException If validation fails
   */
  private void checkIfGenderFulfillProfile(
      final String field,
      final int number,
      final String gender,
      final String text)
      throws EndEntityProfileValidationException {
    final boolean isGenerEmpty = gender.trim().isEmpty();
    if (!isGenerEmpty
        && !(gender.equalsIgnoreCase("m") || gender.equalsIgnoreCase("f"))) {
      throw new EndEntityProfileValidationException(
          "Invalid " + text + ". Must be M or F.");
    }
    if (!getUse(field, number) && !isGenerEmpty) {
      throw new EndEntityProfileValidationException(
          text + " cannot be used in end entity profile.");
    }
    if (!isModifyable(field, number) && !isGenerEmpty) {
      String[] values;
      try {
        values = getValue(field, number).split(SPLITCHAR);
      } catch (Exception e) {
        throw new EndEntityProfileValidationException(
            "Error parsing end entity profile.");
      }
      boolean exists = false;
      for (final String value : values) {
        if (gender.equals(value.trim())) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        throw new EndEntityProfileValidationException(
            "Field "
                + text
                + " data didn't match requirement of end entity profile.");
      }
    }
  }

  /**
   * @param field Field
   * @param number Number
   * @param date date
   * @param text Text
   * @throws EndEntityProfileValidationException If validation fails Used for
   *     date strings, should be YYYYMMDD
   */
  private void checkIfDateFulfillProfile(
      final String field,
      final int number,
      final String date,
      final String text)
      throws EndEntityProfileValidationException {
    final String dateTrim = date.trim();
    final boolean isDateEmpty = dateTrim.isEmpty();
    if (!isDateEmpty && dateTrim.length() != 8) {
      throw new EndEntityProfileValidationException(
          "Invalid " + text + ". Must be of length eight.");
    }
    if (!isDateEmpty && !StringUtils.isNumeric(dateTrim)) {
      throw new EndEntityProfileValidationException(
          "Invalid " + text + ". Must be only numbers.");
    }
    if (!getUse(field, number) && !isDateEmpty) {
      throw new EndEntityProfileValidationException(
          text + " cannot be used in end entity profile.");
    }
    if (!isModifyable(field, number) && !isDateEmpty) {
      String[] values;
      try {
        values = getValue(field, number).split(SPLITCHAR);
      } catch (Exception e) {
        throw new EndEntityProfileValidationException(
            "Error parsing end entity profile.");
      }
      boolean exists = false;
      for (final String value : values) {
        if (date.equals(value.trim())) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        throw new EndEntityProfileValidationException(
            "Field "
                + text
                + " data didn't match requirement of end entity profile.");
      }
    }
  }

  /**
   * Verifies that non-modifiable data is available in profile.
   *
   * @param field Field
   * @param number Number
   * @param data Data
   * @param text Text
   * @param email Email
   * @throws EndEntityProfileValidationException If validation fails
   */
  private void checkIfDataFulfillProfile(
      final String field,
      final int number,
      final String data,
      final String text,
      final String email)
      throws EndEntityProfileValidationException {
    // If USERNAME should be autogenerated skip this check
    if (field.equals(USERNAME) && !isModifyable(USERNAME, 0)) {
      return;
    }
    if (data == null && !field.equals(EMAIL)) {
      throw new EndEntityProfileValidationException(
          "Field " + text + " cannot be null.");
    }
    if (data != null) {
      if (!getUse(field, number) && !data.trim().isEmpty()) {
        throw new EndEntityProfileValidationException(
            text + " cannot be used in end entity profile.");
      }
    }
    if (field.equals(DnComponents.DNEMAILADDRESS)) {
      if (isRequired(field, number)) {
        if (!data.trim().equals(email.trim())) {
          throw new EndEntityProfileValidationException(
              "Field " + text + " data didn't match Email field.");
        }
      }
    } else if (field.equals(DnComponents.RFC822NAME)
        && isRequired(field, number)
        && getUse(field, number)) {
      if (!data.trim().equals(email.trim())) {
        throw new EndEntityProfileValidationException(
            "Field " + text + " data didn't match Email field.");
      }
    } else {
      if (!isModifyable(field, number)) {
        String[] values;
        try {
          values = getValue(field, number).split(SPLITCHAR);
        } catch (Exception e) {
          throw new EndEntityProfileValidationException(
              "Error parsing end entity profile.");
        }
        boolean exists = false;
        for (final String value : values) {
          if (data.equals(value.trim())) {
            exists = true;
          }
        }
        if (!exists) {
          throw new EndEntityProfileValidationException(
              "Field "
                  + text
                  + " data didn't match requirement of end entity profile.");
        }
      }
    }
  }

  private void checkIfAllRequiredFieldsExists(
      final DNFieldExtractor subjectdnfields,
      final DNFieldExtractor subjectaltnames,
      final DNFieldExtractor subjectdirattrs,
      final String username,
      final String email)
      throws EndEntityProfileValidationException {
    // Check if Username exists (if not modifiable skip the check)
    if (isRequired(USERNAME, 0) && isModifyable(USERNAME, 0)) {
      if (username == null || username.trim().isEmpty()) {
        throw new EndEntityProfileValidationException(
            "Username cannot be empty or null.");
      }
    }
    // Check if required Email fields exists.
    if (isRequired(EMAIL, 0)) {
      if (email == null || email.trim().isEmpty()) {
        throw new EndEntityProfileValidationException(
            "Email address cannot be empty or null.");
      }
    }
    // Check if all required subjectdn fields exists.
    final List<String> dnfields = DnComponents.getDnProfileFields();
    final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
    for (int i = 0; i < dnfields.size(); i++) {
      final String currentDnField = dnfields.get(i);
      if (getReverseFieldChecks()) {
        final int nof =
            subjectdnfields.getNumberOfFields(
                dnFieldExtractorIds.get(i).intValue());
        final int numRequiredFields = getNumberOfRequiredFields(currentDnField);
        if (nof < numRequiredFields) {
          throw new EndEntityProfileValidationException(
              "Subject DN field '" + currentDnField + "' must exist.");
        }
      } else {
        final int size = getNumberOfField(currentDnField);
        for (int j = 0; j < size; j++) {
          if (isRequired(currentDnField, j)) {
            if (subjectdnfields
                .getField(dnFieldExtractorIds.get(i).intValue(), j)
                .trim()
                .isEmpty()) {
              throw new EndEntityProfileValidationException(
                  "Subject DN field '" + currentDnField + "' must exist.");
            }
          }
        }
      }
    }
    // Check if all required subject alternate name fields exists.
    final List<String> altnamefields = DnComponents.getAltNameFields();
    final List<Integer> altNameFieldExtractorIds =
        DnComponents.getAltNameDnIds();
    for (int i = 0; i < altnamefields.size(); i++) {
      final String currentAnField = altnamefields.get(i);
      if (getReverseFieldChecks()) {
        final int nof =
            subjectaltnames.getNumberOfFields(
                altNameFieldExtractorIds.get(i).intValue());
        final int numRequiredFields = getNumberOfRequiredFields(currentAnField);
        if (nof < numRequiredFields) {
          throw new EndEntityProfileValidationException(
              "Subject Alternative Name field '"
                  + currentAnField
                  + "' must exist.");
        }
      } else {
        // Only verify fields that are actually used
        // size = getNumberOfField(altnamefields[i]);
        final int size =
            subjectaltnames.getNumberOfFields(
                altNameFieldExtractorIds.get(i).intValue());
        for (int j = 0; j < size; j++) {
          if (isRequired(currentAnField, j)) {
            if (subjectaltnames
                .getField(altNameFieldExtractorIds.get(i).intValue(), j)
                .trim()
                .isEmpty()) {
              throw new EndEntityProfileValidationException(
                  "Subject Alterntive Name field '"
                      + currentAnField
                      + "' must exist.");
            }
          }
        }
      }
    }
    // Check if all required subject directory attribute fields exists.
    final List<String> dirattrfields = DnComponents.getDirAttrFields();
    final List<Integer> dirAttrFieldExtractorIds =
        DnComponents.getDirAttrDnIds();
    for (int i = 0; i < dirattrfields.size(); i++) {
      final String currentDaField = dirattrfields.get(i);
      final int size = getNumberOfField(currentDaField);
      for (int j = 0; j < size; j++) {
        if (isRequired(currentDaField, j)) {
          if (subjectdirattrs
              .getField(dirAttrFieldExtractorIds.get(i).intValue(), j)
              .trim()
              .isEmpty()) {
            throw new EndEntityProfileValidationException(
                "Subject Directory Attribute field '"
                    + currentDaField
                    + "' must exist.");
          }
        }
      }
    }
  }

  /**
   * Method calculating the number of required fields of on kind that is
   * configured for this profile.
   *
   * @param field one of the field constants
   * @return The number of required fields of that kind.
   */
  private int getNumberOfRequiredFields(final String field) {
    int retval = 0;
    final int size = getNumberOfField(field);
    for (int j = 0; j < size; j++) {
      if (isRequired(field, j)) {
        retval++;
      }
    }
    return retval;
  }

  private void checkIfForIllegalNumberOfFields(
      final DNFieldExtractor subjectdnfields,
      final DNFieldExtractor subjectaltnames,
      final DNFieldExtractor subjectdirattrs)
      throws EndEntityProfileValidationException {
    // Check number of subjectdn fields.
    final List<String> dnfields = DnComponents.getDnProfileFields();
    final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
    for (int i = 0; i < dnfields.size(); i++) {
      if (getNumberOfField(dnfields.get(i))
          < subjectdnfields.getNumberOfFields(
              dnFieldExtractorIds.get(i).intValue())) {
        throw new EndEntityProfileValidationException(
            "Wrong number of " + dnfields.get(i) + " fields in Subject DN.");
      }
    }
    // Check number of subject alternate name fields.
    final List<String> altnamefields = DnComponents.getAltNameFields();
    final List<Integer> altNameFieldExtractorIds =
        DnComponents.getAltNameDnIds();
    for (int i = 0; i < altnamefields.size(); i++) {
      if (getNumberOfField(altnamefields.get(i))
          < subjectaltnames.getNumberOfFields(
              altNameFieldExtractorIds.get(i).intValue())) {
        throw new EndEntityProfileValidationException(
            "Wrong number of "
                + altnamefields.get(i)
                + " fields in Subject Alternative Name.");
      }
    }
    // Check number of subject directory attribute fields.
    final List<String> dirattrfields = DnComponents.getDirAttrFields();
    final List<Integer> dirAttrFieldExtractorIds =
        DnComponents.getDirAttrDnIds();
    for (int i = 0; i < dirattrfields.size(); i++) {
      if (getNumberOfField(dirattrfields.get(i))
          < subjectdirattrs.getNumberOfFields(
              dirAttrFieldExtractorIds.get(i).intValue())) {
        throw new EndEntityProfileValidationException(
            "Wrong number of "
                + dirattrfields.get(i)
                + " fields in Subject Directory Attributes.");
      }
    }
  }

  private void checkWithValidators(
      final DNFieldExtractor subjectdnfields,
      final DNFieldExtractor subjectaltnames)
      throws EndEntityProfileValidationException {
    final List<String> dnfields = DnComponents.getDnProfileFields();
    final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
    for (int i = 0; i < dnfields.size(); i++) {
      final int dnId = dnFieldExtractorIds.get(i);
      final int profileId = DnComponents.dnIdToProfileId(dnId);
      final String fieldName = dnfields.get(i);
      final int num = subjectdnfields.getNumberOfFields(dnId);
      for (int j = 0; j < num; j++) {
        final Map<String, Serializable> validators =
            getValidation(profileId, j);
        if (validators != null) {
          final String fieldValue = subjectdnfields.getField(dnId, j);
          try {
            EndEntityValidationHelper.checkValue(
                fieldName, validators, fieldValue);
          } catch (EndEntityFieldValidatorException e) {
            throw new EndEntityProfileValidationException(
                "Did not pass validation of field "
                    + fieldName
                    + " (in DN). "
                    + e.getMessage());
          }
        }
      }
    }

    final List<String> sanfields = DnComponents.getAltNameFields();
    final List<Integer> sanFieldExtractorIds = DnComponents.getAltNameDnIds();
    for (int i = 0; i < sanfields.size(); i++) {
      final int dnId = sanFieldExtractorIds.get(i);
      final int profileId = DnComponents.dnIdToProfileId(dnId);
      final String fieldName = sanfields.get(i);
      final int num = subjectaltnames.getNumberOfFields(dnId);
      for (int j = 0; j < num; j++) {
        final Map<String, Serializable> validators =
            getValidation(profileId, j);
        if (validators != null) {
          final String fieldValue = subjectaltnames.getField(dnId, j);
          try {
            EndEntityValidationHelper.checkValue(
                fieldName, validators, fieldValue);
          } catch (EndEntityFieldValidatorException e) {
            throw new EndEntityProfileValidationException(
                "Did not pass validation of field "
                    + fieldName
                    + " (in SAN). "
                    + e.getMessage());
          }
        }
      }
    }
  }

  /**
   * methods for mapping the DN, AltName,
   *  DirAttr constants from string-&gt;number.
   *
   * @param parameter Parameter
   * @return number from profilemappings.properties, or -1 if the parameter does
   *     not exist
   */
  private static int getParameterNumber(final String parameter) {
    final Integer number = DATA_CONSTANTS.get(parameter);
    if (number != null) {
      return number.intValue();
    }
    LOG.error("No parameter number for " + parameter);
    return -1;
  }

  /**
   * methods for mapping the DN, AltName, DirAttr
   * constants from number-&gt;string.
   *
   * @param parameterNumber Number
   * @return String
   */
  private static String getParameter(final int parameterNumber) {
    String ret = null;
    for (final Entry<String, Integer> entry : DATA_CONSTANTS.entrySet()) {
      if (entry.getValue().intValue() == parameterNumber) {
        ret = entry.getKey();
        break;
      }
    }
    if (ret == null) {
      LOG.error("No parameter for " + parameterNumber);
    }
    return ret;
  }

  private void incrementFieldnumber(final int parameter) {
    @SuppressWarnings("unchecked")
    final ArrayList<Integer> numberarray =
        (ArrayList<Integer>) data.get(NUMBERARRAY);
    numberarray.set(
        parameter, Integer.valueOf(numberarray.get(parameter).intValue() + 1));
  }

  private void decrementFieldnumber(final int parameter) {
    @SuppressWarnings("unchecked")
    final ArrayList<Integer> numberarray =
        (ArrayList<Integer>) data.get(NUMBERARRAY);
    numberarray.set(
        parameter, Integer.valueOf(numberarray.get(parameter).intValue() - 1));
  }

  /**
   * @return fields
   */
  public static String[] getSubjectDNProfileFields() {
    return DnComponents.getDnProfileFields().toArray(new String[0]);
  }

  /**
   * @return fields
   */
  public static String[] getSubjectAltnameProfileFields() {
    return DnComponents.getAltNameFields().toArray(new String[0]);
  }

  /**
   * @return fields
   */
  public static String[] getSubjectDirAttrProfileFields() {
    return DnComponents.getDirAttrFields().toArray(new String[0]);
  }
  /**
   * @return bool
   */
  public boolean getNameConstraintsPermittedUsed() {
    return getUse(NAMECONSTRAINTS_PERMITTED, 0);
  }
  /**
   * @return bool
   */
  public boolean getNameConstraintsPermittedRequired() {
    return isRequired(NAMECONSTRAINTS_PERMITTED, 0);
  }
  /**
   * @return bool
   */
  public boolean getNameConstraintsExcludedUsed() {
    return getUse(NAMECONSTRAINTS_EXCLUDED, 0);
  }

  /**
   * @return bool
   */
  public boolean getNameConstraintsExcludedRequired() {
    return isRequired(NAMECONSTRAINTS_EXCLUDED, 0);
  }

  /** @return true if it should be possible to add extension data in the GUI. */
  public boolean getUseExtensiondata() {
    return getValueDefaultFalse(USEEXTENSIONDATA);
  }

  /**
   * @param use bool
   */
  public void setUseExtensiondata(final boolean use) {
    data.put(USEEXTENSIONDATA, Boolean.valueOf(use));
  }

  @Override
  public String toString() {
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("Values={");
    for (String key : DATA_CONSTANTS.keySet()) {
      // Output all defined values
      Object value = data.get(key);
      if (value != null) {
        stringBuilder.append("[" + key + "=" + value + "]");
      }
    }
    stringBuilder.append("}");
    return stringBuilder.toString();
  }

  /** Nested class FieldInstance for convenient invoking from xhtml. */
  public class FieldInstance {
    /** Name. */
    private final String name;
    /** num. */
    private final int number;
    /** val. */
    private String value;
    /** default. */
    private String defaultValue;
    /** id. */
    private final int profileId;
    /** Bool. */
    private boolean rfcEmailUsed;
    /** pattern. */
    private String regexPattern;

    /**
     * @param aname name
     * @param anumber num
     */
    public FieldInstance(final String aname, final int anumber) {
      this.name = aname;
      this.number = anumber;
      this.defaultValue = EndEntityProfile.this.getValue(aname, anumber);
      this.value = isSelectable() ? getSelectableValues().get(0) : defaultValue;
      this.profileId = EndEntityProfile.DATA_CONSTANTS.get(aname);
      this.rfcEmailUsed = aname.equals("RFC822NAME") && isUsed();
      HashMap<String, Serializable> temp =
          EndEntityProfile.this.getValidation(aname, anumber);
      if (temp != null) {
        this.regexPattern =
            (String) temp.get(RegexFieldValidator.class.getName());
      }
    }

    /**
     * @return bool
     */
    public boolean isUsed() {
      return EndEntityProfile.this.getUse(name, number);
    }

    /**
     * @return bool
     */
    public boolean isRequired() {
      return EndEntityProfile.this.isRequired(name, number);
    }

    /**
     * @return bool
     */
    public boolean isModifiable() {
      return EndEntityProfile.this.isModifyable(name, number);
    }

    /**
     * @return bool
     */
    public boolean isRegexPatternRequired() {
      return getRegexPattern() != null;
    }

    /**
     * @return bool
     */
    public boolean isUnModifiableUpnRfc() {
      return !isModifiable()
          && (name.equals("RFC822NAME") || name.equals("UPN"));
    }

    /**
     * @return bool
     */
    public boolean isRfcUseEmail() {
      return name.equals("RFC822NAME") && isUsed();
    }

    /**
     * @return bool
     */
    public boolean getRfcEmailUsed() {
      return rfcEmailUsed;
    }

    /**
     * @param isrfcEmailUsed bool
     */
    public void setRfcEmailUsed(final boolean isrfcEmailUsed) {
      this.rfcEmailUsed = isrfcEmailUsed;
    }

    /**
     * @return value
     */
    public String getValue() {
      return value;
    }

    /**
     * @param avalue value
     */
    public void setValue(final String avalue) {
      this.value = avalue;
    }

    /**
     * @return value
     */
    public String getDefaultValue() {
      return defaultValue;
    }

    /**
     * @param avalue value
     */
    public void setDefaultValue(final String avalue) {
      this.defaultValue = avalue;
    }

    /**
     * @return name
     */
    public String getName() {
      return name;
    }

    /**
     * @return pattern
     */
    public String getRegexPattern() {
      return regexPattern;
    }

    /**
     * @return num
     */
    public int getNumber() {
      return number;
    }

    /**
     * @return bool
     */
    public boolean isSelectable() {
      return !isModifiable()
          && getDefaultValue() != null
          && getDefaultValue().split(";").length > 1;
    }

    /**
     * @return values
     */
    public List<String> getSelectableValues() {
      return isSelectable() ? Arrays.asList(defaultValue.split(";")) : null;
    }

    /**
     * @return values
     */
    public List<String> getSelectableValuesUpnRfc() {
      return Arrays.asList(defaultValue.split(";"));
    }

    @Override
    public int hashCode() {
      return name.hashCode();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FieldInstance)) {
            return false;
        }
        FieldInstance other = (FieldInstance) o;
        return other.name.equals(this.name);
    }

    /**
     * @return ID
     */
    public int getProfileId() {
      return profileId;
    }
  }

  /** Nested method wrapper class Field for convenient invoking from xhtml. */
  public class Field {
      /** name. */
    private final String name;
    /** Instances.
     */
    private final List<FieldInstance> instances;

    /**
     * @param aname name
     */
    public Field(final String aname) {
      this.name = aname;
      int numberOfInstances = EndEntityProfile.this.getNumberOfField(aname);
      instances = new ArrayList<>(numberOfInstances);
      for (int i = 0; i < numberOfInstances; i++) {
        instances.add(new FieldInstance(aname, i));
      }
    }

    /**
     * @return size
     */
    public int getNumber() {
      return instances.size();
    }

    /**
     * @return name
     */
    public String getName() {
      return name;
    }

    /**
     * @return instances
     */
    public List<FieldInstance> getInstances() {
      return instances;
    }
  }

  /**
   * @return user
   */
  public Field getUsername() {
    return new Field(EndEntityProfile.USERNAME);
  }


  /**
   * @return password
   */
  public Field getPassword() {
    return new Field(EndEntityProfile.PASSWORD);
  }


  /**
   * @return email
   */
  public Field getEmail() {
    return new Field(EndEntityProfile.EMAIL);
  }

}
