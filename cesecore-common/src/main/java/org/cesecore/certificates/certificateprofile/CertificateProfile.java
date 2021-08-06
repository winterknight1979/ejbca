/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificateprofile;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;

/**
 * CertificateProfile is a basic class used to customize a certificate
 * configuration or be inherited by fixed certificate profiles.
 *
 * @version $Id: CertificateProfile.java 29578 2018-08-07 12:19:15Z
 *     jekaterina_b_helmes $
 */
public class CertificateProfile extends UpgradeableDataHashMap // NOPMD: length
    implements Serializable, Cloneable {
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(CertificateProfile.class);
  /** Internal localization of logs and errors. */
  private static final InternalResources INT_RES =
      InternalResources.getInstance();

  // Public Constants
  /** API version. */
  public static final float LATEST_VERSION = (float) 46.0;
  /** Root CA. */
  public static final String ROOTCAPROFILENAME = "ROOTCA";
  /** Sub CA. */
  public static final String SUBCAPROFILENAME = "SUBCA";
  /** User. */
  public static final String ENDUSERPROFILENAME = "ENDUSER";
  /** Signer. */
  public static final String OCSPSIGNERPROFILENAME = "OCSPSIGNER";
  /** Profile. */
  public static final String SERVERPROFILENAME = "SERVER";
  /** Auth. */
  public static final String HARDTOKENAUTHPROFILENAME = "HARDTOKEN_AUTH";
  /** Auth encoding. */
  public static final String HARDTOKENAUTHENCPROFILENAME = "HARDTOKEN_AUTHENC";
  /** Encoding. */
  public static final String HARDTOKENENCPROFILENAME = "HARDTOKEN_ENC";
  /** Name. */
  public static final String HARDTOKENSIGNPROFILENAME = "HARDTOKEN_SIGN";
  /** size of usage array. */
  private static final int KEY_USAGE_LENGTH = 9;
  /** Names. */
  public static final List<String> FIXED_PROFILENAMES = new ArrayList<>();

  static {
    FIXED_PROFILENAMES.add(ROOTCAPROFILENAME);
    FIXED_PROFILENAMES.add(SUBCAPROFILENAME);
    FIXED_PROFILENAMES.add(ENDUSERPROFILENAME);
    FIXED_PROFILENAMES.add(OCSPSIGNERPROFILENAME);
    FIXED_PROFILENAMES.add(SERVERPROFILENAME);
    FIXED_PROFILENAMES.add(HARDTOKENAUTHPROFILENAME);
    FIXED_PROFILENAMES.add(HARDTOKENAUTHENCPROFILENAME);
    FIXED_PROFILENAMES.add(HARDTOKENENCPROFILENAME);
    FIXED_PROFILENAMES.add(HARDTOKENSIGNPROFILENAME);
  }

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = -8069608639716545206L;

  /** Microsoft Template Constants. */
  public static final String MSTEMPL_DOMAINCONTROLLER = "DomainController";

  /** Templates. */
  public static final String[] AVAILABLE_MSTEMPLATES = {
    MSTEMPL_DOMAINCONTROLLER
  };


  /** Boolean. */
  public static final String TRUE = "true";
  /** Boolean. */
  public static final String FALSE = "false";

  /**
   * Determines the access rights in CV Certificates. CV Certificates is used by
   * EU EAC ePassports and is issued by a CVC CA. DG3 is access to fingerprints
   * and DG4 access to iris.
   */
  public static final int CVC_ACCESS_NONE = 0;
  /** Bitmask. */
  public static final int CVC_ACCESS_DG3 = 1;
  /** Bitmask. */
  public static final int CVC_ACCESS_DG4 = 2;
  /** Bitmask. */
  public static final int CVC_ACCESS_DG3DG4 = 3;
  // For signature terminals (defined in version 2.10 of the EAC specification)
  /** Bitmask. */
  public static final int CVC_ACCESS_SIGN = 16;
  /** Bitmask. */
  public static final int CVC_ACCESS_QUALSIGN = 32;
  /** Bitmask. */
  public static final int CVC_ACCESS_SIGN_AND_QUALSIGN = 48;

  /**
   * CVC terminal types. Controls which set of roles and access rights are
   * available.
   */
  public static final int CVC_TERMTYPE_IS = 0;
  /** Authentication terminal. */
  public static final int CVC_TERMTYPE_AT = 1;
  /** Signature terminal. */
  public static final int CVC_TERMTYPE_ST = 2;

  /** Accreditation Body DV for signature terminals. ABs accredits CSPs. */
  public static final int CVC_SIGNTERM_DV_AB = 0;
  /** Certification Service Provider DV for signature terminals. */
  public static final int CVC_SIGNTERM_DV_CSP = 1;

  /** Supported certificate versions. */
  public static final String VERSION_X509V3 = "X509v3";

  /** Name. */
  public static final String CUSTOMPROFILENAME = "CUSTOM";

  /**
   * Constant indicating that any CA can be used with this certificate profile.
   */
  public static final int ANYCA = -1;
  /**
   * Constant indicating that any elliptic curve may be used with this profile.
   */
  public static final String ANY_EC_CURVE = "ANY_EC_CURVE";

  /**
   * Constant holding the default available bit lengths for
   * certificate profiles.
   */
  public static final int[] DEFAULTBITLENGTHS = {
    0, 192, 224, 239, 256, 384, 512, 521, 1024, 1536, 2048, 3072, 4096, 6144,
    8192
  };

  /** Rights. */
  public static final byte[] DEFAULT_CVC_RIGHTS_AT = {0, 0, 0, 0, 0};

  /** Constants for validity and private key usage period. */
  public static final String DEFAULT_CERTIFICATE_VALIDITY = "2y";
  /**
   * Constant for default validity for fixed profiles is 25 years including 6 or
   * 7 leap days.
   */
  public static final String DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA =
      "25y7d";
  /**
   * Constant for default validity offset
   * (for backward compatibility': -10m'!).
   */
  public static final String DEFAULT_CERTIFICATE_VALIDITY_OFFSET = "-10m";

  /** Offset. */
  public static final long DEFAULT_PRIVATE_KEY_USAGE_PERIOD_OFFSET = 0;
  /** Length. */
  public static final long DEFAULT_PRIVATE_KEY_USAGE_PERIOD_LENGTH =
      730 * 24 * 3600;

  // Profile fields
  /** Version. */
  protected static final String CERTVERSION = "certversion";
  /** Validity. */
  @Deprecated protected static final String VALIDITY = "validity";
  /** Validity. */
  protected static final String ENCODED_VALIDITY = "encodedvalidity";
  /** Validity. */
  protected static final String USE_CERTIFICATE_VALIDITY_OFFSET =
      "usecertificatevalidityoffset";
  /** Validity. */
  protected static final String CERTIFICATE_VALIDITY_OFFSET =
      "certificatevalidityoffset";
  /** Expiration. */
  protected static final String USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS =
      "useexpirationrestrictionforweekdays";
  /** Expiration. */
  protected static final String EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE =
      "expirationrestrictionforweekdaysbefore";
  /** Expiration. */
  protected static final String EXPIRATION_RESTRICTION_WEEKDAYS =
      "expirationrestrictionweekdays";
  /** Override. */
  protected static final String ALLOWVALIDITYOVERRIDE = "allowvalidityoverride";
  /** Override. */
  protected static final String ALLOWKEYUSAGEOVERRIDE = "allowkeyusageoverride";
  /** Revocation. */
  protected static final String ALLOWBACKDATEDREVOCATION =
      "allowbackdatedrevokation";
  /** Override. */
  protected static final String ALLOWEXTENSIONOVERRIDE =
      "allowextensionoverride";
  /** Override. */
  protected static final String ALLOWDNOVERRIDE = "allowdnoverride";
  /** EEI.  */
  protected static final String ALLOWDNOVERRIDEBYEEI = "allowdnoverridebyeei";
  /** Certs. */
  protected static final String ALLOWCERTSNOVERIDE = "allowcertsnoverride";
  /** Algos. */
  protected static final String AVAILABLEKEYALGORITHMS =
      "availablekeyalgorithms";
  /** ECC. */
  protected static final String AVAILABLEECCURVES = "availableeccurves";
  /** Bit length. */
  protected static final String AVAILABLEBITLENGTHS = "availablebitlengths";
  /** Bit length. */
  protected static final String MINIMUMAVAILABLEBITLENGTH =
      "minimumavailablebitlength";
  /** Bit length. */
  protected static final String MAXIMUMAVAILABLEBITLENGTH =
      "maximumavailablebitlength";
  /** Type. */
  public static final String TYPE = "type";
  /** CAs. */
  protected static final String AVAILABLECAS = "availablecas";
  /** Publishers. */
  protected static final String USEDPUBLISHERS = "usedpublishers";
  /** Postfix. */
  protected static final String USECNPOSTFIX = "usecnpostfix";
  /** Postix. */
  protected static final String CNPOSTFIX = "cnpostfix";
  /** DN. */
  protected static final String USESUBJECTDNSUBSET = "usesubjectdnsubset";
  /** DN. */
  protected static final String SUBJECTDNSUBSET = "subjectdnsubset";
  /** Alt name. */
  protected static final String USESUBJECTALTNAMESUBSET =
      "usesubjectaltnamesubset";
  /** Alt name. */
  protected static final String SUBJECTALTNAMESUBSET = "subjectaltnamesubset";
  /** extensions. */
  protected static final String USEDCERTIFICATEEXTENSIONS =
      "usedcertificateextensions";
  /**
   * @deprecated since 6.8.0, where approval settings and profiles became
   *     interlinked.
   */
  @Deprecated
  protected static final String APPROVALSETTINGS = "approvalsettings";
  /**
   * @deprecated since 6.6.0, use the appropriate approval profile instead
   *     Needed for a while in order to be able to import old statedumps from
   *     6.5 and earlier
   */
  @Deprecated
  public static final String NUMOFREQAPPROVALS = "numofreqapprovals";
  /**
   * @deprecated since 6.8.0, where approval settings and profiles became
   *     interlinked.
   */
  @Deprecated protected static final String APPROVALPROFILE = "approvalProfile";

  /** Approvals. */
  protected static final String APPROVALS = "approvals";
  /** Algo. */
  protected static final String SIGNATUREALGORITHM = "signaturealgorithm";
  /** Storage. */
  protected static final String USECERTIFICATESTORAGE = "usecertificatestorage";
  /** Data. */
  protected static final String STORECERTIFICATEDATA = "storecertificatedata";
  /** Name. */
  protected static final String STORESUBJECTALTNAME = "storesubjectaltname";
  //
  // CRL extensions
  /** CRL. */
  protected static final String USECRLNUMBER = "usecrlnumber";
  /** CRL. */
  protected static final String CRLNUMBERCRITICAL = "crlnumbercritical";
  //
  // Certificate extensions
  /** Constraints. */
  protected static final String USEBASICCONSTRAINTS = "usebasicconstrants";
  /** Constraints. */
  protected static final String BASICCONSTRAINTSCRITICAL =
      "basicconstraintscritical";
  /** Length. */
  protected static final String USEPATHLENGTHCONSTRAINT =
      "usepathlengthconstraint";
  /** Length. */
  protected static final String PATHLENGTHCONSTRAINT = "pathlengthconstraint";
  /** Usage. */
  protected static final String USEKEYUSAGE = "usekeyusage";
  /** Usage. */
  protected static final String KEYUSAGECRITICAL = "keyusagecritical";
  /** Usage. */
  protected static final String KEYUSAGE = "keyusage";
  /** ID. */
  protected static final String USESUBJECTKEYIDENTIFIER =
      "usesubjectkeyidentifier";
  /** ID. */
  protected static final String SUBJECTKEYIDENTIFIERCRITICAL =
      "subjectkeyidentifiercritical";
  /** ID. */
  protected static final String USEAUTHORITYKEYIDENTIFIER =
      "useauthoritykeyidentifier";
  /** ID. */
  protected static final String AUTHORITYKEYIDENTIFIERCRITICAL =
      "authoritykeyidentifiercritical";
  /** Name. */
  protected static final String USESUBJECTALTERNATIVENAME =
      "usesubjectalternativename";
  /** Name.. */
  protected static final String SUBJECTALTERNATIVENAMECRITICAL =
      "subjectalternativenamecritical";
  /** name.. */
  protected static final String USEISSUERALTERNATIVENAME =
      "useissueralternativename";
  /** Name. */
  protected static final String ISSUERALTERNATIVENAMECRITICAL =
      "issueralternativenamecritical";
  /** CRL. */
  protected static final String USECRLDISTRIBUTIONPOINT =
      "usecrldistributionpoint";
  /** CRL. */
  protected static final String USEDEFAULTCRLDISTRIBUTIONPOINT =
      "usedefaultcrldistributionpoint";
  /** CRL. */
  protected static final String CRLDISTRIBUTIONPOINTCRITICAL =
      "crldistributionpointcritical";
  /** CRL. */
  protected static final String CRLDISTRIBUTIONPOINTURI =
      "crldistributionpointuri";
  /** CRL. */
  protected static final String CRLISSUER = "crlissuer";
  /** CRL. */
  protected static final String USEFRESHESTCRL = "usefreshestcrl";
  /** CRL. */
  protected static final String USECADEFINEDFRESHESTCRL =
      "usecadefinedfreshestcrl";
  /** URI. */
  protected static final String FRESHESTCRLURI = "freshestcrluri";
  /** Policies. */
  protected static final String USECERTIFICATEPOLICIES =
      "usecertificatepolicies";
  /** Policies. */
  protected static final String CERTIFICATEPOLICIESCRITICAL =
      "certificatepoliciescritical";
  /** Policy containing oid, User Notice and Cps Url. */
  protected static final String CERTIFICATE_POLICIES = "certificatepolicies";
 /** Usage. */
  protected static final String USEEXTENDEDKEYUSAGE = "useextendedkeyusage";
  /** Usage. */
  protected static final String EXTENDEDKEYUSAGE = "extendedkeyusage";
  /** Usage. */
  protected static final String EXTENDEDKEYUSAGECRITICAL =
      "extendedkeyusagecritical";
  /** Types. */
  protected static final String USEDOCUMENTTYPELIST = "usedocumenttypelist";
  /** Types. */
  protected static final String DOCUMENTTYPELISTCRITICAL =
      "documenttypelistcritical";
  /** Types.. */
  protected static final String DOCUMENTTYPELIST = "documenttypelist";
  /** Check. */
  protected static final String USEOCSPNOCHECK = "useocspnocheck";
  /** Access. */
  protected static final String USEAUTHORITYINFORMATIONACCESS =
      "useauthorityinformationaccess";
  /** Locator. */
  protected static final String USEOCSPSERVICELOCATOR = "useocspservicelocator";
  /** Issuer. */
  protected static final String USEDEFAULTCAISSUER = "usedefaultcaissuer";
  /** Locator. */
  protected static final String USEDEFAULTOCSPSERVICELOCATOR =
      "usedefaultocspservicelocator";
  /** URI. */
  protected static final String OCSPSERVICELOCATORURI = "ocspservicelocatoruri";
  /** Issuers. */
  protected static final String USECAISSUERS = "usecaissuersuri";
  /** Issuers. */
  protected static final String CAISSUERS = "caissuers";
  /** Order. */
  protected static final String USELDAPDNORDER = "useldapdnorder";
  /** Template. */
  protected static final String USEMICROSOFTTEMPLATE = "usemicrosofttemplate";
  /** Template. */
  protected static final String MICROSOFTTEMPLATE = "microsofttemplate";
  /** Number. */
  protected static final String USECARDNUMBER = "usecardnumber";
  /** Statement. */
  protected static final String USEQCSTATEMENT = "useqcstatement";
  /** Syntax. */
  protected static final String USEPKIXQCSYNTAXV2 = "usepkixqcsyntaxv2";
  /** Critical. */
  protected static final String QCSTATEMENTCRITICAL = "useqcstatementcritical";
  /** Name.*/
  protected static final String QCSTATEMENTRANAME = "useqcstatementraname";
  /** Semantics. */
  protected static final String QCSSEMANTICSID = "useqcsematicsid";
  /** Compliance. */
  protected static final String USEQCETSIQCCOMPLIANCE = "useqcetsiqccompliance";
  /** Limit. */
  protected static final String USEQCETSIVALUELIMIT = "useqcetsivaluelimit";
  /** Limit. */
  protected static final String QCETSIVALUELIMIT = "qcetsivaluelimit";
  /** Limit. */
  protected static final String QCETSIVALUELIMITEXP = "qcetsivaluelimitexp";
  /** Currency. */
  protected static final String QCETSIVALUELIMITCURRENCY =
      "qcetsivaluelimitcurrency";
  /** Period. */
  protected static final String USEQCETSIRETENTIONPERIOD =
      "useqcetsiretentionperiod";
  /** Period. */
  protected static final String QCETSIRETENTIONPERIOD = "qcetsiretentionperiod";
  /** Device. */
  protected static final String USEQCETSISIGNATUREDEVICE =
      "useqcetsisignaturedevice";
  /** Type. */
  protected static final String USEQCETSITYPE = "useqcetsitype";
  /** Type. */
  protected static final String QCETSITYPE = "qcetsitype";
  /** IDs. */
  protected static final String QCETSIPDS = "qcetsipds";
  /**
   * @deprecated since EJBCA 6.6.1. It was only used in 6.6.0, and is needed to
   *     handle upgrades from that version PDS URLs are now handled in QCETSIPDS
   */
  @Deprecated protected static final String QCETSIPDSURL = "qcetsipdsurl";
  /**
   * @deprecated since EJBCA 6.6.1. It was only used in 6.6.0, and is needed to
   *     handle upgrades from that version PDS URLs are now handled in QCETSIPDS
   */
  @Deprecated protected static final String QCETSIPDSLANG = "qcetsipdslang";

  /** Custom. */
  protected static final String USEQCCUSTOMSTRING = "useqccustomstring";
  /** OID. */
  protected static final String QCCUSTOMSTRINGOID = "qccustomstringoid";
  /** String. */
  protected static final String QCCUSTOMSTRINGTEXT = "qccustomstringtext";
  /** Constraints. */
  protected static final String USENAMECONSTRAINTS = "usenameconstraints";
  /** Constraints. */
  protected static final String NAMECONSTRAINTSCRITICAL =
      "nameconstraintscritical";
  /** Atributes. */
  protected static final String USESUBJECTDIRATTRIBUTES =
      "usesubjectdirattributes";
  /** Type. */
  protected static final String CVCTERMINALTYPE = "cvctermtype";
  /** Rights. */
  protected static final String CVCACCESSRIGHTS = "cvcaccessrights";
  /** Rights. */
  protected static final String CVCLONGACCESSRIGHTS = "cvclongaccessrights";
  /** Type. */
  protected static final String CVCSIGNTERMDVTYPE = "cvcsigntermdvtype";
  /** Period. */
  protected static final String USEPRIVKEYUSAGEPERIOD = "useprivkeyusageperiod";
  /** Period. */
  protected static final String USEPRIVKEYUSAGEPERIODNOTBEFORE =
      "useprivkeyusageperiodnotbefore";
  /** Period. */
  protected static final String USEPRIVKEYUSAGEPERIODNOTAFTER =
      "useprivkeyusageperiodnotafter";
  /** Period. */
  protected static final String PRIVKEYUSAGEPERIODSTARTOFFSET =
      "privkeyusageperiodstartoffset";
  /** Period. */
  protected static final String PRIVKEYUSAGEPERIODLENGTH =
      "privkeyusageperiodlength";
  /** Transparency. */
  protected static final String USECERTIFICATETRANSPARENCYINCERTS =
      "usecertificatetransparencyincerts";
  /** Transparency. */
  protected static final String USECERTIFICATETRANSPARENCYINOCSP =
      "usecertificatetransparencyinocsp";
  /** Transparency. */
  protected static final String USECERTIFICATETRANSPARENCYINPUBLISHERS =
      "usecertificatetransparencyinpublisher";

  /* Certificate Transparency */
  /** Existing. */
  protected static final String CTSUBMITEXISTING = "ctsubmitexisting";
  /** Logs. */
  protected static final String CTLOGS = "ctlogs";
  /** Labels. */
  protected static final String CTLABELS = "ctlabels";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MIN_TOTAL_SCTS =
      "ctminscts"; // This key is the same as in previous versions

  /** SCTs. */
  @Deprecated
  protected static final String CT_MIN_TOTAL_SCTS_OCSP =
      "ctminsctsocsp"; // This key is also the same as in previous versions

  /** SCTs. */
  @Deprecated
  protected static final String CT_MAX_SCTS =
      "ctmaxscts"; // Only used to fetch old value after upgrade, replaced by
                   // CT_MAX_NON_MANDATORY_SCTS and CT_MAX_MANDATORY_SCTS

  /** SCTs. */
  @Deprecated
  protected static final String CT_MAX_SCTS_OCSP =
      "ctmaxsctsocsp"; // Only used to fetch old value after upgrade, replaced
                       // by CT_MAX_NONMANDATORY_SCTS_OCSP and
                       // CT_MAX_MANDATORY_SCTS

  /* All deprecated below were removed in 6.10.1. Keep for
   * upgrade purposes or move keys to UpgradeSessionBean */
  /** SCTs. */
  @Deprecated
  protected static final String CT_MIN_MANDATORY_SCTS = "ctminmandatoryscts";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MAX_MANDATORY_SCTS = "ctmaxmandatoryscts";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MIN_MANDATORY_SCTS_OCSP =
      "ctminmandatorysctsocsp";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MAX_MANDATORY_SCTS_OCSP =
      "ctmaxmandatorysctsocsp";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MIN_NONMANDATORY_SCTS =
      "ctminnonmandatoryscts";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MAX_NONMANDATORY_SCTS =
      "ctmaxnonmandatoryscts";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MIN_NONMANDATORY_SCTS_OCSP =
      "ctminnonmandatorysctsocsp";

  /** SCTs. */
  @Deprecated
  protected static final String CT_MAX_NONMANDATORY_SCTS_OCSP =
      "ctmaxnonmandatorysctsocsp";

  /** SCTs. */
  protected static final String CT_SCTS_MIN = "ctsctsmin";
  /** SCTs. */
  protected static final String CT_SCTS_MAX = "ctsctsmax";
  /** SCTs. */
  protected static final String CT_SCTS_MIN_OCSP = "ctsctsminocsp";
  /** SCTs. */
  protected static final String CT_SCTS_MAX_OCSP = "ctsctsmaxocsp";
  /** SCTs. */
  protected static final String CT_NUMBER_OF_SCTS_BY_VALIDITY =
      "ctnumberofsctsbyvalidity";
  /** SCTs. */
  protected static final String CT_NUMBER_OF_SCTS_BY_CUSTOM =
      "ctnumberofsctsbycustom";
  /** SCTs. */
  protected static final String CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY =
      "ctmaxnumberofsctsbyvalidity";
  /** SCTs. */
  protected static final String CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM =
      "ctmaxnumberofsctsbycustom";
  /** Retries. */
  protected static final String CTMAXRETRIES = "ctmaxretries";

  /** Constraint. */
  protected static final String USERSINGLEACTIVECERTIFICATECONSTRAINT =
      "usesingleactivecertificateconstraint";
  /** Custom. */
  protected static final String USECUSTOMDNORDER = "usecustomdnorder";
  /** Custom. */
  protected static final String USECUSTOMDNORDERLDAP = "usecustomdnorderldap";
  /** Custom. */
  protected static final String CUSTOMDNORDER = "customdnorder";
  /** Overrideable. */
  protected static final String OVERRIDABLEEXTENSIONOIDS =
      "overridableextensionoids";
  /** Non-overrideable. */
  protected static final String NONOVERRIDABLEEXTENSIONOIDS =
      "nonoverridableextensionoids";

  /**
   * OID for creating Smartcard Number Certificate Extension SEIS Cardnumber
   * Extension according to SS 614330/31.
   */
  public static final String OID_CARDNUMBER = "1.2.752.34.2.1";

  /** Constants holding the use properties for certificate extensions. */
  protected static final HashMap<String, String>
      USE_STD_CERT_EXTENSIONS = new HashMap<>();
  /** Days in week. */
  private static final int DAYS_IN_WEEK = 7;
  // Old values used to upgrade from v22 to v23
  /** ID. */
  protected static final String CERTIFICATEPOLICYID = "certificatepolicyid";
  /** Policy Notice Url to CPS field alias in the data structure. */
  protected static final String POLICY_NOTICE_CPS_URL = "policynoticecpsurl";
  /** Policy Notice User Notice field alias in the data structure. */
  protected static final String POLICY_NOTICE_UNOTICE_TEXT =
      "policynoticeunoticetext";

  /** Min RSA/DSA key size. */
  private static final int MIN_RSA_DSA_SIZE = 1024;
  /** Min EC key size. */
  private static final int MIN_EC_SIZE = 521;

  static {
    USE_STD_CERT_EXTENSIONS.put(
        USEBASICCONSTRAINTS, Extension.basicConstraints.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEKEYUSAGE, Extension.keyUsage.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USESUBJECTKEYIDENTIFIER, Extension.subjectKeyIdentifier.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEAUTHORITYKEYIDENTIFIER, Extension.authorityKeyIdentifier.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USESUBJECTALTERNATIVENAME, Extension.subjectAlternativeName.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEISSUERALTERNATIVENAME, Extension.issuerAlternativeName.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USECRLDISTRIBUTIONPOINT, Extension.cRLDistributionPoints.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEFRESHESTCRL, Extension.freshestCRL.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USECERTIFICATEPOLICIES, Extension.certificatePolicies.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEEXTENDEDKEYUSAGE, Extension.extendedKeyUsage.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEDOCUMENTTYPELIST, "2.23.136.1.1.6.2");
    USE_STD_CERT_EXTENSIONS.put(
        USEQCSTATEMENT, Extension.qCStatements.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USENAMECONSTRAINTS, Extension.nameConstraints.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USESUBJECTDIRATTRIBUTES, Extension.subjectDirectoryAttributes.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEAUTHORITYINFORMATIONACCESS, Extension.authorityInfoAccess.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEPRIVKEYUSAGEPERIOD, Extension.privateKeyUsagePeriod.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEOCSPNOCHECK, OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
    USE_STD_CERT_EXTENSIONS.put(
        USEMICROSOFTTEMPLATE, CertTools.OID_MSTEMPLATE);
    USE_STD_CERT_EXTENSIONS.put(USECARDNUMBER, OID_CARDNUMBER);
  }

  // Public Methods

  /**
   * Creates a new instance of CertificateProfile. The default contructor
   * creates a basic CertificateProfile that is the same as an End User
   * certificateProfile, except that there are _no_ key usages. this means that
   * a certificate issued with a default profile should not be usable for
   * anything. Should be used for testing and where you want to create your own
   * CertificateProfile for specific purposes.
   */
  public CertificateProfile() {
    setCommonDefaults();
  }

  /**
   * Creates a new instance of CertificateProfile
   *
   * <p>These settings are general for all sub-profiles, only differing values
   * are overridden in the sub-profiles. If changing any present value here you
   * must therefore go through all sub-profiles and add an override there. I.e.
   * only add new values here, don't change any present settings.
   *
   * @param type one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for
   *     example CertificateConstants.CERTPROFILE_NO_PROFILE,
   *     CERTPROFILE_NO_ENDUSER, etc
   */
  public CertificateProfile(final int type) {
    setCommonDefaults();
    setDefaultValues(type);
  }

  private void setCommonDefaults() { // NOPMD: len
    setType(CertificateConstants.CERTTYPE_ENDENTITY);
    setCertificateVersion(VERSION_X509V3);
    setEncodedValidity(DEFAULT_CERTIFICATE_VALIDITY);
    setUseCertificateValidityOffset(false);
    setCertificateValidityOffset(DEFAULT_CERTIFICATE_VALIDITY_OFFSET);
    setUseExpirationRestrictionForWeekdays(false);
    setExpirationRestrictionForWeekdaysExpireBefore(true);
    setDefaultExpirationRestrictionWeekdays();
    setAllowValidityOverride(false);

    setAllowExtensionOverride(false);

    setAllowDNOverride(false);
    setAllowDNOverrideByEndEntityInformation(false);
    setAllowBackdatedRevocation(false);
    setUseCertificateStorage(true);
    setStoreCertificateData(true);
    setStoreSubjectAlternativeName(
        true); // New profiles created after EJBCA 6.6.0 will store SAN by
               // default

    setUseBasicConstraints(true);
    setBasicConstraintsCritical(true);

    setUseSubjectKeyIdentifier(true);
    setSubjectKeyIdentifierCritical(false);

    setUseAuthorityKeyIdentifier(true);
    setAuthorityKeyIdentifierCritical(false);

    setUseSubjectAlternativeName(true);
    setSubjectAlternativeNameCritical(false);

    setUseIssuerAlternativeName(true);
    setIssuerAlternativeNameCritical(false);

    setUseCRLDistributionPoint(false);
    setUseDefaultCRLDistributionPoint(false);
    setCRLDistributionPointCritical(false);
    setCRLDistributionPointURI("");
    setUseFreshestCRL(false);
    setUseCADefinedFreshestCRL(false);
    setFreshestCRLURI("");
    setCRLIssuer(null);

    setUseCertificatePolicies(false);
    setCertificatePoliciesCritical(false);
    ArrayList<CertificatePolicy> policies = new ArrayList<>();
    setCertificatePolicies(policies);

    setAvailableKeyAlgorithmsAsList(AlgorithmTools.getAvailableKeyAlgorithms());
    setAvailableEcCurvesAsList(Arrays.asList(ANY_EC_CURVE));
    setAvailableBitLengths(DEFAULTBITLENGTHS);
    setSignatureAlgorithm(null);

    setUseKeyUsage(true);
    setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
    setAllowKeyUsageOverride(false);
    setKeyUsageCritical(true);

    setUseExtendedKeyUsage(false);
    setExtendedKeyUsage(new ArrayList<String>());
    setExtendedKeyUsageCritical(false);

    setUseDocumentTypeList(false);
    setDocumentTypeListCritical(false);
    setDocumentTypeList(new ArrayList<String>());

    ArrayList<Integer> availablecas = new ArrayList<>();
    availablecas.add(Integer.valueOf(ANYCA));
    setAvailableCAs(availablecas);

    setPublisherList(new ArrayList<Integer>());

    setUseOcspNoCheck(false);

    setUseLdapDnOrder(true);
    setUseCustomDnOrder(false);

    setUseMicrosoftTemplate(false);
    setMicrosoftTemplate("");
    setUseCardNumber(false);

    setUseCNPostfix(false);
    setCNPostfix("");

    setUseSubjectDNSubSet(false);
    setSubjectDNSubSet(new ArrayList<String>());
    setUseSubjectAltNameSubSet(false);
    setSubjectAltNameSubSet(new ArrayList<Integer>());

    setUsePathLengthConstraint(false);
    setPathLengthConstraint(0);

    setUseQCStatement(false);
    setUsePkixQCSyntaxV2(false);
    setQCStatementCritical(false);
    setQCStatementRAName(null);
    setQCSemanticsId(null);
    setUseQCEtsiQCCompliance(false);
    setUseQCEtsiSignatureDevice(false);
    setUseQCEtsiValueLimit(false);
    setQCEtsiValueLimit(0);
    setQCEtsiValueLimitExp(0);
    setQCEtsiValueLimitCurrency(null);
    setUseQCEtsiRetentionPeriod(false);
    setQCEtsiRetentionPeriod(0);
    setUseQCCustomString(false);
    setQCCustomStringOid(null);
    setQCCustomStringText(null);
    setQCEtsiPds(null);
    setQCEtsiType(null);

    setUseCertificateTransparencyInCerts(false);
    setUseCertificateTransparencyInOCSP(false);
    setUseCertificateTransparencyInPublishers(false);

    setUseSubjectDirAttributes(false);
    setUseNameConstraints(false);
    setUseAuthorityInformationAccess(false);
    setCaIssuers(new ArrayList<String>());
    setUseDefaultCAIssuer(false);
    setUseDefaultOCSPServiceLocator(false);
    setOCSPServiceLocatorURI("");

    // Default to have access to fingerprint and iris
    setCVCAccessRights(CertificateProfile.CVC_ACCESS_DG3DG4);

    setUsedCertificateExtensions(new ArrayList<Integer>());
    setApprovals(new LinkedHashMap<ApprovalRequestType, Integer>());

    // PrivateKeyUsagePeriod extension
    setUsePrivateKeyUsagePeriodNotBefore(false);
    setUsePrivateKeyUsagePeriodNotAfter(false);
    setPrivateKeyUsagePeriodStartOffset(
        DEFAULT_PRIVATE_KEY_USAGE_PERIOD_OFFSET);
    setPrivateKeyUsagePeriodLength(DEFAULT_PRIVATE_KEY_USAGE_PERIOD_LENGTH);

    setSingleActiveCertificateConstraint(false);

    setOverridableExtensionOIDs(new LinkedHashSet<String>());
    setNonOverridableExtensionOIDs(new LinkedHashSet<String>());
  }

  /**
   * @param type one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for
   *     example CertificateConstants.CERTPROFILE_FIXED_ROOTCA
   */
  private void setDefaultValues(final int type) { // NOPMD: len
    if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA) {
      setType(CertificateConstants.CERTTYPE_ROOTCA);
      setAllowValidityOverride(true);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
      setKeyUsage(CertificateConstants.CRLSIGN, true);
      setKeyUsageCritical(true);
      setEncodedValidity(DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA);
    } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA) {
      setType(CertificateConstants.CERTTYPE_SUBCA);
      setAllowValidityOverride(true);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
      setKeyUsage(CertificateConstants.CRLSIGN, true);
      setKeyUsageCritical(true);
      setEncodedValidity(DEFAULT_CERTIFICATE_VALIDITY_FOR_FIXED_CA);
    } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      // Standard key usages for end users are: digitalSignature |
      // nonRepudiation, and/or (keyEncipherment or keyAgreement)
      // Default key usage is digitalSignature | nonRepudiation |
      // keyEncipherment
      // Create an array for KeyUsage according to X509Certificate.getKeyUsage()
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsage(CertificateConstants.NONREPUDIATION, true);
      setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_clientAuth.getId());
      eku.add(KeyPurposeId.id_kp_emailProtection.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
    } else if (type
        == CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      // Default key usage for an OCSP signer is digitalSignature
      // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_OCSPSigning.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
      setUseOcspNoCheck(true);
    } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SERVER) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      // Standard key usages for server are: digitalSignature | (keyEncipherment
      // or keyAgreement)
      // Default key usage is digitalSignature | keyEncipherment
      // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_serverAuth.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
    } else if (type
        == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_clientAuth.getId());
      eku.add(KeyPurposeId.id_kp_smartcardlogon.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
    } else if (type
        == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
      setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_clientAuth.getId());
      eku.add(KeyPurposeId.id_kp_emailProtection.getId());
      eku.add(KeyPurposeId.id_kp_smartcardlogon.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
    } else if (type
        == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_emailProtection.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
    } else if (type
        == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN) {
      setType(CertificateConstants.CERTTYPE_ENDENTITY);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[KEY_USAGE_LENGTH]);
      setKeyUsage(CertificateConstants.NONREPUDIATION, true);
      setKeyUsageCritical(true);
      setUseExtendedKeyUsage(true);
      ArrayList<String> eku = new ArrayList<>();
      eku.add(KeyPurposeId.id_kp_emailProtection.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
    }
  }

  // Public Methods.
  /**
   * @return the version of the certificate, should be one of the VERSION_
   *     constants defined in CertificateProfile class.
   */
  public String getCertificateVersion() {
    return (String) data.get(CERTVERSION);
  }

  /**
   * Sets the version of the certificate, should be one of the VERSION_
   * constants defined in CertificateProfile class.
   *
   * @param version version
   */
  public void setCertificateVersion(final String version) {
    data.put(CERTVERSION, version);
  }

  /**
   * @see ValidityDate#getDateBeforeVersion661(long, java.util.Date)
   * @return a long that is used to provide the end date of certificates for
   *     this profile, interpreted by ValidityDate#getDate
   * @deprecated since since EJBCA 6.6.1
   */
  @Deprecated
  public long getValidity() {
    return ((Long) data.get(VALIDITY)).longValue();
  }

  /**
   * Gets the encoded validity.
   *
   * @return the validity as ISO8601 date or relative time.
   * @see org.cesecore.util.ValidityDate ValidityDate
   * @see org.cesecore.util.SimpleTime SimpleTime
   */
  @SuppressWarnings("deprecation")
  public String getEncodedValidity() {
    String result = (String) data.get(ENCODED_VALIDITY);
    if (StringUtils.isBlank(result)) {
      result = ValidityDate.getStringBeforeVersion661(getValidity());
      setEncodedValidity(result);
    }
    return result;
  }

  /**
   * Sets the encoded validity .
   *
   * @param encodedValidity the validity as ISO8601 date or relative time.
   * @see org.cesecore.util.ValidityDate ValidityDate
   * @see org.cesecore.util.SimpleTime SimpleTime
   */
  public void setEncodedValidity(final String encodedValidity) {
    data.put(ENCODED_VALIDITY, encodedValidity);
  }

  /**
   * Gets the certificate validity offset.
   *
   * @return true if we should overwrite the default certificate validity offset
   *     with the one specified in the certificate profile.
   * @see #setCertificateValidityOffset
   */
  public boolean getUseCertificateValidityOffset() {
    // Extra null check to handle in-development upgrades
    if (data.get(USE_CERTIFICATE_VALIDITY_OFFSET) != null) {
      return Boolean.valueOf(
          (Boolean) data.get(USE_CERTIFICATE_VALIDITY_OFFSET));
    } else {
      return false;
    }
  }

  /**
   * Use certificate validity offset.
   *
   * @param enabled boolean
   */
  public void setUseCertificateValidityOffset(final boolean enabled) {
    data.put(USE_CERTIFICATE_VALIDITY_OFFSET, Boolean.valueOf(enabled));
  }

  /**
   * Gets the certificate validity offset.
   *
   * @return the offset as simple time string with seconds precision (i.e.
   *     '-10m')
   * @see org.cesecore.util.SimpleTime
   */
  public String getCertificateValidityOffset() {
    return (String) data.get(CERTIFICATE_VALIDITY_OFFSET);
  }

  /**
   * Sets the certificate not before offset.
   *
   * @param simpleTime the offset as simple time string with seconds precision.
   * @see org.cesecore.util.SimpleTime
   */
  public void setCertificateValidityOffset(final String simpleTime) {
    data.put(CERTIFICATE_VALIDITY_OFFSET, simpleTime);
  }

  /**
   * @return true if we should apply restrictions that certificate expiration
   *     can only occur on week days specified by
   *     setExpirationRestrictionWeekday
   * @see #setExpirationRestrictionWeekdays(boolean[])
   */
  public boolean getUseExpirationRestrictionForWeekdays() {
    return Boolean.valueOf(
        (Boolean) data.get(USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS));
  }

  /**
   * Use validity expiration restriction.
   *
   * @param enabled boolean
   */
  public void setUseExpirationRestrictionForWeekdays(final boolean enabled) {
    data.put(USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS, Boolean.valueOf(enabled));
  }

  /**
   * @return true if we should roll back expiration or false of we should roll
   *     forward expiration to match week days specified by
   *     setExpirationRestrictionWeekday
   * @see #setExpirationRestrictionWeekdays(boolean[])
   */
  public boolean getExpirationRestrictionForWeekdaysExpireBefore() {
    return Boolean.valueOf(
        (Boolean) data.get(EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE));
  }

  /**
   * Sets if the certificate validity shall expire earlier as requested if a the
   * expiration restriction was applied?
   *
   * @param enabled true, otherwise false.
   */
  public void setExpirationRestrictionForWeekdaysExpireBefore(
          final boolean enabled) {
    data.put(
        EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE, Boolean.valueOf(enabled));
  }

  /**
   * @param weekday (see java.util.Calendar.MONDAY - SUNDAY)
   * @return true if the weekday is selected as validity expiration restriction.
   */
  @SuppressWarnings("unchecked")
  public boolean getExpirationRestrictionWeekday(final int weekday) {
    return ((ArrayList<Boolean>) data.get(EXPIRATION_RESTRICTION_WEEKDAYS))
        .get(weekday - 1)
        .booleanValue();
  }

  /**
   * Include a weekday as validity expiration restriction.
   *
   * @param weekday (see java.util.Calendar.MONDAY - SUNDAY)
   * @param enabled boolean
   */
  @SuppressWarnings("unchecked")
  public void setExpirationRestrictionWeekday(
          final int weekday, final boolean enabled) {
    ((ArrayList<Boolean>) data.get(EXPIRATION_RESTRICTION_WEEKDAYS))
        .set(weekday - 1, Boolean.valueOf(enabled));
  }

  /**
   * Gets a copy of the List&lt;Boolean&gt; where validity restriction for
   * weekdays are stored.
   *
   * @return boolean array.
   */
  @SuppressWarnings("unchecked")
  public boolean[] getExpirationRestrictionWeekdays() {
    final ArrayList<Boolean> list =
        (ArrayList<Boolean>) data.get(EXPIRATION_RESTRICTION_WEEKDAYS);
    final boolean[] result = new boolean[list.size()];
    for (int i = 0; i < list.size(); i++) {
      result[i] = list.get(i).booleanValue();
    }
    return result;
  }

  private void setExpirationRestrictionWeekdays(final boolean[] weekdays) {
    final ArrayList<Boolean> list = new ArrayList<Boolean>(weekdays.length);
    for (int i = 0; i < weekdays.length; i++) {
      list.add(Boolean.valueOf(weekdays[i]));
    }
    data.put(EXPIRATION_RESTRICTION_WEEKDAYS, list);
  }

  private void setDefaultExpirationRestrictionWeekdays() {
    setExpirationRestrictionWeekdays(new boolean[DAYS_IN_WEEK]);
    setExpirationRestrictionWeekday(Calendar.MONDAY, true);
    setExpirationRestrictionWeekday(Calendar.FRIDAY, true);
    setExpirationRestrictionWeekday(Calendar.SATURDAY, true);
    setExpirationRestrictionWeekday(Calendar.SUNDAY, true);
  }

  /**
   * If validity override is allowed, a certificate can have a shorter validity
   * than the one specified in the certificate profile, but never longer. A
   * certificate created with validity override can hava a starting point in the
   * future.
   *
   * @return true if validity override is allowed
   */
  public boolean getAllowValidityOverride() {
    return ((Boolean) data.get(ALLOWVALIDITYOVERRIDE)).booleanValue();
  }

  /**
   * If validity override is allowed, a certificate can have a shorter validity
   * than the one specified in the certificate profile, but never longer. A
   * certificate created with validity override can hava a starting point in the
   * future.
   *
   * @param allowvalidityoverride boolean
   */
  public void setAllowValidityOverride(final boolean allowvalidityoverride) {
    data.put(ALLOWVALIDITYOVERRIDE, Boolean.valueOf(allowvalidityoverride));
  }

  /**
   * If extension override is allowed, the X509 certificate extension created in
   * a certificate can come from the request sent by the user. If the request
   * contains an extension than will be used instead of the one defined in the
   * profile. If the request does not contain an extension, the one defined in
   * the profile will be used.
   *
   * @return boolean
   */
  public boolean getAllowExtensionOverride() {
    Object d = data.get(ALLOWEXTENSIONOVERRIDE);
    if (d == null) {
      return false;
    }
    return ((Boolean) d).booleanValue();
  }

  /**
   * @param allowextensionoverride boolean
   * @see #getAllowExtensionOverride()
   */
  public void setAllowExtensionOverride(final boolean allowextensionoverride) {
    data.put(ALLOWEXTENSIONOVERRIDE, Boolean.valueOf(allowextensionoverride));
  }

  /**
   * If DN override is allowed, the X509 subject DN extension created in a
   * certificate can come directly from the CSR in the request sent by the user.
   * This is instead of the normal way where the user's registered DN is used.
   *
   * @return boolean
   */
  public boolean getAllowDNOverride() {
    Object d = data.get(ALLOWDNOVERRIDE);
    if (d == null) {
      return false;
    }
    return ((Boolean) d).booleanValue();
  }

  /**
   * @param allowdnoverride boolean
   * @see #getAllowDNOverride()
   */
  public void setAllowDNOverride(final boolean allowdnoverride) {
    data.put(ALLOWDNOVERRIDE, Boolean.valueOf(allowdnoverride));
  }

  /**
   * If DN override by End Entity Information is allowed, the X509 subject DN
   * extension created in a certificate can come directly from the request meta
   * information sent by the user. This is instead of the normal way where the
   * user's registered DN is used.
   *
   * @return boolean
   */
  public boolean getAllowDNOverrideByEndEntityInformation() {
    Object d = data.get(ALLOWDNOVERRIDEBYEEI);
    if (d == null) {
      return false;
    }
    return ((Boolean) d).booleanValue();
  }

  /**
   * @param value boolean
   * @see #getAllowDNOverrideByEndEntityInformation()
   */
  public void setAllowDNOverrideByEndEntityInformation(final boolean value) {
    data.put(ALLOWDNOVERRIDEBYEEI, Boolean.valueOf(value));
  }

  /**
   * If override is allowed the serial number could be specified.
   *
   * @return true if allowed
   */
  public boolean getAllowCertSerialNumberOverride() {
    Object d = data.get(ALLOWCERTSNOVERIDE);
    if (d == null) {
      return false;
    }
    return ((Boolean) d).booleanValue();
  }

  /**
   * @see #getAllowDNOverride()
   * @param allowdnoverride new value
   */
  public void setAllowCertSerialNumberOverride(final boolean allowdnoverride) {
    data.put(ALLOWCERTSNOVERIDE, Boolean.valueOf(allowdnoverride));
  }

  /**
   * @return bool
   */
  public boolean getUseBasicConstraints() {
    return ((Boolean) data.get(USEBASICCONSTRAINTS)).booleanValue();
  }

  /**
   * @param usebasicconstraints bool
   */
  public void setUseBasicConstraints(final boolean usebasicconstraints) {
    data.put(USEBASICCONSTRAINTS, Boolean.valueOf(usebasicconstraints));
  }

  /**
   * @return bool
   */
  public boolean getBasicConstraintsCritical() {
    return ((Boolean) data.get(BASICCONSTRAINTSCRITICAL)).booleanValue();
  }

  /**
   * @param basicconstraintscritical bool
   */
  public void setBasicConstraintsCritical(
          final boolean basicconstraintscritical) {
    data.put(
        BASICCONSTRAINTSCRITICAL, Boolean.valueOf(basicconstraintscritical));
  }

  /**
   * @return bool
   */
  public boolean getUseKeyUsage() {
    return ((Boolean) data.get(USEKEYUSAGE)).booleanValue();
  }

  /**
   * @param usekeyusage bool
   */
  public void setUseKeyUsage(final boolean usekeyusage) {
    data.put(USEKEYUSAGE, Boolean.valueOf(usekeyusage));
  }

  /**
   * @return bool
   */
  public boolean getKeyUsageCritical() {
    return ((Boolean) data.get(KEYUSAGECRITICAL)).booleanValue();
  }

  /**
   * @param keyusagecritical bool
   */
  public void setKeyUsageCritical(
          final boolean keyusagecritical) {
    data.put(KEYUSAGECRITICAL, Boolean.valueOf(keyusagecritical));
  }

  /**
   * @return bool
   */
  public boolean getUseSubjectKeyIdentifier() {
    return ((Boolean) data.get(USESUBJECTKEYIDENTIFIER)).booleanValue();
  }

  /**
   * @param usesubjectkeyidentifier bool
   */
  public void setUseSubjectKeyIdentifier(
          final boolean usesubjectkeyidentifier) {
    data.put(USESUBJECTKEYIDENTIFIER, Boolean.valueOf(usesubjectkeyidentifier));
  }

  /**
   * @return bool
   */
  public boolean getSubjectKeyIdentifierCritical() {
    return ((Boolean) data.get(SUBJECTKEYIDENTIFIERCRITICAL)).booleanValue();
  }

  /**
   * @param subjectkeyidentifiercritical bool
   */
  public void setSubjectKeyIdentifierCritical(
      final boolean subjectkeyidentifiercritical) {
    data.put(
        SUBJECTKEYIDENTIFIERCRITICAL,
        Boolean.valueOf(subjectkeyidentifiercritical));
  }

  /**
   * @return bool
   */
  public boolean getUseAuthorityKeyIdentifier() {
    return ((Boolean) data.get(USEAUTHORITYKEYIDENTIFIER)).booleanValue();
  }

  /**
   * @param useauthoritykeyidentifier bool
   */
  public void setUseAuthorityKeyIdentifier(
          final boolean useauthoritykeyidentifier) {
    data.put(
        USEAUTHORITYKEYIDENTIFIER, Boolean.valueOf(useauthoritykeyidentifier));
  }

  /**
   * @return bool
   */
  public boolean getAuthorityKeyIdentifierCritical() {
    return ((Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue();
  }

  /**
   * @param authoritykeyidentifiercritical bool
   */
  public void setAuthorityKeyIdentifierCritical(
     final  boolean authoritykeyidentifiercritical) {
    data.put(
        AUTHORITYKEYIDENTIFIERCRITICAL,
        Boolean.valueOf(authoritykeyidentifiercritical));
  }

  /**
   * @return bool
   */
  public boolean getUseSubjectAlternativeName() {
    return ((Boolean) data.get(USESUBJECTALTERNATIVENAME)).booleanValue();
  }

  /**
   * @param usesubjectalternativename bool
   */
  public void setUseSubjectAlternativeName(
          final boolean usesubjectalternativename) {
    data.put(
        USESUBJECTALTERNATIVENAME, Boolean.valueOf(usesubjectalternativename));
  }

  /**
   * @return bool
   */
  public boolean getStoreCertificateData() {
    // Lazy upgrade for profiles created prior to EJBCA 6.2.10
    final Boolean value = (Boolean) data.get(STORECERTIFICATEDATA);
    if (value == null) {
      // Default for existing profiles is true
      setStoreCertificateData(true);
      return true;
    } else {
      return value.booleanValue();
    }
  }

  /**
   * @param storeCertificateData bool
   */
  public void setStoreCertificateData(final boolean storeCertificateData) {
    data.put(STORECERTIFICATEDATA, Boolean.valueOf(storeCertificateData));
  }

  /**
   * @return true if the CertificateData.subjectAltName column should be
   *     populated.
   */
  public boolean getStoreSubjectAlternativeName() {
    // Lazy upgrade for profiles created prior to EJBCA 6.6.0
    final Boolean value = (Boolean) data.get(STORESUBJECTALTNAME);
    if (value == null) {
      // Old profiles created before EJBCA 6.6.0 will not store SAN by default.
      setStoreSubjectAlternativeName(false);
      return false;
    } else {
      return value.booleanValue();
    }
  }

  /**
   * @param storeSubjectAlternativeName bool
   */
  public void setStoreSubjectAlternativeName(
      final boolean storeSubjectAlternativeName) {
    data.put(STORESUBJECTALTNAME, Boolean.valueOf(storeSubjectAlternativeName));
  }

  /**
   * @return bool
   */
  public boolean getSubjectAlternativeNameCritical() {
    return ((Boolean) data.get(SUBJECTALTERNATIVENAMECRITICAL)).booleanValue();
  }

  /**
   * @param subjectalternativenamecritical bool
   */
  public void setSubjectAlternativeNameCritical(
      final boolean subjectalternativenamecritical) {
    data.put(
        SUBJECTALTERNATIVENAMECRITICAL,
        Boolean.valueOf(subjectalternativenamecritical));
  }

  /**
   * @return bool
   */
  public boolean getUseIssuerAlternativeName() {
    return ((Boolean) data.get(USEISSUERALTERNATIVENAME)).booleanValue();
  }

  /**
   * @param useissueralternativename bool
   */
  public void setUseIssuerAlternativeName(
          final boolean useissueralternativename) {
    data.put(
        USEISSUERALTERNATIVENAME, Boolean.valueOf(useissueralternativename));
  }

  /**
   * @return bool
   */
  public boolean getIssuerAlternativeNameCritical() {
    return ((Boolean) data.get(ISSUERALTERNATIVENAMECRITICAL)).booleanValue();
  }

  /**
   * @param issueralternativenamecritical bool
   */
  public void setIssuerAlternativeNameCritical(
      final boolean issueralternativenamecritical) {
    data.put(
        ISSUERALTERNATIVENAMECRITICAL,
        Boolean.valueOf(issueralternativenamecritical));
  }

  /**
   * @return bool
   */
  public boolean getUseCRLDistributionPoint() {
    return ((Boolean) data.get(USECRLDISTRIBUTIONPOINT)).booleanValue();
  }

  /**
   * @param usecrldistributionpoint bool
   */
  public void setUseCRLDistributionPoint(
          final boolean usecrldistributionpoint) {
    data.put(USECRLDISTRIBUTIONPOINT, Boolean.valueOf(usecrldistributionpoint));
  }

  /**
   * @return bool
   */
  public boolean getUseDefaultCRLDistributionPoint() {
    return ((Boolean) data.get(USEDEFAULTCRLDISTRIBUTIONPOINT)).booleanValue();
  }

  /**
   * @param usedefaultcrldistributionpoint bool
   */
  public void setUseDefaultCRLDistributionPoint(
      final boolean usedefaultcrldistributionpoint) {
    data.put(
        USEDEFAULTCRLDISTRIBUTIONPOINT,
        Boolean.valueOf(usedefaultcrldistributionpoint));
  }

  /**
   * @return bool
   */
  public boolean getCRLDistributionPointCritical() {
    return ((Boolean) data.get(CRLDISTRIBUTIONPOINTCRITICAL)).booleanValue();
  }

  /**
   * @param crldistributionpointcritical bool
   */
  public void setCRLDistributionPointCritical(
      final boolean crldistributionpointcritical) {
    data.put(
        CRLDISTRIBUTIONPOINTCRITICAL,
        Boolean.valueOf(crldistributionpointcritical));
  }

  /**
   * @return URI
   */
  public String getCRLDistributionPointURI() {
    return (String) data.get(CRLDISTRIBUTIONPOINTURI);
  }

  /**
   * @param crldistributionpointuri URI
   */
  public void setCRLDistributionPointURI(final String crldistributionpointuri) {
    if (crldistributionpointuri == null) {
      data.put(CRLDISTRIBUTIONPOINTURI, "");
    } else {
      data.put(CRLDISTRIBUTIONPOINTURI, crldistributionpointuri);
    }
  }

  /**
   * @return bool
   */
  public String getCRLIssuer() {
    return (String) data.get(CRLISSUER);
  }

  /**
   * @param crlissuer issuer
   */
  public void setCRLIssuer(final String crlissuer) {
    if (crlissuer == null) {
      data.put(CRLISSUER, "");
    } else {
      data.put(CRLISSUER, crlissuer);
    }
  }

  /**
   * @return bool
   */
  public boolean getUseFreshestCRL() {
    Object obj = data.get(USEFRESHESTCRL);
    if (obj == null) {
      return false;
    } else {
      return ((Boolean) obj).booleanValue();
    }
  }

  /**
   * @param usefreshestcrl bool
   */
  public void setUseFreshestCRL(final boolean usefreshestcrl) {
    data.put(USEFRESHESTCRL, Boolean.valueOf(usefreshestcrl));
  }

  /**
   * @return bool
   */
  public boolean getUseCADefinedFreshestCRL() {
    Object obj = data.get(USECADEFINEDFRESHESTCRL);
    if (obj == null) {
      return false;
    } else {
      return ((Boolean) obj).booleanValue();
    }
  }

  /**
   * @param usecadefinedfreshestcrl bool
   */
  public void setUseCADefinedFreshestCRL(
          final boolean usecadefinedfreshestcrl) {
    data.put(USECADEFINEDFRESHESTCRL, Boolean.valueOf(usecadefinedfreshestcrl));
  }

  /**
   * @return URI
   */
  public String getFreshestCRLURI() {
    return (String) data.get(FRESHESTCRLURI);
  }

  /**
   * @param freshestcrluri URI
   */
  public void setFreshestCRLURI(final String freshestcrluri) {
    if (freshestcrluri == null) {
      data.put(FRESHESTCRLURI, "");
    } else {
      data.put(FRESHESTCRLURI, freshestcrluri);
    }
  }

  /**
   * @return bool
   */
  public boolean getUseCertificatePolicies() {
    return ((Boolean) data.get(USECERTIFICATEPOLICIES)).booleanValue();
  }

  /**
   * @param usecertificatepolicies bool
   */
  public void setUseCertificatePolicies(final boolean usecertificatepolicies) {
    data.put(USECERTIFICATEPOLICIES, Boolean.valueOf(usecertificatepolicies));
  }

  /**
   * @return bool
   */
  public boolean getUseCertificateStorage() {
    // Lazy upgrade for profiles created prior to EJBCA 6.2.10
    Boolean value = (Boolean) data.get(USECERTIFICATESTORAGE);
    if (value == null) {
      // Default is true
      setUseCertificateStorage(true);
      return true;
    } else {
      return value.booleanValue();
    }
  }

  /**
   * @param useCertificateStorage bool
   */
  public void setUseCertificateStorage(final boolean useCertificateStorage) {
    data.put(USECERTIFICATESTORAGE, Boolean.valueOf(useCertificateStorage));
  }

  /**
   * @return bool
   */
  public boolean getCertificatePoliciesCritical() {
    return ((Boolean) data.get(CERTIFICATEPOLICIESCRITICAL)).booleanValue();
  }

  /**
   * @param certificatepoliciescritical bool
   */
  public void setCertificatePoliciesCritical(
      final boolean certificatepoliciescritical) {
    data.put(
        CERTIFICATEPOLICIESCRITICAL,
        Boolean.valueOf(certificatepoliciescritical));
  }

  /**
   * @return policies
   */
  public List<CertificatePolicy> getCertificatePolicies() {
    @SuppressWarnings("unchecked")
    List<CertificatePolicy> l =
        (List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES);
    if (l == null) {
      l = new ArrayList<CertificatePolicy>();
    } else {
      // Check class name, because we changed this in EJBCA 5 and need to
      // support older versions in the database for 100% upgrade
      if (l.size() > 0) {
        try {
          // Don't remove the unused test object
          CertificatePolicy test =
              l.get(
                  0); // NOPMD: we need to actually get the text object,
                      // otherwise the cast will not be tried
          test.getPolicyID();
        } catch (ClassCastException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "CertificatePolicy in profile is old class name (< EJBCA 5),"
                    + " post-upgrade has not been run. Converting in code to"
                    + " return new class type.");
          }
          @SuppressWarnings("unchecked")
          List<Object> oldl = (List<Object>) data.get(CERTIFICATE_POLICIES);
          // In worst case they can have mixed old and new classes, therefore we
          // use a "normal" iterator so we can verify the cast
          l = new ArrayList<CertificatePolicy>();
          for (int i = 0; i < oldl.size(); i++) {
            try {
              org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy
                  oldPol =
                      (org.ejbca.core.model.ca.certificateprofiles
                              .CertificatePolicy)
                          oldl.get(i);
              CertificatePolicy newPol =
                  new CertificatePolicy(
                      oldPol.getPolicyID(),
                      oldPol.getQualifierId(),
                      oldPol.getQualifier());
              if (LOG.isTraceEnabled()) {
                LOG.trace("Adding converted policy");
              }
              l.add(newPol);
            } catch (ClassCastException e2) {
              // This was already a new class, there are mixed policies here...
              CertificatePolicy newPol = (CertificatePolicy) oldl.get(i);
              if (LOG.isTraceEnabled()) {
                LOG.trace("Adding non-converted policy");
              }
              l.add(newPol);
            }
          }
        }
      }
    }
    return l;
  }

  /**
   * @param policy policy
   */
  @SuppressWarnings("unchecked")
  public void addCertificatePolicy(final CertificatePolicy policy) {
    if (data.get(CERTIFICATE_POLICIES) == null) {
      setCertificatePolicies(new ArrayList<CertificatePolicy>());
    }
    ((List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES)).add(policy);
  }

  /**
   * @param policies Policies
   */
  public void setCertificatePolicies(final List<CertificatePolicy> policies) {
    if (policies == null) {
      data.put(CERTIFICATE_POLICIES, new ArrayList<CertificatePolicy>(0));
    } else {
      data.put(CERTIFICATE_POLICIES, policies);
    }
  }

  /**
   * @param policy Policy
   */
  @SuppressWarnings("unchecked")
  public void removeCertificatePolicy(final CertificatePolicy policy) {
    if (data.get(CERTIFICATE_POLICIES) != null) {
      ((List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES)).remove(policy);
    }
  }

  /**
   * Type is used when setting BasicConstraints, i.e. to determine if it is a CA
   * or an end entity
   *
   * @return type
   * @see CertificateConstants#CERTTYPE_ROOTCA etc
   */
  public int getType() {
    return ((Integer) data.get(TYPE)).intValue();
  }

  /**
   * Type is used when setting BasicConstraints, i.e. to determine if it is a CA
   * or an end entity
   *
   * @param type type
   * @see CertificateConstants#CERTTYPE_ROOTCA etc
   */
  public void setType(final int type) {
    data.put(TYPE, Integer.valueOf(type));
  }

  /**
   * @return bool
   */
  public boolean isTypeSubCA() {
    return ((Integer) data.get(TYPE)).intValue()
        == CertificateConstants.CERTTYPE_SUBCA;
  }

  /**
   * @return bool
   */
  public boolean isTypeRootCA() {
    return ((Integer) data.get(TYPE)).intValue()
        == CertificateConstants.CERTTYPE_ROOTCA;
  }

  /**
   * @return bool
   */
  public boolean isTypeEndEntity() {
    return ((Integer) data.get(TYPE)).intValue()
        == CertificateConstants.CERTTYPE_ENDENTITY;
  }

  /**
   * @return algos
   */
  public String[] getAvailableKeyAlgorithms() {
    final List<String> availableKeyAlgorithms =
        getAvailableKeyAlgorithmsAsList();
    return availableKeyAlgorithms.toArray(
        new String[availableKeyAlgorithms.size()]);
  }

  /**
   * @return Algos
   */
  @SuppressWarnings("unchecked")
  public List<String> getAvailableKeyAlgorithmsAsList() {
    return (ArrayList<String>) data.get(AVAILABLEKEYALGORITHMS);
  }

  /**
   * @param availableKeyAlgorithms Algos
   */
  public void setAvailableKeyAlgorithms(final String[] availableKeyAlgorithms) {
    setAvailableKeyAlgorithmsAsList(Arrays.asList(availableKeyAlgorithms));
  }

  /**
   * @param availableKeyAlgorithms Algos
   */
  public void setAvailableKeyAlgorithmsAsList(
      final List<String> availableKeyAlgorithms) {
    data.put(AVAILABLEKEYALGORITHMS, new ArrayList<>(availableKeyAlgorithms));
  }

  /**
   * @return curves
   */
  public String[] getAvailableEcCurves() {
    final List<String> availableEcCurves = getAvailableEcCurvesAsList();
    return availableEcCurves.toArray(new String[availableEcCurves.size()]);
  }

  /**
   * @return curves
   */
  @SuppressWarnings("unchecked")
  public List<String> getAvailableEcCurvesAsList() {
    return (ArrayList<String>) data.get(AVAILABLEECCURVES);
  }

  /**
   * @param availableEcCurves Curves
   */
  public void setAvailableEcCurves(final String[] availableEcCurves) {
    setAvailableEcCurvesAsList(Arrays.asList(availableEcCurves));
  }

  /**
   * @param availableEcCurves Curves
   */
  public void setAvailableEcCurvesAsList(final List<String> availableEcCurves) {
    data.put(AVAILABLEECCURVES, new ArrayList<>(availableEcCurves));
  }

  /**
   * @return lengths
   */
  public int[] getAvailableBitLengths() {
    final List<Integer> availablebitlengths = getAvailableBitLengthsAsList();
    final int[] returnval = new int[availablebitlengths.size()];
    for (int i = 0; i < availablebitlengths.size(); i++) {
      returnval[i] = availablebitlengths.get(i).intValue();
    }
    return returnval;
  }

  /**
   * @return lengths
   */
  @SuppressWarnings("unchecked")
  public List<Integer> getAvailableBitLengthsAsList() {
    return (ArrayList<Integer>) data.get(AVAILABLEBITLENGTHS);
  }

  /**
   * @param availablebitlengths lengths
   */
  public void setAvailableBitLengths(final List<Integer> availablebitlengths) {
    // Strange values here, but it makes the <> below work for sure
    int minimumavailablebitlength = 99999999;
    int maximumavailablebitlength = 0;

    for (int i = 0; i < availablebitlengths.size(); i++) {
      if (availablebitlengths.get(i) > maximumavailablebitlength) {
        maximumavailablebitlength = availablebitlengths.get(i);
      }
      if (availablebitlengths.get(i) < minimumavailablebitlength) {
        minimumavailablebitlength = availablebitlengths.get(i);
      }
    }
    data.put(AVAILABLEBITLENGTHS, availablebitlengths);
    data.put(
        MINIMUMAVAILABLEBITLENGTH, Integer.valueOf(minimumavailablebitlength));
    data.put(
        MAXIMUMAVAILABLEBITLENGTH, Integer.valueOf(maximumavailablebitlength));
  }

  /**
   * @param availablebitlengths lengths
   */
  public void setAvailableBitLengths(final int[] availablebitlengths) {
    ArrayList<Integer> availbitlengths =
        new ArrayList<>(availablebitlengths.length);

    for (int i = 0; i < availablebitlengths.length; i++) {
      availbitlengths.add(Integer.valueOf(availablebitlengths[i]));
    }
    setAvailableBitLengths(availbitlengths);
  }

  /**
   * @return length
   */
  public int getMinimumAvailableBitLength() {
    return ((Integer) data.get(MINIMUMAVAILABLEBITLENGTH)).intValue();
  }

  /**
   * @return length
   */
  public int getMaximumAvailableBitLength() {
    return ((Integer) data.get(MAXIMUMAVAILABLEBITLENGTH)).intValue();
  }

  /**
   * @param keyAlgorithm Algorithm
   * @param keySpecification Spec
   * @return true if the given combination of keyAlgorithm/keySpecification is
   *     allowed by this certificate profile.
   */
  public boolean isKeyTypeAllowed(
      final String keyAlgorithm, final String keySpecification) {
    final List<String> availableKeyAlgorithms =
        getAvailableKeyAlgorithmsAsList();
    final List<Integer> availableBitLengths = getAvailableBitLengthsAsList();
    final List<String> availableEcCurves = getAvailableEcCurvesAsList();
    if (!availableKeyAlgorithms.contains(keyAlgorithm)) {
      return false;
    }
    if (StringUtils.isNumeric(keySpecification)) {
      // keySpecification is a bit length (RSA)
      return availableBitLengths.contains(Integer.parseInt(keySpecification));
    } else {
      // keySpecification is a curve name (EC)
      return availableEcCurves.contains(keySpecification)
          || availableEcCurves.contains(CertificateProfile.ANY_EC_CURVE);
    }
  }

  /**
   * Returns the chosen algorithm to be used for signing the certificates or
   * null if it is to be inherited from the CA (i.e., it is the same as the
   * algorithm used to sign the CA certificate).
   *
   * @see org.cesecore.certificates.util.AlgorithmConstants#AVAILABLE_SIGALGS
   * @return JCE identifier for the signature algorithm or null if it is to be
   *     inherited from the CA (i.e., it is the same as the algorithm used to
   *     sign the CA certificate).
   */
  public String getSignatureAlgorithm() {
    // If it's null, it is inherited from issuing CA.
    return (String) data.get(SIGNATUREALGORITHM);
  }

  /**
   * Sets the algorithm to be used for signing the certificates. A null value
   * means that the signature algorithm is to be inherited from the CA (i.e., it
   * is the same as the algorithm used to sign the CA certificate).
   *
   * @param signAlg JCE identifier for the signature algorithm or null if it is
   *     to be inherited from the CA (i.e., it is the same as the algorithm used
   *     to sign the CA certificate).
   * @see org.cesecore.certificates.util.AlgorithmConstants#AVAILABLE_SIGALGS
   */
  public void setSignatureAlgorithm(final String signAlg) {
    data.put(SIGNATUREALGORITHM, signAlg);
  }

  /**
   * @return usage
   */
  public boolean[] getKeyUsage() {
    @SuppressWarnings("unchecked")
    ArrayList<Boolean> keyusage = (ArrayList<Boolean>) data.get(KEYUSAGE);
    boolean[] returnval = new boolean[keyusage.size()];
    for (int i = 0; i < keyusage.size(); i++) {
      returnval[i] = keyusage.get(i).booleanValue();
    }
    return returnval;
  }

  /**
   * @param keyusageconstant from CertificateConstants.DIGITALSIGNATURE etc
   * @return true or false if the key usage is set or not.
   */
  @SuppressWarnings("unchecked")
  public boolean getKeyUsage(final int keyusageconstant) {
    return ((ArrayList<Boolean>) data.get(KEYUSAGE))
        .get(keyusageconstant)
        .booleanValue();
  }

  /**
   * @param keyusage usage
   */
  public void setKeyUsage(final boolean[] keyusage) {
    ArrayList<Boolean> keyuse = new ArrayList<Boolean>(keyusage.length);

    for (int i = 0; i < keyusage.length; i++) {
      keyuse.add(Boolean.valueOf(keyusage[i]));
    }
    data.put(KEYUSAGE, keyuse);
  }

  /**
   * @param keyusageconstant from CertificateConstants.DIGITALSIGNATURE etc
   * @param value true or false if the key usage is set or not.
   */
  @SuppressWarnings("unchecked")
  public void setKeyUsage(final int keyusageconstant, final boolean value) {
    ((ArrayList<Boolean>) data.get(KEYUSAGE))
        .set(keyusageconstant, Boolean.valueOf(value));
  }

  /**
   * @param override bool
   */
  public void setAllowKeyUsageOverride(final boolean override) {
    data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.valueOf(override));
  }

  /**
   * @return bool
   */
  public boolean getAllowKeyUsageOverride() {
    return ((Boolean) data.get(ALLOWKEYUSAGEOVERRIDE)).booleanValue();
  }

  /**
   * @param override bool
   */
  public void setAllowBackdatedRevocation(final boolean override) {
    this.data.put(ALLOWBACKDATEDREVOCATION, Boolean.valueOf(override));
  }

  /**
   * @return bool
   */
  public boolean getAllowBackdatedRevocation() {
    final Object value = this.data.get(ALLOWBACKDATEDREVOCATION);
    return value != null
        && value instanceof Boolean
        && ((Boolean) value).booleanValue();
  }

  /**
   * @param use bool
   */
  public void setUseDocumentTypeList(final boolean use) {
    data.put(USEDOCUMENTTYPELIST, Boolean.valueOf(use));
  }

  /**
   * @return bool
   */
  public boolean getUseDocumentTypeList() {
    return ((Boolean) data.get(USEDOCUMENTTYPELIST)).booleanValue();
  }

  /**
   * @param critical bool
   */
  public void setDocumentTypeListCritical(final boolean critical) {
    data.put(DOCUMENTTYPELISTCRITICAL, Boolean.valueOf(critical));
  }

  /**
   * @return bool
   */
  public boolean getDocumentTypeListCritical() {
    return ((Boolean) data.get(DOCUMENTTYPELISTCRITICAL)).booleanValue();
  }

  /**
   * @param docTypes types
   */
  public void setDocumentTypeList(final ArrayList<String> docTypes) {
    data.put(DOCUMENTTYPELIST, docTypes);
  }

  /**
   * @return types
   */
  @SuppressWarnings("unchecked")
  public ArrayList<String> getDocumentTypeList() {
    return (ArrayList<String>) data.get(DOCUMENTTYPELIST);
  }

  /**
   * @param use bool
   */
  public void setUseExtendedKeyUsage(final boolean use) {
    data.put(USEEXTENDEDKEYUSAGE, Boolean.valueOf(use));
  }

  /**
   * @return bool
   */
  public boolean getUseExtendedKeyUsage() {
    return ((Boolean) data.get(USEEXTENDEDKEYUSAGE)).booleanValue();
  }

  /**
   * @param critical bool
   */
  public void setExtendedKeyUsageCritical(final boolean critical) {
    data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.valueOf(critical));
  }

  /**
   * @return bool
   */
  public boolean getExtendedKeyUsageCritical() {
    return ((Boolean) data.get(EXTENDEDKEYUSAGECRITICAL)).booleanValue();
  }

  /**
   * Extended Key Usage is an arraylist of oid Strings. Usually oids comes from
   * KeyPurposeId in BC.
   *
   * @param extendedkeyusage oid strings
   */
  public void setExtendedKeyUsage(final ArrayList<String> extendedkeyusage) {
    data.put(EXTENDEDKEYUSAGE, extendedkeyusage);
  }

  /**
   * Extended Key Usage is an arraylist of Strings with eku oids.
   *
   * @return oid strings
   */
  @SuppressWarnings("unchecked")
  public ArrayList<String> getExtendedKeyUsageOids() {
    return (ArrayList<String>) data.get(EXTENDEDKEYUSAGE);
  }

  /**
   * @param extendedKeyUsageOids OIDs
   */
  public void setExtendedKeyUsageOids(
      final ArrayList<String> extendedKeyUsageOids) {
    setExtendedKeyUsage(extendedKeyUsageOids);
  }

  /**
   * @param use bool
   */
  public void setUseCustomDnOrder(final boolean use) {
    data.put(USECUSTOMDNORDER, Boolean.valueOf(use));
  }

  /**
   * @return bool
   */
  public boolean getUseCustomDnOrder() {
    boolean ret = false; // Default value is false here
    Object o = data.get(USECUSTOMDNORDER);
    if (o != null) {
      ret = ((Boolean) o).booleanValue();
    }
    return ret;
  }

  /**
   * Set to true if we should apply the rules for LDAP DN Order (separate flag)
   * to the custom DN order.
   *
   * @param useldap true or false
   */
  public void setUseCustomDnOrderWithLdap(final boolean useldap) {
    data.put(USECUSTOMDNORDERLDAP, Boolean.valueOf(useldap));
  }

  /**
   * @return true if we should apply the rules for LDAP DN Order (separate
   *     flag), default to false for new usage, where no custom order exists,
   *     and to true for old usage to be backward compatible
   */
  public boolean getUseCustomDnOrderWithLdap() {
    boolean ret = true; // Default value is true here
    Object o = data.get(USECUSTOMDNORDERLDAP);
    if (o != null) {
      ret = ((Boolean) o).booleanValue();
    } else if (getCustomDnOrder().isEmpty()) {
      // We have not set a value for this checkbox, and we have no custom DN
      // order defined
      // in this case we default to false (new usage)
      ret = false;
    }
    return ret;
  }

  /**
   * Custom DN order is an ArrayList of DN strings.
   *
   * @see DnComponents
   * @return ArrayList of Strings or an empty ArrayList
   */
  @SuppressWarnings("unchecked")
  public ArrayList<String> getCustomDnOrder() {
    if (data.get(CUSTOMDNORDER) == null) {
      return new ArrayList<>();
    }
    return (ArrayList<String>) data.get(CUSTOMDNORDER);
  }

  /**
   * @param dnOrder Order
   */
  public void setCustomDnOrder(final ArrayList<String> dnOrder) {
    data.put(CUSTOMDNORDER, dnOrder);
  }

  /**
   * @return bool
   */
  public boolean getUseLdapDnOrder() {
    boolean ret = true; // Default value is true here
    Object o = data.get(USELDAPDNORDER);
    if (o != null) {
      ret = ((Boolean) o).booleanValue();
    }
    return ret;
  }

  /**
   * @param use bool
   */
  public void setUseLdapDnOrder(final boolean use) {
    data.put(USELDAPDNORDER, Boolean.valueOf(use));
  }

  /**
   * @return bool
   */
  public boolean getUseMicrosoftTemplate() {
    return ((Boolean) data.get(USEMICROSOFTTEMPLATE)).booleanValue();
  }

  /**
   * @param use bool
   */
  public void setUseMicrosoftTemplate(final boolean use) {
    data.put(USEMICROSOFTTEMPLATE, Boolean.valueOf(use));
  }

  /**
   * @return template
   */
  public String getMicrosoftTemplate() {
    return (String) data.get(MICROSOFTTEMPLATE);
  }

  /**
   * @param mstemplate template
   */
  public void setMicrosoftTemplate(final String mstemplate) {
    data.put(MICROSOFTTEMPLATE, mstemplate);
  }
  /**
   * @return bool
   */
  public boolean getUseCardNumber() {
    return ((Boolean) data.get(USECARDNUMBER)).booleanValue();
  }

  /**
   * @param use bool
   */
  public void setUseCardNumber(final boolean use) {
    data.put(USECARDNUMBER, Boolean.valueOf(use));
  }

  /**
   * @return bool
   */
  public boolean getUseCNPostfix() {
    return ((Boolean) data.get(USECNPOSTFIX)).booleanValue();
  }

  /**
   * @param use bool
   */
  public void setUseCNPostfix(final boolean use) {
    data.put(USECNPOSTFIX, Boolean.valueOf(use));
  }

  /**
   * @return postfix
   */
  public String getCNPostfix() {
    return (String) data.get(CNPOSTFIX);
  }

  /**
   * @param cnpostfix postfix
   */
  public void setCNPostfix(final String cnpostfix) {
    data.put(CNPOSTFIX, cnpostfix);
  }

  /**
   * @return bool
   */
  public boolean getUseSubjectDNSubSet() {
    return ((Boolean) data.get(USESUBJECTDNSUBSET)).booleanValue();
  }

  /**
   * @param use bool
   */
  public void setUseSubjectDNSubSet(final boolean use) {
    data.put(USESUBJECTDNSUBSET, Boolean.valueOf(use));
  }

  /**
   * @return a List of Integer (DNFieldExtractor constants) indicating which
   *     subject dn fields that should be used in certificate.
   */
  @SuppressWarnings("unchecked")
  public List<Integer> getSubjectDNSubSet() {
    return (List<Integer>) data.get(SUBJECTDNSUBSET);
  }

  /**
   * Should contain a collection of Integer (DNFieldExtractor constants)
   * indicating which subject dn fields that should be used in certificate.
   *
   * <p>Will come in as a list of string from the GUI, because JSP doesn't
   * always care about type safety.
   *
   * @param subjectdns DNs
   */
  public void setSubjectDNSubSet(final List<String> subjectdns) {
    List<Integer> convertedList = new ArrayList<>();
    for (String value : subjectdns) {
      convertedList.add(Integer.valueOf(value));
    }
    data.put(SUBJECTDNSUBSET, convertedList);
  }

  /**
   * Overridable Extension OIDs is an Set of oid Strings. It is used to list
   * what are the extensions that can be overridden when allow extension
   * override is enabled in the Certificate Profile.
   *
   * @param overridableextensionoids Set of oids (strings), or an empty set,
   *     should not be null
   */
  public void setOverridableExtensionOIDs(
      final Set<String> overridableextensionoids) {
    data.put(
        OVERRIDABLEEXTENSIONOIDS,
        new LinkedHashSet<String>(overridableextensionoids));
  }

  /**
   * Overridable Extension OIDs is an Set of oid Strings. It is used to list
   * what are the extensions that can be overridden when allow extension
   * override is enabled in the Certificate Profile.
   *
   * @return Set of strings containing oids, or an empty set, never null
   */
  @SuppressWarnings("unchecked")
  public Set<String> getOverridableExtensionOIDs() {
    if (data.get(OVERRIDABLEEXTENSIONOIDS) == null) {
      return new LinkedHashSet<String>();
    }
    return (Set<String>) data.get(OVERRIDABLEEXTENSIONOIDS);
  }

  /**
   * Non Overridable Extension OIDs is a Set of oid Strings. It is used to list
   * what are the extensions that can not be overridden when allow extension
   * override is enabled in the Certificate Profile..
   *
   * @param nonoverridableextensionoids Set of oids (strings) that are not
   *     allowed to be overridden, or empty set to not disallow anything, not
   *     null
   */
  public void setNonOverridableExtensionOIDs(
      final Set<String> nonoverridableextensionoids) {
    data.put(
        NONOVERRIDABLEEXTENSIONOIDS,
        new LinkedHashSet<String>(nonoverridableextensionoids));
  }

  /**
   * Non Overridable Extension OIDs is a Set of oid Strings. It is used to list
   * what are the extensions that can not be overridde when allow extension
   * override is enabled in the Certificate Profile..
   *
   * @return Set of strings containing oids, or an empty set, never null
   */
  @SuppressWarnings("unchecked")
  public Set<String> getNonOverridableExtensionOIDs() {
    if (data.get(NONOVERRIDABLEEXTENSIONOIDS) == null) {
      return new LinkedHashSet<String>();
    }
    return (Set<String>) data.get(NONOVERRIDABLEEXTENSIONOIDS);
  }

  /**
   * Method taking a full user dn and returns a DN only containing the DN fields
   * specified in the subjectdn sub set array.
   *
   * @param dn DN
   * @return a subset of original DN
   */
  public String createSubjectDNSubSet(final String dn) {
    DNFieldExtractor extractor =
        new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    return constructUserData(extractor, getSubjectDNSubSet(), true);
  }

  /** @return bool */
  public boolean getUseSubjectAltNameSubSet() {
    return ((Boolean) data.get(USESUBJECTALTNAMESUBSET)).booleanValue();
  }

  /**
   * @param use bool
   */
  public void setUseSubjectAltNameSubSet(final boolean use) {
    data.put(USESUBJECTALTNAMESUBSET, Boolean.valueOf(use));
  }

  /**
   * @return a List of Integer (DNFieldExtractor constants) indicating which
   *     subject altnames fields that should be used in certificate.
   */
  @SuppressWarnings("unchecked")
  public List<Integer> getSubjectAltNameSubSet() {
    return (List<Integer>) data.get(SUBJECTALTNAMESUBSET);
  }

  /**
   * Sets a List of Integer (DNFieldExtractor constants) indicating which
   * subject altnames fields that should be used in certificate.
   *
   * @param subjectaltnames names
   */
  public void setSubjectAltNameSubSet(final List<Integer> subjectaltnames) {
    data.put(SUBJECTALTNAMESUBSET, subjectaltnames);
  }

  /**
   * Method taking a full user dn and returns a AltName only containing the
   * AltName fields specified in the subjectaltname sub set array.
   *
   * @param subjectaltname Alt Name
   * @return a subset of original DN
   */
  public String createSubjectAltNameSubSet(final String subjectaltname) {
    DNFieldExtractor extractor =
        new DNFieldExtractor(
            subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    return constructUserData(extractor, getSubjectAltNameSubSet(), false);
  }

  /**
   * Help method converting a full DN or Subject Alt Name to one usng only
   * specified fields.
   *
   * @param extractor extractor
   * @param usefields fields
   * @param subjectdn DN
   * @return data
   */
  protected static String constructUserData(
      final DNFieldExtractor extractor,
      final Collection<Integer> usefields,
      final boolean subjectdn) {
    String retval = "";

    if (usefields instanceof List<?>) {
      Collections.sort((List<Integer>) usefields);
    }
    String dnField = null;
    for (Integer next : usefields) {
      dnField = extractor.getFieldString(next.intValue());
      if (StringUtils.isNotEmpty(dnField)) {
        if (retval.length() == 0) {
          retval += dnField; // first item, don't start with a comma
        } else {
          retval += "," + dnField;
        }
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("CertificateProfile: constructed DN or AltName: " + retval);
    }
    return retval;
  }

  /**
   * @return a List of caids (Integer), indicating which CAs the profile should
   *     be applicable to.
   *     <p>If it contains the constant ANYCA then the profile is applicable to
   *     all CAs
   */
  @SuppressWarnings("unchecked")
  public List<Integer> getAvailableCAs() {
    return (List<Integer>) data.get(AVAILABLECAS);
  }

  /**
   * Saves the CertificateProfile's list of CAs the cert profile is applicable
   * to.
   *
   * @param availablecas a List of caids (Integer)
   */
  public void setAvailableCAs(final List<Integer> availablecas) {
    data.put(AVAILABLECAS, availablecas);
  }

 /** @return bool */
  @SuppressWarnings("unchecked")
  public boolean isApplicableToAnyCA() {
    return ((List<Integer>) data.get(AVAILABLECAS))
        .contains(Integer.valueOf(ANYCA));
  }

  /**
   * @return a List of publisher id's (Integer) indicating which publishers a
   *     certificate created with this profile should be published to. Never
   *     returns null.
   */
  @SuppressWarnings("unchecked")
  public List<Integer> getPublisherList() {
    Object o = data.get(USEDPUBLISHERS);
    if (o == null) {
      o = new ArrayList<Integer>();
    }
    return (List<Integer>) o;
  }

  /**
   * Saves the CertificateProfile's list of publishers that certificates created
   * with this profile should be published to.
   *
   * @param publisher a List&lt;Integer&gt; of publisher Ids
   */
  public void setPublisherList(final List<Integer> publisher) {
    data.put(USEDPUBLISHERS, publisher);
  }

  /**
   * Method indicating that Path Length Constraint should be used in the
   * BasicConstaint.
   *
   * @return boolean
   */
  public boolean getUsePathLengthConstraint() {
    return ((Boolean) data.get(USEPATHLENGTHCONSTRAINT)).booleanValue();
  }

  /**
   * Method indicating that Path Length Constraint should be used in the
   * BasicConstaint.
   *
   * @param use boolean
   */
  public void setUsePathLengthConstraint(final boolean use) {
    data.put(USEPATHLENGTHCONSTRAINT, Boolean.valueOf(use));
  }

  /**
   * @return Length
   */
  public int getPathLengthConstraint() {
    return ((Integer) data.get(PATHLENGTHCONSTRAINT)).intValue();
  }
  /**
   * @param pathlength Length
   */
  public void setPathLengthConstraint(final int pathlength) {
    data.put(PATHLENGTHCONSTRAINT, Integer.valueOf(pathlength));
  }

  /**
   * @param caIssuers List of issuers
   */
  public void setCaIssuers(final List<String> caIssuers) {
    data.put(CAISSUERS, caIssuers);
  }

  /**
   * @param ocaIssuer Issuer
   */
  @SuppressWarnings("unchecked")
  public void addCaIssuer(final String ocaIssuer) {
    String caIssuer = ocaIssuer.trim();
    if (caIssuer.length() < 1) {
      return;
    }
    if (data.get(CAISSUERS) == null) {
      List<String> caIssuers = new ArrayList<>();
      caIssuers.add(caIssuer);
      this.setCaIssuers(caIssuers);
    } else {
      ((List<String>) data.get(CAISSUERS)).add(caIssuer);
    }
  }

  /** @return list of issuers */
  @SuppressWarnings("unchecked")
  public List<String> getCaIssuers() {
    if (data.get(CAISSUERS) == null) {
      return new ArrayList<>();
    } else {
      return (List<String>) data.get(CAISSUERS);
    }
  }

  /**
   * @param caIssuer issuer
   */
  public void removeCaIssuer(final String caIssuer) {
    if (data.get(CAISSUERS) != null) {
      ((List<?>) data.get(CAISSUERS)).remove(caIssuer);
    }
  }

  /** @return bool */
  public boolean getUseOcspNoCheck() {
    if (data.get(USEOCSPNOCHECK) == null) {
      return false;
    } else {
      return ((Boolean) data.get(USEOCSPNOCHECK)).booleanValue();
    }
  }

  /**
   * @param useocspnocheck bool
   */
  public void setUseOcspNoCheck(final boolean useocspnocheck) {
    data.put(USEOCSPNOCHECK, Boolean.valueOf(useocspnocheck));
  }

  /** @return bool */
  public boolean getUseAuthorityInformationAccess() {
    return ((Boolean) data.get(USEAUTHORITYINFORMATIONACCESS)).booleanValue();
  }

  /**
   * @param useauthorityinformationaccess bool
   */
  public void setUseAuthorityInformationAccess(
      final boolean useauthorityinformationaccess) {
    data.put(
        USEAUTHORITYINFORMATIONACCESS,
        Boolean.valueOf(useauthorityinformationaccess));
  }

  /** @return bool */
  public boolean getUseDefaultCAIssuer() {
    // Lazy instantiation in case upgrade for some reason fails
    if (data.get(USEDEFAULTCAISSUER) == null) {
      data.put(USEDEFAULTCAISSUER, false);
    }
    return ((Boolean) data.get(USEDEFAULTCAISSUER)).booleanValue();
  }

  /**
   * @param usedefaultcaissuer bool
   */
  public void setUseDefaultCAIssuer(final boolean usedefaultcaissuer) {
    data.put(USEDEFAULTCAISSUER, Boolean.valueOf(usedefaultcaissuer));
  }

  /** @return bool */
  public boolean getUseDefaultOCSPServiceLocator() {
    return ((Boolean) data.get(USEDEFAULTOCSPSERVICELOCATOR)).booleanValue();
  }

  /**
   * @param usedefaultocspservicelocator bool
   */
  public void setUseDefaultOCSPServiceLocator(
      final boolean usedefaultocspservicelocator) {
    data.put(
        USEDEFAULTOCSPSERVICELOCATOR,
        Boolean.valueOf(usedefaultocspservicelocator));
  }

  /** @return URI */
  public String getOCSPServiceLocatorURI() {
    return (String) data.get(OCSPSERVICELOCATORURI);
  }

  /**
   * @param ocspservicelocatoruri URI
   */
  public void setOCSPServiceLocatorURI(final String ocspservicelocatoruri) {
    if (ocspservicelocatoruri == null) {
      data.put(OCSPSERVICELOCATORURI, "");
    } else {
      data.put(OCSPSERVICELOCATORURI, ocspservicelocatoruri);
    }
  }

  /** @return bool */
  public boolean getUseQCStatement() {
    return ((Boolean) data.get(USEQCSTATEMENT)).booleanValue();
  }

  /**
   * @param useqcstatement bool
   */
  public void setUseQCStatement(final boolean useqcstatement) {
    data.put(USEQCSTATEMENT, Boolean.valueOf(useqcstatement));
  }

  /** @return bool */
  public boolean getUsePkixQCSyntaxV2() {
    return ((Boolean) data.get(USEPKIXQCSYNTAXV2)).booleanValue();
  }

  /**
   * @param pkixqcsyntaxv2 bool
   */
  public void setUsePkixQCSyntaxV2(final boolean pkixqcsyntaxv2) {
    data.put(USEPKIXQCSYNTAXV2, Boolean.valueOf(pkixqcsyntaxv2));
  }

  /** @return bool */
  public boolean getQCStatementCritical() {
    return ((Boolean) data.get(QCSTATEMENTCRITICAL)).booleanValue();
  }

  /**
   * @param qcstatementcritical bool
   */
  public void setQCStatementCritical(final boolean qcstatementcritical) {
    data.put(QCSTATEMENTCRITICAL, Boolean.valueOf(qcstatementcritical));
  }

  /** @return String with RAName or empty string */
  public String getQCStatementRAName() {
    return (String) data.get(QCSTATEMENTRANAME);
  }

  /**
   * @param qcstatementraname RA name
   */
  public void setQCStatementRAName(final String qcstatementraname) {
    if (qcstatementraname == null) {
      data.put(QCSTATEMENTRANAME, "");
    } else {
      data.put(QCSTATEMENTRANAME, qcstatementraname);
    }
  }

  /** @return String with SemanticsId or empty string */
  public String getQCSemanticsId() {
    return (String) data.get(QCSSEMANTICSID);
  }

  /**
   * @param qcsemanticsid ID
   */
  public void setQCSemanticsId(final String qcsemanticsid) {
    if (qcsemanticsid == null) {
      data.put(QCSSEMANTICSID, "");
    } else {
      data.put(QCSSEMANTICSID, qcsemanticsid);
    }
  }

  /** @return bool */
  public boolean getUseQCEtsiQCCompliance() {
    return ((Boolean) data.get(USEQCETSIQCCOMPLIANCE)).booleanValue();
  }

  /**
   * @param useqcetsiqccompliance bool
   */
  public void setUseQCEtsiQCCompliance(final boolean useqcetsiqccompliance) {
    data.put(USEQCETSIQCCOMPLIANCE, Boolean.valueOf(useqcetsiqccompliance));
  }

  /** @return limit */
  public boolean getUseQCEtsiValueLimit() {
    return ((Boolean) data.get(USEQCETSIVALUELIMIT)).booleanValue();
  }

  /**
   * @param useqcetsivaluelimit limit
   */
  public void setUseQCEtsiValueLimit(final boolean useqcetsivaluelimit) {
    data.put(USEQCETSIVALUELIMIT, Boolean.valueOf(useqcetsivaluelimit));
  }

  /** @return limit */
  public int getQCEtsiValueLimit() {
    return ((Integer) data.get(QCETSIVALUELIMIT)).intValue();
  }

  /**
   * @param qcetsivaluelimit limit
   */
  public void setQCEtsiValueLimit(final int qcetsivaluelimit) {
    data.put(QCETSIVALUELIMIT, Integer.valueOf(qcetsivaluelimit));
  }

  /** @return limit */
  public int getQCEtsiValueLimitExp() {
    return ((Integer) data.get(QCETSIVALUELIMITEXP)).intValue();
  }

  /**
   * @param qcetsivaluelimitexp limit
   */
  public void setQCEtsiValueLimitExp(final int qcetsivaluelimitexp) {
    data.put(QCETSIVALUELIMITEXP, Integer.valueOf(qcetsivaluelimitexp));
  }

  /** @return String with Currency or empty string */
  public String getQCEtsiValueLimitCurrency() {
    return (String) data.get(QCETSIVALUELIMITCURRENCY);
  }

  /**
   * @param qcetsivaluelimitcurrency Limit
   */
  public void setQCEtsiValueLimitCurrency(
          final String qcetsivaluelimitcurrency) {
    if (qcetsivaluelimitcurrency == null) {
      data.put(QCETSIVALUELIMITCURRENCY, "");
    } else {
      data.put(QCETSIVALUELIMITCURRENCY, qcetsivaluelimitcurrency);
    }
  }

  /** @return bool */
  public boolean getUseQCEtsiRetentionPeriod() {

    return ((Boolean) data.get(USEQCETSIRETENTIONPERIOD)).booleanValue();
  }

  /**
   * @param useqcetsiretentionperiod bool
   */
  public void setUseQCEtsiRetentionPeriod(
          final boolean useqcetsiretentionperiod) {
    data.put(
        USEQCETSIRETENTIONPERIOD, Boolean.valueOf(useqcetsiretentionperiod));
  }

  /** @return period */
  public int getQCEtsiRetentionPeriod() {
    return ((Integer) data.get(QCETSIRETENTIONPERIOD)).intValue();
  }

  /**
   * @param qcetsiretentionperiod period
   */
  public void setQCEtsiRetentionPeriod(final int qcetsiretentionperiod) {
    data.put(QCETSIRETENTIONPERIOD, Integer.valueOf(qcetsiretentionperiod));
  }

  /** @return bool */
  public boolean getUseQCEtsiSignatureDevice() {
    return ((Boolean) data.get(USEQCETSISIGNATUREDEVICE)).booleanValue();
  }

  /**
   * @param useqcetsisignaturedevice bool
   */
  public void setUseQCEtsiSignatureDevice(
          final boolean useqcetsisignaturedevice) {
    data.put(
        USEQCETSISIGNATUREDEVICE, Boolean.valueOf(useqcetsisignaturedevice));
  }

  /**
   * @return String with Type OID or null (or empty string) if it's not to be
   *     used (EN 319 412-05) 0.4.0.1862.1.6.1 = id-etsi-qct-esign
   *     0.4.0.1862.1.6.2 = id-etsi-qct-eseal 0.4.0.1862.1.6.3 = id-etsi-qct-web
   */
  public String getQCEtsiType() {
    return (String) data.get(QCETSITYPE);
  }

  /**
   * @param qcetsitype type
   */
  public void setQCEtsiType(final String qcetsitype) {
    data.put(QCETSITYPE, qcetsitype);
  }

  /**
   * @return the PKI Disclosure Statements (EN 319 412-05) used in this profile,
   *     or null if none are present.
   */
  @SuppressWarnings("unchecked")
  public List<PKIDisclosureStatement> getQCEtsiPds() {
    List<PKIDisclosureStatement> result = null;
    List<PKIDisclosureStatement> pdsList =
        (List<PKIDisclosureStatement>) data.get(QCETSIPDS);
    if (pdsList != null && !pdsList.isEmpty()) {
      result = new ArrayList<>(pdsList.size());
      try {
        for (final PKIDisclosureStatement pds : pdsList) {
          result.add((PKIDisclosureStatement) pds.clone());
        }
      } catch (CloneNotSupportedException e) {
        throw new IllegalStateException(e);
      }
    }
    return result;
  }

  /**
   * Sets the PKI Disclosure Statements (EN 319 412-05). Both null and empty
   * lists are interpreted as an "none".
   *
   * @param pds list of disclosure statements
   */
  public void setQCEtsiPds(final List<PKIDisclosureStatement> pds) {
    if (pds == null || pds.isEmpty()) { // never store an empty list
      data.put(QCETSIPDS, null);
    } else {
      data.put(QCETSIPDS, new ArrayList<>(pds));
    }
    // Remove old data from EJBCA < 6.6.1
    data.remove(QCETSIPDSURL);
    data.remove(QCETSIPDSLANG);
  }

  /** @return bool */
  public boolean getUseQCCustomString() {
    return ((Boolean) data.get(USEQCCUSTOMSTRING)).booleanValue();
  }

  /**
   * @param useqccustomstring bool
   */
  public void setUseQCCustomString(final boolean useqccustomstring) {
    data.put(USEQCCUSTOMSTRING, Boolean.valueOf(useqccustomstring));
  }

  /** @return String with oid or empty string */
  public String getQCCustomStringOid() {
    return (String) data.get(QCCUSTOMSTRINGOID);
  }

  /**
   *  @param qccustomstringoid OID
   */
  public void setQCCustomStringOid(final String qccustomstringoid) {
    if (qccustomstringoid == null) {
      data.put(QCCUSTOMSTRINGOID, "");
    } else {
      data.put(QCCUSTOMSTRINGOID, qccustomstringoid);
    }
  }

  /** @return String with custom text or empty string */
  public String getQCCustomStringText() {
    return (String) data.get(QCCUSTOMSTRINGTEXT);
  }

  /**
   * @param qccustomstringtext text
   */
  public void setQCCustomStringText(final String qccustomstringtext) {
    if (qccustomstringtext == null) {
      data.put(QCCUSTOMSTRINGTEXT, "");
    } else {
      data.put(QCCUSTOMSTRINGTEXT, qccustomstringtext);
    }
  }

  /** @return bool */
  public boolean getUseNameConstraints() {
    Boolean b = (Boolean) data.get(USENAMECONSTRAINTS);
    return b != null && b.booleanValue();
  }

  /** @param use bool */
  public void setUseNameConstraints(final boolean use) {
    data.put(USENAMECONSTRAINTS, Boolean.valueOf(use));
  }

  /** @return bool */
  public boolean getNameConstraintsCritical() {
    Boolean b = (Boolean) data.get(NAMECONSTRAINTSCRITICAL);
    return b != null && b.booleanValue();
  }

  /** @param use bool */
  public void setNameConstraintsCritical(final boolean use) {
    data.put(NAMECONSTRAINTSCRITICAL, Boolean.valueOf(use));
  }

  /** @return bool */
  public boolean getUseSubjectDirAttributes() {
    return ((Boolean) data.get(USESUBJECTDIRATTRIBUTES)).booleanValue();
  }

  /** @param use bool */
  public void setUseSubjectDirAttributes(final boolean use) {
    data.put(USESUBJECTDIRATTRIBUTES, Boolean.valueOf(use));
  }

  /** @param enabled bool */
  public void setSingleActiveCertificateConstraint(final boolean enabled) {
    data.put(USERSINGLEACTIVECERTIFICATECONSTRAINT, Boolean.valueOf(enabled));
  }

  /** @return bool */
  public boolean isSingleActiveCertificateConstraint() {
    Object constraintObject = data.get(USERSINGLEACTIVECERTIFICATECONSTRAINT);
    if (constraintObject == null) {
      // For upgrading from versions prior to 6.3.1
      setSingleActiveCertificateConstraint(false);
      return false;
    } else {
      return ((Boolean) data.get(USERSINGLEACTIVECERTIFICATECONSTRAINT))
          .booleanValue();
    }
  }

  /**
   * Returns which type of terminals are used in this ca/certificate hierarchy.
   * The values correspond to the id-roles-1/2/3 OIDs.
   *
   * @return type
   */
  public int getCVCTerminalType() {
    if (data.get(CVCTERMINALTYPE) == null) {
      return CertificateProfile.CVC_TERMTYPE_IS;
    }
    return ((Integer) data.get(CVCTERMINALTYPE)).intValue();
  }

  /** @param termtype type */
  public void setCVCTerminalType(final int termtype) {
    data.put(CVCTERMINALTYPE, Integer.valueOf(termtype));
  }

  /** @return bool */
  public boolean isCvcTerminalTypeIs() {
    return getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_IS;
  }

  /** @return bool */
  public boolean isCvcTerminalTypeAt() {
    return getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_AT;
  }

  /** @return bool */
  public boolean isCvcTerminalTypeSt() {
    return getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_ST;
  }

  /**  @return rights */
  public int getCVCAccessRights() {
    if (data.get(CVCACCESSRIGHTS) == null) {
      return CertificateProfile.CVC_ACCESS_NONE;
    }
    return ((Integer) data.get(CVCACCESSRIGHTS)).intValue();
  }

  /** @param access access */
  public void setCVCAccessRights(final int access) {
    data.put(CVCACCESSRIGHTS, Integer.valueOf(access));
  }

  /**
   * Used for bitmasks that don't fit in an int. E.g. the 5-byte bitmask for
   * Authentication Terminals
   *
   * @return rights
   */
  public byte[] getCVCLongAccessRights() {
    if (data.get(CVCLONGACCESSRIGHTS) == null) {
      return null;
    }
    @SuppressWarnings("unchecked")
    List<Byte> rightsList = (List<Byte>) data.get(CVCLONGACCESSRIGHTS);
    return ArrayUtils.toPrimitive(rightsList.toArray(new Byte[0]));
  }

  /** @param access access */
  public void setCVCLongAccessRights(final byte[] access) {
    if (access == null) {
      data.put(CVCLONGACCESSRIGHTS, null);
    } else {
      // Convert to List<Byte> since byte[] doesn't work with database
      // protection
      data.put(
          CVCLONGACCESSRIGHTS,
          new ArrayList<>(Arrays.asList(ArrayUtils.toObject(access))));
    }
  }

  /** @return type */
  public int getCVCSignTermDVType() {
    if (data.get(CVCSIGNTERMDVTYPE) == null) {
      return CertificateProfile.CVC_SIGNTERM_DV_CSP;
    }
    return ((Integer) data.get(CVCSIGNTERMDVTYPE)).intValue();
  }

  /**
   * @param type Type
   */
  public void setCVCSignTermDVType(final int type) {
    data.put(CVCSIGNTERMDVTYPE, Integer.valueOf(type));
  }

  /**
   * Method returning a list of (Integers) of ids of used CUSTOM certificate
   * extensions. I.e. those custom certificate extensions selected for this
   * profile. Never null.
   *
   * <p>Autoupgradable method
   *
   * @return extensions
   */
  @SuppressWarnings("unchecked")
  public List<Integer> getUsedCertificateExtensions() {
    if (data.get(USEDCERTIFICATEEXTENSIONS) == null) {
      return new ArrayList<>();
    }
    return (List<Integer>) data.get(USEDCERTIFICATEEXTENSIONS);
  }

  /**
   * Method setting a list of used certificate extensions a list of Integers
   * containing CertificateExtension Id is expected.
   *
   * @param usedCertificateExtensions extensions
   */
  public void setUsedCertificateExtensions(
      final List<Integer> usedCertificateExtensions) {
    if (usedCertificateExtensions == null) {
      data.put(USEDCERTIFICATEEXTENSIONS, new ArrayList<Integer>());
    } else {
      data.put(USEDCERTIFICATEEXTENSIONS, usedCertificateExtensions);
    }
  }

  /**
   * Function that looks up in the profile all certificate extensions that we
   * should use if the value is that we should use it, the oid for this
   * extension is returned in the list.
   *
   * @return List of oid Strings for standard certificate extensions that should
   *     be used
   */
  public List<String> getUsedStandardCertificateExtensions() {
    ArrayList<String> ret = new ArrayList<>();
    Iterator<String> iter =
        USE_STD_CERT_EXTENSIONS.keySet().iterator();
    while (iter.hasNext()) {
      String s = iter.next();
      if (data.get(s) != null && ((Boolean) data.get(s)).booleanValue()) {
        ret.add(USE_STD_CERT_EXTENSIONS.get(s));
        if (LOG.isDebugEnabled()) {
          LOG.debug("Using standard certificate extension: " + s);
        }
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Not using standard certificate extensions: " + s);
        }
      }
    }
    return ret;
  }

  /**
   * @return a List of Integers (CAInfo.REQ_APPROVAL_ constants) of which action
   *     that requires approvals, default none, never null
   * @deprecated since 6.8.0. Use getApprovals() instead;
   */
  @SuppressWarnings("unchecked")
  @Deprecated
  public List<Integer> getApprovalSettings() {
    List<Integer> approvalSettings = (List<Integer>) data.get(APPROVALSETTINGS);
    if (approvalSettings != null) {
      return approvalSettings;
    } else {
      return new ArrayList<>();
    }
  }

  /**
   * List of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that
   * requires approvals.
   *
   * @param approvalSettings settings
   * @deprecated since 6.8.0. Use setApprovals() instead;
   */
  @Deprecated
  public void setApprovalSettings(final List<Integer> approvalSettings) {
    data.put(APPROVALSETTINGS, approvalSettings);
  }

  /**
   * Returns the number of different administrators that needs to approve an
   * action, default 1.
   *
   * @return number of required approvals
   * @deprecated since 6.6.0, use the appropriate approval profile instead
   *     Needed for a while in order to be able to import old statedumps from
   *     6.5 and earlier
   */
  @Deprecated
  public int getNumOfReqApprovals() {
    Integer result = (Integer) data.get(NUMOFREQAPPROVALS);
    if (result != null) {
      return result.intValue();
    } else {
      return 1;
    }
  }

  /**
   * The number of different administrators that needs to approve.
   *
   * @param numOfReqApprovals number of required approvals
   * @deprecated since 6.6.0, use the appropriate approval profile instead
   *     Needed for a while in order to be able to import old statedumps from
   *     6.5 and earlier
   */
  @Deprecated
  public void setNumOfReqApprovals(final int numOfReqApprovals) {
    data.put(NUMOFREQAPPROVALS, Integer.valueOf(numOfReqApprovals));
  }

  /**
   * @return the id of the approval profile. ID -1 means that no approval
   *     profile was set
   * @deprecated since 6.8.0. Use getApprovals() instead;
   */
  @Deprecated
  public int getApprovalProfileID() {
    Integer approvalProfileId = (Integer) data.get(APPROVALPROFILE);
    if (approvalProfileId != null) {
      return approvalProfileId.intValue();
    } else {
      return -1;
    }
  }

  /**
   * @param approvalProfileID ID
   * @deprecated since 6.8.0. Use setApprovals() instead;
   */
  @Deprecated
  public void setApprovalProfileID(final int approvalProfileID) {
    data.put(APPROVALPROFILE, Integer.valueOf(approvalProfileID));
  }

  /**
   * @param oapprovals Approvals
   */
  public void setApprovals(final Map<ApprovalRequestType, Integer> oapprovals) {
    LinkedHashMap<ApprovalRequestType, Integer> approvals;
    if (oapprovals == null) {
      approvals = new LinkedHashMap<>();
    } else {
      approvals = new LinkedHashMap<ApprovalRequestType, Integer>(oapprovals);
    }
    // We must store this as a predictable order map in the database, in order
    // for databaseprotection to work
    data.put(
        APPROVALS, approvals);
  }

  /**
   * @return a map of approvals, mapped as approval setting (as defined in this
   *     class) : approval profile ID. Never returns null.
   */
  @SuppressWarnings("unchecked")
  public Map<ApprovalRequestType, Integer> getApprovals() {
    if (data.get(APPROVALS) == null) {
      Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
      int approvalProfileId = getApprovalProfileID();
      if (approvalProfileId != -1) {
        for (int approvalSetting : getApprovalSettings()) {
          approvals.put(
              ApprovalRequestType.getFromIntegerValue(approvalSetting),
              approvalProfileId);
        }
      }
      setApprovals(approvals);
    }
    return (Map<ApprovalRequestType, Integer>) data.get(APPROVALS);
  }

  /**
   * @return If the PrivateKeyUsagePeriod extension should be used and with the
   *     notBefore component.
   */
  public boolean isUsePrivateKeyUsagePeriodNotBefore() {
    if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) {
      return false;
    }
    return ((Boolean) data.get(USEPRIVKEYUSAGEPERIODNOTBEFORE)).booleanValue();
  }

  /**
   * Sets if the PrivateKeyUsagePeriod extension should be used and with the
   * notBefore component. Setting this to true means that there will be an
   * PrivateKeyUsagePeriod extension and that it also at least will contain an
   * notBefore component. Setting this to false means that the extension will
   * not contain an notBefore component. In that case if there will be an
   * extension depends on if {@link #isUsePrivateKeyUsagePeriodNotAfter()} is
   * true.
   *
   * @param use True if the notBefore component should be used.
   */
  public void setUsePrivateKeyUsagePeriodNotBefore(final boolean use) {
    data.put(USEPRIVKEYUSAGEPERIODNOTBEFORE, use);
    data.put(
        USEPRIVKEYUSAGEPERIOD, use || isUsePrivateKeyUsagePeriodNotAfter());
  }

  /**
   * @return If the PrivateKeyUsagePeriod extension should be used and with the
   *     notAfter component.
   */
  public boolean isUsePrivateKeyUsagePeriodNotAfter() {
    if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) {
      return false;
    }
    return ((Boolean) data.get(USEPRIVKEYUSAGEPERIODNOTAFTER)).booleanValue();
  }

  /**
   * Sets if the PrivateKeyUsagePeriod extension should be used and with the
   * notAfter component. Setting this to true means that there will be an
   * PrivateKeyUsagePeriod extension and that it also at least will contain an
   * notAfter component. Setting this to false means that the extension will not
   * contain an notAfter component. In that case if there will be an extension
   * depends on if {@link #isUsePrivateKeyUsagePeriodNotBefore()} is true.
   *
   * @param use True if the notAfter component should be used.
   */
  public void setUsePrivateKeyUsagePeriodNotAfter(final boolean use) {
    data.put(USEPRIVKEYUSAGEPERIODNOTAFTER, use);
    data.put(
        USEPRIVKEYUSAGEPERIOD, use || isUsePrivateKeyUsagePeriodNotBefore());
  }

  /**
   * @return How long (in seconds) after the certificate's notBefore date the
   *     PrivateKeyUsagePeriod's notBefore date should be.
   */
  public long getPrivateKeyUsagePeriodStartOffset() {
    return ((Long) data.get(PRIVKEYUSAGEPERIODSTARTOFFSET)).longValue();
  }

  /**
   * Sets how long (in seconds) after the certificate's notBefore date the
   * PrivateKeyUsagePeriod's notBefore date should be.
   *
   * @param start Offset from certificate issuance.
   */
  public void setPrivateKeyUsagePeriodStartOffset(final long start) {
    data.put(PRIVKEYUSAGEPERIODSTARTOFFSET, start);
  }

  /**
   * @return The private key usage period (private key validity) length (in
   *     seconds).
   */
  public long getPrivateKeyUsagePeriodLength() {
    return ((Long) data.get(PRIVKEYUSAGEPERIODLENGTH)).longValue();
  }

  /**
   * Sets the private key usage period (private key validity) length (in
   * seconds).
   *
   * @param validity The length.
   */
  public void setPrivateKeyUsagePeriodLength(final long validity) {
    data.put(PRIVKEYUSAGEPERIODLENGTH, validity);
  }

  /**
   * @return Whether Certificate Transparency (CT) should be used when
   *     generating new certificates. CT is specified in RFC 6962
   */
  public boolean isUseCertificateTransparencyInCerts() {
    if (data.get(USECERTIFICATETRANSPARENCYINCERTS) == null) {
      return false;
    }
    return ((Boolean) data.get(USECERTIFICATETRANSPARENCYINCERTS))
        .booleanValue();
  }

  /** @param use bool  */
  public void setUseCertificateTransparencyInCerts(final boolean use) {
    data.put(USECERTIFICATETRANSPARENCYINCERTS, use);
  }

  /**
   * @return Whether Certificate Transparency (CT) should be used in OCSP
   *     responses. CT is specified in RFC 6962
   */
  public boolean isUseCertificateTransparencyInOCSP() {
    if (data.get(USECERTIFICATETRANSPARENCYINOCSP) == null) {
      return false;
    }
    return ((Boolean) data.get(USECERTIFICATETRANSPARENCYINOCSP))
        .booleanValue();
  }

  /** @param use bool  */
  public void setUseCertificateTransparencyInOCSP(final boolean use) {
    data.put(USECERTIFICATETRANSPARENCYINOCSP, use);
  }

  /**
   * @return Whether Certificate Transparency (CT) should be used in publishers.
   *     You have to create a publisher and enable it in the profile also!
   */
  public boolean isUseCertificateTransparencyInPublishers() {
    if (data.get(USECERTIFICATETRANSPARENCYINPUBLISHERS) == null) {
      // Default to being enabled if CT in OCSP was enabled
      return isUseCertificateTransparencyInOCSP();
    }
    return ((Boolean) data.get(USECERTIFICATETRANSPARENCYINPUBLISHERS))
        .booleanValue();
  }

  /** @param use bool  */
  public void setUseCertificateTransparencyInPublishers(final boolean use) {
    data.put(USECERTIFICATETRANSPARENCYINPUBLISHERS, use);
  }

  /** @return bool */
  public boolean isCtEnabled() {
    return isUseCertificateTransparencyInCerts()
        || isUseCertificateTransparencyInOCSP()
        || isUseCertificateTransparencyInPublishers();
  }

  /** @return bool */
  public boolean isNumberOfSctByValidity() {
    if (data.get(CT_NUMBER_OF_SCTS_BY_VALIDITY) == null) {
      // Default value
      return true;
    }
    return (Boolean) data.get(CT_NUMBER_OF_SCTS_BY_VALIDITY);
  }

  /** @param use bool  */
  public void setNumberOfSctByValidity(final boolean use) {
    data.put(CT_NUMBER_OF_SCTS_BY_VALIDITY, use);
  }

  /** @return bool */
  public boolean isNumberOfSctByCustom() {
    if (data.get(CT_NUMBER_OF_SCTS_BY_CUSTOM) == null) {
      // Default value
      return false;
    }
    return (Boolean) data.get(CT_NUMBER_OF_SCTS_BY_CUSTOM);
  }

  /** @param use bool  */
  public void setNumberOfSctByCustom(final boolean use) {
    data.put(CT_NUMBER_OF_SCTS_BY_CUSTOM, use);
  }

  /** @return bool */
  public boolean isMaxNumberOfSctByValidity() {
    if (data.get(CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY) == null) {
      // Default value
      return false;
    }
    return (Boolean) data.get(CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY);
  }
  /** @param use bool  */
  public void setMaxNumberOfSctByValidity(final boolean use) {
    data.put(CT_MAX_NUMBER_OF_SCTS_BY_VALIDITY, use);
  }

  /** @return bool */
  public boolean isMaxNumberOfSctByCustom() {
    if (data.get(CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM) == null) {
      // Default value
      return true;
    }
    return (Boolean) data.get(CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM);
  }
 /** @param use bool */
  public void setMaxNumberOfSctByCustom(final boolean use) {
    data.put(CT_MAX_NUMBER_OF_SCTS_BY_CUSTOM, use);
  }

  /**
   * @return Whether existing certificates should be submitted by the CT
   *     publisher and the CT OCSP extension class.
   */
  public boolean isUseCTSubmitExisting() {
    if (data.get(CTSUBMITEXISTING) == null) {
      return true;
    }
    return ((Boolean) data.get(CTSUBMITEXISTING)).booleanValue();
  }

  /** @param use bool*/
  public void setUseCTSubmitExisting(final boolean use) {
    data.put(CTSUBMITEXISTING, use);
  }

  /** @return the IDs of the CT logs that are activated in this profile. */
  @SuppressWarnings("unchecked")
  @Deprecated
  public Set<Integer> getEnabledCTLogs() {
    if (data.get(CTLOGS) == null) {
      return new LinkedHashSet<>();
    }

    return (Set<Integer>) data.get(CTLOGS);
  }

  /**
   * Sets the enabled CT logs. NOTE: The argument must be a LinkedHashSet, since
   * order is important
   *
   * @param logIds IDs
   */
  @Deprecated
  public void setEnabledCTLogs(final LinkedHashSet<Integer> logIds) {
    data.put(CTLOGS, new LinkedHashSet<>(logIds));
  }

  /** @return labels */
  @SuppressWarnings("unchecked")
  public Set<String> getEnabledCtLabels() {
    if (data.get(CTLABELS) == null) {
      return new LinkedHashSet<>();
    }
    return (Set<String>) data.get(CTLABELS);
  }

  /** @param ctLabels Labels */
  public void setEnabledCTLabels(final LinkedHashSet<String> ctLabels) {
    data.put(CTLABELS, ctLabels);
  }

  /**
   * Number of CT logs to require an SCT from, or it will be considered an
   * error. If zero, CT is completely optional and ignored if no log servers can
   * be contacted.
   *
   * <p>This value is used for certificates and publishers. For OCSP
   * responses, @see CertificateProfile#getCtMinTotalSctsOcsp
   *
   * <p>
   *
   * @return the total number of SCTs required
   */
  @Deprecated
  public int getCtMinTotalScts() {
    if (data.get(CT_MIN_TOTAL_SCTS) == null) {
      return 0; // setting is OFF
    }
    return (Integer) data.get(CT_MIN_TOTAL_SCTS);
  }

  /** @param value minimum number of SCTs required in total */
  @Deprecated
  public void setCtMinTotalScts(final int value) {
    data.put(CT_MIN_TOTAL_SCTS, value);
  }

  /**
   * @return sets
   * @see CertificateProfile#getCtMinTotalScts
   */
  @Deprecated
  public int getCtMinTotalSctsOcsp() {
    if (data.get(CT_MIN_TOTAL_SCTS_OCSP) == null) {
      return getCtMinTotalScts();
    }
    return (Integer) data.get(CT_MIN_TOTAL_SCTS_OCSP);
  }

  /**
   * @param value minimum number of SCTs for OCSP responses required in total
   */
  @Deprecated
  public void setCtMinTotalSctsOcsp(final int value) {
    data.put(CT_MIN_TOTAL_SCTS_OCSP, value);
  }

  /**
   * Number of SCTs retrieved after which we will stop contacting non-mandatory
   * log servers.
   *
   * @return the maximum number of non-mandatory SCTs
   */
  @Deprecated
  public int getCtMaxNonMandatoryScts() {
    if (data.get(CT_MAX_NONMANDATORY_SCTS) == null) {
      if (data.get(CT_MAX_SCTS) == null) {
        LOG.info(
            "CT_MAX_NON_MANDATORY_SCTS is null => legacy value is also null,"
                + " using 1 log as default.");
        return 1;
      }
      LOG.info(
          "CT_MAX_NON_MANDATORY_SCTS is null => using legacy value: "
              + data.get(CT_MAX_SCTS));
      return (Integer) data.get(CT_MAX_SCTS);
    }
    return (Integer) data.get(CT_MAX_NONMANDATORY_SCTS);
  }

  /** @param value the maximum number of non-mandatory SCTs */
  @Deprecated
  public void setCtMaxNonMandatoryScts(final int value) {
    data.put(CT_MAX_NONMANDATORY_SCTS, value);
  }

  /**
   * @return sets
   * @see CertificateProfile#getCtMaxNonMandatoryScts
   */
  @Deprecated
  public int getCtMaxNonMandatorySctsOcsp() {
    if (data.get(CT_MAX_NONMANDATORY_SCTS_OCSP) == null) {
      if (data.get(CT_MAX_SCTS_OCSP) == null) {
        LOG.info(
            "CT_MAX_NON_MANDATORY_SCTS_OCSP is null => legacy value is also"
                + " null, using 1 log as default.");
        return 1;
      }
      LOG.info(
          "CT_MAX_NON_MANDATORY_SCTS_OCSP is null => using legacy value: "
              + data.get(CT_MAX_SCTS_OCSP));
      return (Integer) data.get(CT_MAX_SCTS_OCSP);
    }
    return (Integer) data.get(CT_MAX_NONMANDATORY_SCTS_OCSP);
  }

  /**
   * @param value maximum value number of non-mandatory SCTs for OCSP responses
   */
  @Deprecated
  public void setCtMaxNonMandatorySctsOcsp(final int value) {
    data.put(CT_MAX_NONMANDATORY_SCTS_OCSP, value);
  }

  /**
   * Number of CT logs marked as "not mandatory" to require an SCT from, or it
   * will be considered an error. Default is zero logs.
   *
   * <p>For publishers, certificates are submitted to all enabled logs.
   *
   * @return scts
   */
  @Deprecated
  public int getCtMinNonMandatoryScts() {
    if (data.get(CT_MIN_NONMANDATORY_SCTS) == null) {
      return getCtMinTotalScts();
    }
    return (Integer) data.get(CT_MIN_NONMANDATORY_SCTS);
  }

  /** @param value minimum number of non-mandatory SCTs */
  @Deprecated
  public void setCtMinNonMandatoryScts(final int value) {
    data.put(CT_MIN_NONMANDATORY_SCTS, value);
  }

  /**
   * @return scts
   * @see CertificateProfile#getCtMinNonMandatoryScts
   */
  @Deprecated
  public int getCtMinNonMandatorySctsOcsp() {
    if (data.get(CT_MIN_NONMANDATORY_SCTS_OCSP) == null) {
      return getCtMinNonMandatoryScts();
    }
    return (Integer) data.get(CT_MIN_NONMANDATORY_SCTS_OCSP);
  }

  /** @param value minimum number of non-mandatory SCTs */
  @Deprecated
  public void setCtMinNonMandatorySctsOcsp(final int value) {
    data.put(CT_MIN_NONMANDATORY_SCTS_OCSP, value);
  }

  /** @return Min SCTs */
  public int getCtMinScts() {
    if (data.get(CT_SCTS_MIN) == null) {
      return getCtMinTotalScts();
    }
    return (Integer) data.get(CT_SCTS_MIN);
  }

  /** @param value Min SCTs*/
  public void setCtMinScts(final int value) {
    data.put(CT_SCTS_MIN, value);
  }

  /** @return max scts */
  public int getCtMaxScts() {
    if (data.get(CT_SCTS_MAX) == null) {
      return getCtMinTotalScts();
    }
    return (Integer) data.get(CT_SCTS_MAX);
  }

  /** @param value Max SCTs*/
  public void setCtMaxScts(final int value) {
    data.put(CT_SCTS_MAX, value);
  }

  /** @return Min SCTs */
  public int getCtMinSctsOcsp() {
    if (data.get(CT_SCTS_MIN_OCSP) == null) {
      return getCtMinTotalScts();
    }
    return (Integer) data.get(CT_SCTS_MIN_OCSP);
  }

  /** @param value Min SCTs*/
  public void setCtMinSctsOcsp(final int value) {
    data.put(CT_SCTS_MIN_OCSP, value);
  }

  /** @return max scts */
  public int getCtMaxSctsOcsp() {
    if (data.get(CT_SCTS_MAX_OCSP) == null) {
      return getCtMinTotalScts();
    }
    return (Integer) data.get(CT_SCTS_MAX_OCSP);
  }
 /** @param value value */
  public void setCtMaxSctsOcsp(final int value) {
    data.put(CT_SCTS_MAX_OCSP, value);
  }

  /**
   * @return Number of times to retry connecting to a Certificate Transparency
   *     log
   */
  public int getCTMaxRetries() {
    if (data.get(CTMAXRETRIES) == null) {
      return 0;
    }
    return (Integer) data.get(CTMAXRETRIES);
  }

  /** @param numRetries retries*/
  public void setCTMaxRetries(final int numRetries) {
    data.put(CTMAXRETRIES, numRetries);
  }

  /**
   * Usage only intended for post upgrade! Removes CT data prior to EJBCA 6.10.1
   * from certificate profile.
   */
  public void removeLegacyCtData() {
    if (data.get(CT_MAX_SCTS) != null) {
      data.remove(CT_MAX_SCTS);
    }
    if (data.get(CT_MAX_SCTS_OCSP) != null) {
      data.remove(CT_MAX_SCTS_OCSP);
    }
    removeMandatory();
    if (data.get(CT_MIN_NONMANDATORY_SCTS) != null) {
      data.remove(CT_MIN_NONMANDATORY_SCTS);
    }
    if (data.get(CT_MAX_NONMANDATORY_SCTS) != null) {
      data.remove(CT_MAX_NONMANDATORY_SCTS);
    }
    if (data.get(CT_MIN_NONMANDATORY_SCTS_OCSP) != null) {
      data.remove(CT_MIN_NONMANDATORY_SCTS_OCSP);
    }
    if (data.get(CT_MAX_NONMANDATORY_SCTS_OCSP) != null) {
      data.remove(CT_MAX_NONMANDATORY_SCTS_OCSP);
    }
  }

/**
 *
 */
private void removeMandatory() {
    if (data.get(CT_MIN_MANDATORY_SCTS) != null) {
      data.remove(CT_MIN_MANDATORY_SCTS);
    }
    if (data.get(CT_MAX_MANDATORY_SCTS) != null) {
      data.remove(CT_MAX_MANDATORY_SCTS);
    }
    if (data.get(CT_MIN_MANDATORY_SCTS_OCSP) != null) {
      data.remove(CT_MIN_MANDATORY_SCTS_OCSP);
    }
    if (data.get(CT_MAX_MANDATORY_SCTS_OCSP) != null) {
      data.remove(CT_MAX_MANDATORY_SCTS_OCSP);
    }
}

  /**
   * Checks that a public key fulfills the policy in the CertificateProfile.
   *
   * @param publicKey PublicKey to verify
   * @throws IllegalKeyException if the PublicKey does not fulfill policy in
   *     CertificateProfile
   */
  public void verifyKey(final PublicKey publicKey) throws IllegalKeyException {
    final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
    final int keyLength = KeyTools.getKeyLength(publicKey);
    if (LOG.isDebugEnabled()) {
      LOG.debug("KeyAlgorithm: " + keyAlgorithm + " KeyLength: " + keyLength);
    }
    // Verify that the key algorithm is compliant with the certificate profile
    doVerifyCompliant(keyAlgorithm);
    if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
      final List<String> availableEcCurves = getAvailableEcCurvesAsList();
      final String keySpecification =
          AlgorithmTools.getKeySpecification(publicKey);
      for (final String ecNamedCurveAlias
          : AlgorithmTools.getEcKeySpecAliases(keySpecification)) {
        if (availableEcCurves.contains(ecNamedCurveAlias)) {
          // Curve is allowed, so we don't check key strength
          return;
        }
      }
      if (!availableEcCurves.contains(ANY_EC_CURVE)) {
        // Curve will never be allowed by bit length check
        throw new IllegalKeyException(
            INT_RES.getLocalizedMessage(
                "createcert.illegaleccurve", keySpecification));
      }
    }
    // Verify key length that it is compliant with certificate profile
    if (keyLength == -1) {
      throw new IllegalKeyException(
          INT_RES.getLocalizedMessage(
              "createcert.unsupportedkeytype", publicKey.getClass().getName()));
    }
    if (keyLength < (getMinimumAvailableBitLength() - 1)
        || keyLength > (getMaximumAvailableBitLength())) {
      throw new IllegalKeyException(
          INT_RES.getLocalizedMessage(
              "createcert.illegalkeylength", Integer.valueOf(keyLength)));
    }
  }

/**
 * @param keyAlgorithm algo
 * @throws IllegalKeyException Fail
 */
private void doVerifyCompliant(final String keyAlgorithm)
        throws IllegalKeyException {
    if (!getAvailableKeyAlgorithmsAsList().contains(keyAlgorithm)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "List of available algorithms "
                + getAvailableKeyAlgorithmsAsList()
                + " does not contain the on of the public key: "
                + keyAlgorithm);
      }
      throw new IllegalKeyException(
          INT_RES.getLocalizedMessage(
              "createcert.illegalkeyalgorithm", keyAlgorithm));
    }
}

  /**
   * Checks that provided caId is allowed.
   *
   * @param caId caId to verify
   * @return Returns true, if caId belongs to availableCas or if any CA is
   *     allowed (-1 is in availableCAs list)
   */
  public boolean isCaAllowed(final int caId) {
    List<Integer> availableCAs = getAvailableCAs();
    return availableCAs.contains(-1) || availableCAs.contains(caId);
  }

  @Override
  public CertificateProfile clone() throws CloneNotSupportedException {
    final CertificateProfile clone = new CertificateProfile(0);
    // We need to make a deep copy of the hashmap here
    clone.data = new LinkedHashMap<>(data.size());
    for (final Entry<Object, Object> entry : data.entrySet()) {
      Object value = entry.getValue();
      if (value instanceof ArrayList<?>) {
        // We need to make a clone of this object, but the stored immutables can
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

  /**
   * Function setting the current version of the class data. Used for JUnit
   * testing
   *
   * @param version version
   */
  protected void setVersion(final float version) {
    data.put(VERSION, Float.valueOf(version));
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @SuppressWarnings("deprecation")
  @Override
  public void upgrade() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
    }
    if (Float.compare(getLatestVersion(), getVersion()) != 0) {
      // New version of the class, upgrade
      String msg =
          INT_RES.getLocalizedMessage(
              "certprofile.upgrade", new Float(getVersion()));
      LOG.info(msg);

      doUpgradeSetup1();
      doUpgradeSetup2();
      doUpgradeSetup3();
      doV202122Upgrade();
      doV23Upgrade();
      doV2425Upgrade();
      doV26to31Upgrade();
      doV33To35Upgrade();
      doV36to41Upgrade();
      // v42. ETSI QC Type and PDS specified in EN 319 412-05.
      // Nothing to set though, since null values means to not use the new
      // values

      // v43, ECA-5304.
      if (data.get(USEDEFAULTCAISSUER) == null) {
        setUseDefaultCAIssuer(false);
      }

      // v44. ECA-5141
      // 'encodedValidity' is derived by the former long value!
      if (null == data.get(ENCODED_VALIDITY)
        && data.get(VALIDITY)
            != null) { // avoid NPE if this is a very raw profile
          setEncodedValidity(
              ValidityDate.getStringBeforeVersion661(getValidity()));

        // Don't upgrade to anything is there was nothing to upgrade
      }
      // v44. ECA-5330
      // initialize fields for expiration restriction for weekdays. use is false
      // because of backward compatibility, the before restriction default is
      // true
      doV44Upgrade();

      // v45: Multiple ETSI QC PDS values (ECA-5478)
      doV45Upgrade();
      // v46: approvals changed type to LinkedHashMap
      setApprovals(getApprovals());

      data.put(VERSION, new Float(LATEST_VERSION));
    }
    LOG.trace("<upgrade");
  }

/**
 *
 */
private void doV44Upgrade() {
    if (null == data.get(USE_EXPIRATION_RESTRICTION_FOR_WEEKDAYS)) {
        setUseExpirationRestrictionForWeekdays(false);
      }
      if (null == data.get(EXPIRATION_RESTRICTION_WEEKDAYS)) {
        setDefaultExpirationRestrictionWeekdays();
      }
      if (null == data.get(EXPIRATION_RESTRICTION_FOR_WEEKDAYS_BEFORE)) {
        setExpirationRestrictionForWeekdaysExpireBefore(true);
      }
      // v44. ECA-3554
      // initialize default certificate not before offset (default '-10m'
      // because of backward compatibility).
      if (null == data.get(USE_CERTIFICATE_VALIDITY_OFFSET)) {
        setUseCertificateValidityOffset(false);
      }
      if (null == data.get(CERTIFICATE_VALIDITY_OFFSET)) {
        setCertificateValidityOffset(DEFAULT_CERTIFICATE_VALIDITY_OFFSET);
      }
}

/**
 *
 */
private void doV36to41Upgrade() {
    if (data.get(USEISSUERALTERNATIVENAME) == null) { // v 36
        setUseIssuerAlternativeName(false);
      }
      if (data.get(ISSUERALTERNATIVENAMECRITICAL) == null) { // v 36
        setIssuerAlternativeNameCritical(false);
      }
      if (data.get(USEDOCUMENTTYPELIST) == null) { // v 37
        setUseDocumentTypeList(false);
      }
      if (data.get(DOCUMENTTYPELISTCRITICAL) == null) { // v 37
        setDocumentTypeListCritical(false);
      }
      if (data.get(DOCUMENTTYPELIST) == null) { // v 37
        setDocumentTypeList(new ArrayList<String>());
      }
      doV39Upgrade();
      if (data.get(AVAILABLEECCURVES) == null) { // v 40
        setAvailableEcCurves(new String[] {ANY_EC_CURVE});
      }
      if (data.get(APPROVALPROFILE) == null) { // v41
        setApprovalProfileID(-1);
      }
}

/**
 *
 */
private void doV33To35Upgrade() {
    if (data.get(NUMOFREQAPPROVALS) == null) { // v 33
        setNumOfReqApprovals(1);
      }
      if (data.get(APPROVALSETTINGS) == null) { // v 33
        setApprovalSettings(new ArrayList<Integer>());
      }

      if (data.get(SIGNATUREALGORITHM) == null) { // v 34
        setSignatureAlgorithm(null);
      }

      if (data.get(USEPRIVKEYUSAGEPERIODNOTBEFORE) == null) { // v 35
        setUsePrivateKeyUsagePeriodNotBefore(false);
      }
      if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) { // v 35
        setUsePrivateKeyUsagePeriodNotAfter(false);
      }
      if (data.get(PRIVKEYUSAGEPERIODSTARTOFFSET) == null) { // v 35
        setPrivateKeyUsagePeriodStartOffset(
            DEFAULT_PRIVATE_KEY_USAGE_PERIOD_OFFSET);
      }
      if (data.get(PRIVKEYUSAGEPERIODLENGTH) == null) { // v 35
        setPrivateKeyUsagePeriodLength(DEFAULT_PRIVATE_KEY_USAGE_PERIOD_LENGTH);
      }
}

/**
 *
 */
private void doV26to31Upgrade() {
    if (data.get(ALLOWEXTENSIONOVERRIDE) == null) {
        setAllowExtensionOverride(false); // v26
      }

      if (data.get(USEQCETSIRETENTIONPERIOD) == null) {
        setUseQCEtsiRetentionPeriod(false); // v27
        setQCEtsiRetentionPeriod(0);
      }

      if (data.get(CVCACCESSRIGHTS) == null) {
        setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE); // v28
      }

      if (data.get(USELDAPDNORDER) == null) {
        setUseLdapDnOrder(true); // v29, default value is true
      }

      if (data.get(USECARDNUMBER) == null) { // v30, default value is false
        setUseCardNumber(false);
      }

      if (data.get(ALLOWDNOVERRIDE) == null) {
        setAllowDNOverride(false); // v31
      }
}

/**
 *
 */
private void doV202122Upgrade() {
    if (data.get(CRLISSUER) == null) {
        setCRLIssuer(null); // v20
      }

      if (data.get(USEOCSPNOCHECK) == null) {
        setUseOcspNoCheck(false); // v21
      }
      if (data.get(USEFRESHESTCRL) == null) {
        setUseFreshestCRL(false); // v22
        setUseCADefinedFreshestCRL(false);
        setFreshestCRLURI(null);
      }
}

/**
 *
 */
private void doUpgradeSetup1() {
    if (data.get(ALLOWKEYUSAGEOVERRIDE) == null) {
        data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
      }
      if (data.get(USEEXTENDEDKEYUSAGE) == null) {
        data.put(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
      }
      if (data.get(EXTENDEDKEYUSAGE) == null) {
        data.put(EXTENDEDKEYUSAGE, new ArrayList<String>());
      }
      if (data.get(EXTENDEDKEYUSAGECRITICAL) == null) {
        data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.FALSE);
      }
      if (data.get(AVAILABLECAS) == null) {
        ArrayList<Integer> availablecas = new ArrayList<>();
        availablecas.add(Integer.valueOf(ANYCA));
        data.put(AVAILABLECAS, availablecas);
      }
}
private void doUpgradeSetup2() {
      if (data.get(USEDPUBLISHERS) == null) {
        data.put(USEDPUBLISHERS, new ArrayList<Integer>());
      }
      if (data.get(USEOCSPSERVICELOCATOR) == null
          && data.get(USEAUTHORITYINFORMATIONACCESS) == null) {
        // Only set this flag if we have not already set the new flag
        // USEAUTHORITYINFORMATIONACCESS
        // setUseOCSPServiceLocator(false);
        data.put(USEOCSPSERVICELOCATOR, Boolean.FALSE);
        setOCSPServiceLocatorURI("");
      }

      if (data.get(USEMICROSOFTTEMPLATE) == null) {
        setUseMicrosoftTemplate(false);
        setMicrosoftTemplate("");
      }

      if (data.get(USECNPOSTFIX) == null) {
        setUseCNPostfix(false);
        setCNPostfix("");
      }

      if (data.get(USESUBJECTDNSUBSET) == null) {
        setUseSubjectDNSubSet(false);
        setSubjectDNSubSet(new ArrayList<String>());
        setUseSubjectAltNameSubSet(false);
        setSubjectAltNameSubSet(new ArrayList<Integer>());
      }

      if (data.get(USEPATHLENGTHCONSTRAINT) == null) {
        setUsePathLengthConstraint(false);
        setPathLengthConstraint(0);
      }

}
private void doUpgradeSetup3() {
      if (data.get(USEQCSTATEMENT) == null) {
        setUseQCStatement(false);
        setUsePkixQCSyntaxV2(false);
        setQCStatementCritical(false);
        setQCStatementRAName(null);
        setQCSemanticsId(null);
        setUseQCEtsiQCCompliance(false);
        setUseQCEtsiSignatureDevice(false);
        setUseQCEtsiValueLimit(false);
        setUseQCEtsiRetentionPeriod(false);
        setQCEtsiRetentionPeriod(0);
        setQCEtsiValueLimit(0);
        setQCEtsiValueLimitExp(0);
        setQCEtsiValueLimitCurrency(null);
      }

      if (data.get(USEDEFAULTCRLDISTRIBUTIONPOINT) == null) {
        setUseDefaultCRLDistributionPoint(false);
        setUseDefaultOCSPServiceLocator(false);
      }

      if (data.get(USEQCCUSTOMSTRING) == null) {
        setUseQCCustomString(false);
        setQCCustomStringOid(null);
        setQCCustomStringText(null);
      }
      if (data.get(USESUBJECTDIRATTRIBUTES) == null) {
        setUseSubjectDirAttributes(false);
      }
      if (data.get(ALLOWVALIDITYOVERRIDE) == null) {
        setAllowValidityOverride(false);
      }
}

/**
 *
 */
private void doV2425Upgrade() {
    if (data.get(USECAISSUERS) == null
          && data.get(USEAUTHORITYINFORMATIONACCESS) == null) {
        // Only set this flag if we have not already set the new flag
        // USEAUTHORITYINFORMATIONACCESS
        // setUseCaIssuers(false); // v24
        data.put(USECAISSUERS, Boolean.FALSE); // v24
        setCaIssuers(new ArrayList<String>());
      }
      if ((data.get(USEOCSPSERVICELOCATOR) != null
              || data.get(USECAISSUERS) != null)
          && data.get(USEAUTHORITYINFORMATIONACCESS) == null) {
        // Only do this if we have not already set the new flag
        // USEAUTHORITYINFORMATIONACCESS
        boolean ocsp = false;
        if (data.get(USEOCSPSERVICELOCATOR) != null) {
          ocsp = ((Boolean) data.get(USEOCSPSERVICELOCATOR)).booleanValue();
        }
        boolean caissuers = false;
        if (data.get(USECAISSUERS) != null) {
          caissuers = ((Boolean) data.get(USECAISSUERS)).booleanValue();
        }
        if (ocsp || caissuers) {
          setUseAuthorityInformationAccess(true); // v25
        } else {
          setUseAuthorityInformationAccess(false); // v25
        }
      } else if (data.get(USEAUTHORITYINFORMATIONACCESS) == null) {
        setUseAuthorityInformationAccess(false);
      }
}

/**
 *
 */
private void doV45Upgrade() {
    if (!data.containsKey(QCETSIPDS)) {
        final String url = (String) data.get(QCETSIPDSURL);
        final String lang = (String) data.get(QCETSIPDSLANG);
        if (StringUtils.isNotEmpty(url)) {
          final List<PKIDisclosureStatement> pdsList = new ArrayList<>();
          pdsList.add(new PKIDisclosureStatement(url, lang));
          data.put(QCETSIPDS, pdsList);
        } else {
          data.put(QCETSIPDS, null);
        }
      }
}

/**
 *
 */
private void doV39Upgrade() {
    if (data.get(AVAILABLEKEYALGORITHMS) == null) { // v 39
        // Make some intelligent guesses what key algorithm this profile is used
        // for
        final List<String> availableKeyAlgorithms =
            AlgorithmTools.getAvailableKeyAlgorithms();
        if (getMinimumAvailableBitLength() > MIN_EC_SIZE) {
          availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_ECDSA);
          availableKeyAlgorithms.remove(
              AlgorithmConstants.KEYALGORITHM_DSTU4145);
          availableKeyAlgorithms.remove(
              AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        }
        if (getMinimumAvailableBitLength() > MIN_RSA_DSA_SIZE
            || getMaximumAvailableBitLength() < MIN_RSA_DSA_SIZE) {
          availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_DSA);
        }
        if (getMaximumAvailableBitLength() < MIN_RSA_DSA_SIZE) {
          availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_RSA);
        }
        setAvailableKeyAlgorithmsAsList(availableKeyAlgorithms);
      }
}

/**
 *
 */
private void doV23Upgrade() {
    if (data.get(CERTIFICATE_POLICIES) == null  // v23
        && data.get(CERTIFICATEPOLICYID) != null) {
          String ids = (String) data.get(CERTIFICATEPOLICYID);
          String unotice = null;
          String cpsuri = null;
          if (data.get(POLICY_NOTICE_UNOTICE_TEXT) != null) {
            unotice = (String) data.get(POLICY_NOTICE_UNOTICE_TEXT);
          }
          if (data.get(POLICY_NOTICE_CPS_URL) != null) {
            cpsuri = (String) data.get(POLICY_NOTICE_CPS_URL);
          }
          // Only the first policy could have user notice and cpsuri in the old
          // scheme
          StringTokenizer tokenizer = new StringTokenizer(ids, ";", false);
          if (tokenizer.hasMoreTokens()) {
            String id = tokenizer.nextToken();
            CertificatePolicy newpolicy = null;
            if (StringUtils.isNotEmpty(unotice)) {
              newpolicy =
                  new CertificatePolicy(
                      id, CertificatePolicy.ID_QT_UNNOTICE, unotice);
              addCertificatePolicy(newpolicy);
            }
            if (StringUtils.isNotEmpty(cpsuri)) {
              newpolicy =
                  new CertificatePolicy(
                      id, CertificatePolicy.ID_QT_CPS, cpsuri);
              addCertificatePolicy(newpolicy);
            }
            // If it was a lonely policy id
            if (newpolicy == null) {
              newpolicy = new CertificatePolicy(id, null, null);
              addCertificatePolicy(newpolicy);
            }
          }
          while (tokenizer.hasMoreTokens()) {
            String id = tokenizer.nextToken();
            CertificatePolicy newpolicy = new CertificatePolicy(id, null, null);
            addCertificatePolicy(newpolicy);
          }

      }
}

}
