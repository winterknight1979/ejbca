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

package org.cesecore.util;

import com.novell.ldap.LDAPDN;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.CharUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreRuntimeException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.ReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Tools to handle common certificate operations.
 *
 * @version $Id: CertTools.java 30344 2018-11-01 13:10:21Z samuellb $
 */
public abstract class CertTools { // NOPMD: len
    /** ogger. */
  private static final Logger LOGGER = Logger.getLogger(CertTools.class);

  /** Internal resource. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  // Initialize dnComponents
  static {
    DnComponents.getDnObjects(true);
  }


  /** Config. */
  public static final String EMAIL = "rfc822name";
  /** Config. */
  public static final String EMAIL1 = "email";
  /** Config. */
  public static final String EMAIL2 = "EmailAddress";
  /** Config. */
  public static final String EMAIL3 = "E";
  /** Config. */
  public static final String DNS = "dNSName";
  /** Config. */
  public static final String URI = "uniformResourceIdentifier";
  /** Config. */
  public static final String URI1 = "uri";
  /** Config. */
  public static final String URI2 = "uniformResourceId";
  /** Config. */
  public static final String IPADDR = "iPAddress";
  /** Config. */
  public static final String DIRECTORYNAME = "directoryName";
  /** Config. */
  public static final String REGISTEREDID = "registeredID";
  /** Config. */
  public static final String XMPPADDR = "xmppAddr";
  /** Config. */
  public static final String SRVNAME = "srvName";
  /** Config. */
  public static final String FASCN = "fascN";

  /** Kerberos altName for smart card logon. */
  public static final String KRB5PRINCIPAL = "krb5principal";
  /** OID for Kerberos altName for smart card logon. */
  public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
  /** Microsoft altName for windows smart card logon. */
  public static final String UPN = "upn";
  /** ObjectID for upn altName for windows smart card logon.*/
  public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
  /** ObjectID for XmppAddr, rfc6120#section-13.7.1.4. */
  public static final String XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
  /** ObjectID for srvName, rfc4985. */
  public static final String SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
  /** ID. */
  public static final String PERMANENTIDENTIFIER = "permanentIdentifier";
  /** ASN.i ID. */
  public static final String PERMANENTIDENTIFIER_OBJECTID = "1.3.6.1.5.5.7.8.3";
  /** Separator. */
  public static final String PERMANENTIDENTIFIER_SEP = "/";
  /** ASN.i ID. */
  public static final String FASCN_OBJECTID = "2.16.840.1.101.3.6.6";

  /** Microsoft altName for windows domain controller guid. */
  public static final String GUID = "guid";
  /** ObjectID for upn altName for windows domain controller guid. */
  public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
  /**
   * ObjectID for Microsoft Encrypted File System Certificates extended key
   * usage.
   */
  public static final String EFS_OBJECTID = "1.3.6.1.4.1.311.10.3.4";
  /**
   * ObjectID for Microsoft Encrypted File System Recovery Certificates extended
   * key usage.
   */
  public static final String EFSR_OBJECTID = "1.3.6.1.4.1.311.10.3.4.1";
  /** ObjectID for Microsoft Signer of documents extended key usage. */
  public static final String MS_DOCUMENT_SIGNING_OBJECTID =
      "1.3.6.1.4.1.311.10.3.12";
  /** Object id id-pkix. */
  public static final String ID_PKIX = "1.3.6.1.5.5.7";
  /** Object id id-kp. */
  public static final String ID_KP = ID_PKIX + ".3";
  /** Object id id-pda. */
  public static final String ID_PDA = ID_PKIX + ".9";
  /** Object id id-pda-dateOfBirth DateOfBirth ::= GeneralizedTime .*/
  public static final String ID_PDA_DATE_OF_BIRTH = ID_PDA + ".1";
  /** Object id id-pda-placeOfBirth PlaceOfBirth ::= DirectoryString. */
  public static final String ID_PDA_PLACE_OF_BIRTH = ID_PDA + ".2";
  /**
   * Object id id-pda-gender Gender ::= PrintableString (SIZE(1)) -- "M", "F",
   * "m" or "f".
   */
  public static final String ID_PDA_GENDER = ID_PDA + ".3";
  /**
   * Object id id-pda-countryOfCitizenship CountryOfCitizenship ::=
   * PrintableString (SIZE (2)) -- ISO 3166 Country Code.
   */
  public static final String ID_PDA_COUNTRY_OF_CITIZENSHIP = ID_PDA + ".4";
  /**
   * Object id id-pda-countryOfResidence CountryOfResidence ::= PrintableString
   * (SIZE (2)) -- ISO 3166 Country Code.
   */
  public static final String ID_PDA_COUNTRY_OF_RESIDENCE = ID_PDA + ".5";
  /** OID used for creating MS Templates certificate extension .*/
  public static final String OID_MSTEMPLATE = "1.3.6.1.4.1.311.20.2";
  /** extended key usage OID Intel AMT (out of band) network management. */
  public static final String INTEL_AMT = "2.16.840.1.113741.1.2.3";

  /** Object ID for CT (Certificate Transparency) specific extensions. */
  public static final String ID_CT_REDACTED_DOMAINS = "1.3.6.1.4.1.11129.2.4.6";
 /** IDs. */
  private static final String[] EMAILIDS = {EMAIL, EMAIL1, EMAIL2, EMAIL3};
 /** Regex. */
  private static final Pattern UNESCAPE_FIELD_REGEX =
      Pattern.compile("\\\\([,+\"\\\\<>; ])");

  /** delimiter. */
  public static final String BEGIN_CERTIFICATE_REQUEST =
      "-----BEGIN CERTIFICATE REQUEST-----";
  /** delimiter. */
  public static final String END_CERTIFICATE_REQUEST =
      "-----END CERTIFICATE REQUEST-----";
  /** delimiter. */
  public static final String BEGIN_KEYTOOL_CERTIFICATE_REQUEST =
      "-----BEGIN NEW CERTIFICATE REQUEST-----";
  /** delimiter. */
  public static final String END_KEYTOOL_CERTIFICATE_REQUEST =
      "-----END NEW CERTIFICATE REQUEST-----";
  /** delimiter. */
  public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
  /** delimiter. */
  public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
  /** delimiter. */
  public static final String BEGIN_CERTIFICATE_WITH_NL =
      "-----BEGIN CERTIFICATE-----\n";
  /** delimiter. */
  public static final String END_CERTIFICATE_WITH_NL =
      "\n-----END CERTIFICATE-----\n";
  /** delimiter. */
  public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
  /** delimiter. */
  public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
  /** delimiter. */
  public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
  /** delimiter. */
  public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
  /** delimiter. */
  public static final String BEGIN_X509_CRL_KEY = "-----BEGIN X509 CRL-----";
  /** delimiter. */
  public static final String END_X509_CRL_KEY = "-----END X509 CRL-----";
  /** delimiter. */
  public static final String BEGIN_PKCS7 = "-----BEGIN PKCS7-----";
  /** delimiter. */
  public static final String END_PKCS7 = "-----END PKCS7-----";

  /**
   * See stringToBcX500Name(String, X500NameStyle, boolean), this method uses
   * the default name style (CeSecoreNameStyle) and ldap order.
   *
   * @see #stringToBcX500Name(String, X500NameStyle, boolean)
   * @param dn String containing DN that will be transformed into X500Name, The
   *     DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in the
   *     string will be added to the end positions of OID array.
   * @return X500Name, which can be empty if dn does not contain any real DN
   *     components, or null if input is null
   */
  public static X500Name stringToBcX500Name(final String dn) {
    final X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
    return stringToBcX500Name(dn, nameStyle, true);
  }

  /**
   * See stringToBcX500Name(String, X500NameStyle, boolean), this method uses
   * the default name style (CeSecoreNameStyle) and ldap order.
   *
   * @see #stringToBcX500Name(String, X500NameStyle, boolean)
   * @param dn String containing DN that will be transformed into X500Name, The
   *     DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in the
   *     string will be added to the end positions of OID array.
   * @param ldapOrder true if X500Name should be in Ldap Order
   * @return X500Name, which can be empty if dn does not contain any real DN
   *     components, or null if input is null
   */
  public static X500Name stringToBcX500Name(
      final String dn, final boolean ldapOrder) {
    final X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
    return stringToBcX500Name(dn, nameStyle, ldapOrder);
  }

  /**
   * Creates a (Bouncycastle) X500Name object from a string with a DN. Known OID
   * (with order) are: <code>
   *  EmailAddress, UID, CN, SN (SerialNumber),
   *   GivenName, Initials, SurName, T, OU,
   * O, L, ST, DC, C </code> To change order edit 'dnObjects' in this source
   * file. Important NOT to mess with the ordering within this class, since cert
   * vierification on some clients (IE :-() might depend on order.
   *
   * @param dn String containing DN that will be transformed into X500Name, The
   *     DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in the
   *     string will be added to the end positions of OID array.
   * @param nameStyle Controls how the name is encoded. Usually it should be a
   *     CeSecoreNameStyle.
   * @param ldaporder true if LDAP ordering of DN should be used (default in
   *     EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
   *     order is the reverse
   * @return X500Name, which can be empty if dn does not contain any real DN
   *     components, or null if input is null
   * @throws IllegalArgumentException if DN is not valid
   */
  public static X500Name stringToBcX500Name(
      final String dn, final X500NameStyle nameStyle, final boolean ldaporder) {
    return stringToBcX500Name(dn, nameStyle, ldaporder, null);
  }
  /**
   * Same as @see {@link CertTools#stringToBcX500Name(String, X500NameStyle,
   * boolean)} but with the possibility of specifying a custom order. ONLY to be
   * used when creating names that are transient, never for storing in the
   * database.
   *
   * @param dn String containing DN that will be transformed into X500Name, The
   *     DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in the
   *     string will be added to the end positions of OID array.
   * @param nameStyle Controls how the name is encoded. Usually it should be a
   *     CeSecoreNameStyle.
   * @param ldaporder true if LDAP ordering of DN should be used (default in
   *     EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
   *     order is the reverse
   * @param order specified order, which overrides 'ldaporder', care must be
   *     taken constructing this String array, ignored if null or empty
   * @return X500Name, which can be empty if dn does not contain any real DN
   *     components, or null if input is null
   */
  public static X500Name stringToBcX500Name(
      final String dn,
      final X500NameStyle nameStyle,
      final boolean ldaporder,
      final String[] order) {
    return stringToBcX500Name(dn, nameStyle, ldaporder, order, true);
  }

  /**
   * @param dn DN
   * @param nameStyle Style
   * @param ldaporder Order
   * @param order Order
   * @param applyLdapToCustomOrder Bool
   * @return Name
   */
  public static X500Name stringToBcX500Name(
      final String dn,
      final X500NameStyle nameStyle,
      final boolean ldaporder,
      final String[] order,
      final boolean applyLdapToCustomOrder) {
    final X500Name x500Name = stringToUnorderedX500Name(dn, nameStyle);
    if (x500Name == null) {
      return null;
    }
    // -- Reorder fields
    final X500Name orderedX500Name =
        getOrderedX500Name(
            x500Name, ldaporder, order, applyLdapToCustomOrder, nameStyle);
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(
          ">stringToBcX500Name: x500Name="
              + x500Name.toString()
              + " orderedX500Name="
              + orderedX500Name.toString());
    }
    return orderedX500Name;
  }

  /**
   * @param odn DN
   * @param nameStyle Style
   * @return Name
   */
  public static X500Name stringToUnorderedX500Name(
      final String odn, final X500NameStyle nameStyle) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">stringToUnorderedX500Name: " + odn);
    }
    if (odn == null) {
      return null;
    }
    // If the entire DN is quoted (which is strange but legacy), we just remove
    // these quotes and carry on
    String dn = unquoteDN(odn);
    final X500NameBuilder nameBuilder = createNameBuilder(nameStyle, dn);
    final X500Name x500Name = nameBuilder.build();
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<stringToUnorderedX500Name: x500Name="
              + x500Name.toString());
    }
    return x500Name;
  }

/**
 * @param nameStyle style
 * @param dn DN
 * @return Builder
 */
private static X500NameBuilder createNameBuilder(final X500NameStyle nameStyle,
        final String dn) {
    final X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
    boolean quoted = false;
    boolean escapeNext = false;
    int currentStartPosition = -1;
    String currentPartName = null;
    for (int i = 0; i < dn.length(); i++) {
      final char current = dn.charAt(i);
      // Toggle quoting for every non-escaped "-char
      quoted = toggleQuoted(quoted, escapeNext, current);
      // If there is an unescaped and unquoted =-char the proceeding chars is a
      // part name
      if (currentStartPosition == -1
          && !quoted
          && !escapeNext
          && current == '='
          && 1 <= i) {
        // Trim spaces (e.g. "O =value")
        int endIndexOfPartName = getEndOfPN(dn, i);
        int startIndexOfPartName = getStartOfPN(dn, endIndexOfPartName);
        currentPartName =
            dn.substring(startIndexOfPartName, endIndexOfPartName);
        currentStartPosition = i + 1;
      }
      // When we have found a start marker, we need to be on the lookout for the
      // ending marker
      if (currentStartPosition != -1
          && (!quoted && !escapeNext && (current == ',' || current == '+')
              || i == dn.length() - 1)) {
        int endPosition = (i == dn.length() - 1) ? dn.length() - 1 : i - 1;
        // Remove white spaces from the end of the value
        endPosition = stripEnd(dn, currentStartPosition, endPosition);
        // Remove white spaces from the beginning of the value
        currentStartPosition = stripStart(dn,
                currentStartPosition, endPosition);
        // Only return the inner value if the part is quoted
        if (currentStartPosition < dn.length()
            && dn.charAt(currentStartPosition) == '"'
            && dn.charAt(endPosition) == '"') {
          currentStartPosition++;
          endPosition--;
        }
        String currentValue =
            dn.substring(currentStartPosition, endPosition + 1);
        // Unescape value (except escaped #) since the nameBuilder will double
        // each escape
        currentValue =
            unescapeValue(new StringBuilder(currentValue)).toString();
        handleOID(nameBuilder, currentPartName, currentValue);
        // Reset markers
        currentStartPosition = -1;
        currentPartName = null;
      }
      escapeNext = handleEscapeNext(quoted, escapeNext, current);
    }
    return nameBuilder;
}

/**
 * @param quoted bool
 * @param escapeNext bool
 * @param current char
 * @return bool
 */
private static boolean toggleQuoted(
        final boolean quoted, final boolean escapeNext, final char current) {
    if (!escapeNext && current == '"') {
        return !quoted;
      }
    return quoted;
}

/**
 * @param odn DN
 * @return DN
 */
private static String unquoteDN(final String odn) {
    String dn;
        if (odn.length() > 2
            && odn.charAt(0) == '"'
            && odn.charAt(odn.length() - 1) == '"') {
          dn = odn.substring(1, odn.length() - 1);
        } else {
            dn = odn;
        }
    return dn;
}

/**
 * @param quoted  Bool
 * @param oe Bool
 * @param current char
 * @return bool
 */
private static boolean handleEscapeNext(final boolean quoted,
        final boolean oe, final char current) {
    boolean e = oe;
    if (e) {
        // This character was escaped, so don't escape the next one
        e = false;
      } else {
        if (!quoted && current == '\\') {
          // This escape character is not escaped itself, so the next one should
          // be
          e = true;
        }
      }
    return e;
}

/**
 * @param nameBuilder name
 * @param currentPartName part
 * @param currentValue val
 */
private static void handleOID(final X500NameBuilder nameBuilder,
        final String currentPartName, final String currentValue) {
    try {
      // -- First search the OID by name in declared OID's
      ASN1ObjectIdentifier oid = DnComponents.getOid(currentPartName);
      // -- If isn't declared, we try to create it
      if (oid == null) {
        oid = new ASN1ObjectIdentifier(currentPartName);
      }
      nameBuilder.addRDN(oid, currentValue);
    } catch (final IllegalArgumentException e) {
      // If it is not an OID we will ignore it
      LOGGER.warn(
          "Unknown DN component ignored and silently dropped: "
              + currentPartName);
    }
}

/**
 * @param dn DN
 * @param c Pos
 * @param endPosition End
 * @return Start
 */
private static int stripStart(final String dn,
        final int c, final int endPosition) {
    int i = c;
    while (endPosition > i
        && dn.charAt(i) == ' ') {
      i++;
    }
    return i;
}

/**
 * @param dn DN
 * @param currentStartPosition Start
 * @param e End
 * @return End
 */
private static int stripEnd(final String dn,
        final int currentStartPosition, final int e) {
    int i = e;
    while (i > currentStartPosition
        && dn.charAt(i) == ' ') {
      i--;
    }
    return i;
}

/**
 * @param dn EN
 * @param endIndexOfPartName End
 * @return Start
 */
private static int getStartOfPN(final String dn, final int endIndexOfPartName) {
    int startIndexOfPartName = endIndexOfPartName - 1;
    final String endOfPartNameSearchChars = ", +";
    while (startIndexOfPartName > 0
        && endOfPartNameSearchChars.indexOf(
                dn.charAt(startIndexOfPartName - 1))
            == -1) {
      startIndexOfPartName--;
    }
    return startIndexOfPartName;
}

/**
 * @param dn DN
 * @param i Start
 * @return End
 */
private static int getEndOfPN(final String dn, final int i) {
    int endIndexOfPartName = i;
    while (endIndexOfPartName > 0
        && dn.charAt(endIndexOfPartName - 1) == ' ') {
      endIndexOfPartName--;
    }
    return endIndexOfPartName;
}

  /**
   * Removes any unescaped '\' character from the provided StringBuilder.
   * Assumes that escaping quotes have been stripped. Special treatment of the #
   * sign, which if not escaped will be treated as hex encoded DER value by BC.
   *
   * @param sb unescaped StringBuilder
   * @return escaped StringBuilder
   */
  private static StringBuilder unescapeValue(final StringBuilder sb) {
    boolean esq = false;
    int index = 0;
    while (index < (sb.length() - 1)) {
      if (!esq && sb.charAt(index) == '\\' && sb.charAt(index + 1) != '#') {
        esq = true;
        sb.deleteCharAt(index);
      } else {
        esq = false;
        index++;
      }
    }
    return sb;
  }

/** Remove extra '+' character escaping.
 *
 * @param value value
 * @return unescaped
 */
  public static String getUnescapedPlus(final String value) {
    final StringBuilder buf = new StringBuilder(value);
    int index = 0;
    int end = buf.length();
    while (index < end) {
      if (buf.charAt(index) == '\\' && index + 1 != end) {
        final char c = buf.charAt(index + 1);
        if (c == '+') {
          buf.deleteCharAt(index);
          end--;
        }
      }
      index++;
    }
    return buf.toString();
  }

  /**
   * Check if the String contains any unescaped '+'. RFC 2253, section 2.2
   * states that '+' is used for multi-valued RelativeDistinguishedName. BC
   * (version 1.45) did not support multi-valued RelativeDistinguishedName, and
   * automatically escaped them instead. Even though it is now (BC 1.49b15)
   * supported, we want to keep ecaping '+' chars and warn that this might not
   * be supported in the future.
   *
   * @param dn DN
   * @return escaped DN
   */
  public static String handleUnescapedPlus(final String dn) {
    if (dn == null) {
      return dn;
    }
    final StringBuilder buf = new StringBuilder(dn);
    int index = 0;
    final int end = buf.length();
    while (index < end) {
      if (buf.charAt(index) == '+') {
        // Found an unescaped '+' character.
        LOGGER.warn(
            "DN \""
                + dn
                + "\" contains an unescaped '+'-character that will be"
                + " automatically escaped. RFC 2253 reservs this for"
                + " multi-valued RelativeDistinguishedNames. Encourage clients"
                + " to use '\\+' instead, since future behaviour might"
                + " change.");
        buf.insert(index, '\\');
        index++;
      } else if (buf.charAt(index) == '\\') {
        // Found an escape character.
        index++;
      }
      index++;
    }
    return buf.toString();
  }

  /**
   * Every DN-string should look the same. Creates a name string ordered and
   * looking like we want it...
   *
   * @param odn String containing DN
   * @return String containing DN, or empty string if dn does not contain any
   *     real DN components, or null if input is null
   */
  public static String stringToBCDNString(final String odn) {
    // BC now seem to handle multi-valued RDNs, but we keep escaping this for
    // now to keep the behavior until support is required
    String dn = handleUnescapedPlus(odn);
        // Log warning if dn contains unescaped '+'
    if (isDNReversed(dn)) {
      dn = reverseDN(dn);
    }
    String ret = null;
    final X500Name name = stringToBcX500Name(dn);
    if (name != null) {
      ret = name.toString();
    }
    /*
     * For some databases (MySQL for instance) the database column
     *  holding subjectDN is only 250 chars long. There have been strange error
     * reported (clipping DN naturally) that is hard to debug if DN is
     *  more than 250 chars and we don't have a good message
     */
    final int maxLength = 250;
    if (ret != null && ret.length() > maxLength) {
      LOGGER.info(
          "Warning! DN is more than 250 characters long. Some databases have"
              + " only 250 characters in the database for SubjectDN. Clipping"
              + " may occur! DN ("
              + ret.length()
              + " chars): "
              + ret);
    }
    return ret;
  }

  /**
   * Convenience method for getting an email addresses from a DN. Uses {@link
   * #getPartsFromDN(String,String)} internally, and searches for {@link
   * #EMAIL}, {@link #EMAIL1}, {@link #EMAIL2}, {@link #EMAIL3} and returns the
   * first one found.
   *
   * @param dn the DN
   * @return ArrayList containing email or empty list if email is not present
   */
  public static ArrayList<String> getEmailFromDN(final String dn) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getEmailFromDN(" + dn + ")");
    }
    final ArrayList<String> ret = new ArrayList<String>();
    for (int i = 0; i < EMAILIDS.length; i++) {
      final List<String> emails = getPartsFromDN(dn, EMAILIDS[i]);
      if (!emails.isEmpty()) {
        ret.addAll(emails);
      }
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<getEmailFromDN(" + dn + "): " + ret.size());
    }
    return ret;
  }

  /**
   * Search for e-mail address, first in SubjectAltName (as in PKIX
   * recommendation) then in subject DN. Original author: Marco Ferrante, (c)
   * 2005 CSITA - University of Genoa (Italy)
   *
   * @param certificate certificate
   * @return subject email or null if not present in certificate
   */
  public static String getEMailAddress(final Certificate certificate) {
    LOGGER.debug("Searching for EMail Address in SubjectAltName");
    if (certificate == null) {
      return null;
    }
    if (certificate instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) certificate;
      try {
        if (x509cert.getSubjectAlternativeNames() != null) {
          for (final List<?> item : x509cert.getSubjectAlternativeNames()) {
            final Integer type = (Integer) item.get(0);
            if (type.intValue() == 1) {
              return (String) item.get(1);
            }
          }
        }
      } catch (final CertificateParsingException e) {
        LOGGER.error("Error parsing certificate: ", e);
      }
      LOGGER.debug("Searching for EMail Address in Subject DN");
      final ArrayList<String> emails =
          CertTools.getEmailFromDN(x509cert.getSubjectDN().getName());
      if (!emails.isEmpty()) {
        return emails.get(0);
      }
    }
    return null;
  }

  /**
   * Takes a DN and reverses it completely so the first attribute ends up last.
   * C=SE,O=Foo,CN=Bar becomes CN=Bar,O=Foo,C=SE.
   *
   * @param dn String containing DN to be reversed, The DN string has the format
   *     "C=SE, O=xx, OU=yy, CN=zz".
   * @return String containing reversed DN
   */
  public static String reverseDN(final String dn) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">reverseDN: dn: " + dn);
    }
    String ret = null;
    if (dn != null) {
      String o;
      final BasicX509NameTokenizer xt = new BasicX509NameTokenizer(dn);
      final StringBuilder buf = new StringBuilder();
      boolean first = true;
      while (xt.hasMoreTokens()) {
        o = xt.nextToken();
        // log.debug("token: "+o);
        if (!first) {
          buf.insert(0, ",");
        } else {
          first = false;
        }
        buf.insert(0, o);
      }
      if (buf.length() > 0) {
        ret = buf.toString();
      }
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<reverseDN: resulting dn: " + ret);
    }
    return ret;
  }

  /**
   * Tries to determine if a DN is in reversed form. It does this by taking the
   * last attribute and the first attribute. If the last attribute comes before
   * the first in the dNObjects array the DN is assumed to be in reversed order.
   *
   * <p>The default ordering is: "CN=Tomas, O=PrimeKey, C=SE" (dNObjectsForward
   * ordering in EJBCA) a dn or form "C=SE, O=PrimeKey, CN=Tomas" is reversed.
   *
   * <p>If the string has only one component (e.g. "CN=example.com") then this
   * method returns false. If the string does not contain any real DN
   * components, it returns false.
   *
   * @param dn String containing DN to be checked, The DN string has the format
   *     "C=SE, O=xx, OU=yy, CN=zz".
   * @return true if the DN is believed to be in reversed order, false otherwise
   */
  public static boolean isDNReversed(final String dn) {
    /*
     * if (log.isTraceEnabled()) { log.trace(">isDNReversed: dn: " + dn); }
     */
    boolean ret = false;
    if (dn != null) {
      String first = null;
      String last = null;
      final X509NameTokenizer xt = new X509NameTokenizer(dn);
      if (xt.hasMoreTokens()) {
        first = xt.nextToken().trim();
      }
      while (xt.hasMoreTokens()) {
        last = xt.nextToken().trim();
      }
      final String[] dNObjects = DnComponents.getDnObjects(true);
      if (first != null && last != null) {
        // Be careful for bad input, that may not have any = sign in it
        final int fi = first.indexOf('=');
        first = first.substring(0, fi != -1 ? fi : first.length() - 1);
        final int li = last.indexOf('=');
        last = last.substring(0, li != -1 ? li : last.length() - 1);
        int firsti = 0;
        int lasti = 0;
        for (int i = 0; i < dNObjects.length; i++) {
          if (first.equalsIgnoreCase(dNObjects[i])) {
            firsti = i;
          }
          if (last.equalsIgnoreCase(dNObjects[i])) {
            lasti = i;
          }
        }
        if (lasti < firsti) {
          ret = true;
        }
      }
    }
    /*
     * if (log.isTraceEnabled()) { log.trace("<isDNReversed: " + ret); }
     */
    return ret;
  } // isDNReversed

  /**
   * Checks if a DN has at least two components. Then the DN can be in either
   * LDAP or X500 order. Otherwise it's not possible to determine the order.
   *
   * @param dn DN
   * @return boolean
   */
  public static boolean dnHasMultipleComponents(final String dn) {
    final X509NameTokenizer xt = new X509NameTokenizer(dn);
    if (xt.hasMoreTokens()) {
      xt.nextToken();
      return xt.hasMoreTokens();
    }
    return false;
  }

  /**
   * Gets a specified part of a DN. Specifically the first occurrence it the DN
   * contains several instances of a part (i.e. cn=x, cn=y returns x).
   *
   * @param dn String containing DN, The DN string has the format "C=SE, O=xx,
   *     OU=yy, CN=zz".
   * @param dnpart String specifying which part of the DN to get, should be "CN"
   *     or "OU" etc.
   * @return String containing dnpart or null if dnpart is not present
   */
  public static String getPartFromDN(final String dn, final String dnpart) {
    String part = null;
    final List<String> dnParts = getPartsFromDNInternal(dn, dnpart, true);
    if (!dnParts.isEmpty()) {
      part = dnParts.get(0);
    }
    return part;
  }

  /**
   * Gets a specified parts of a DN. Returns all occurrences as an ArrayList,
   * also works if DN contains several instances of a part (i.e. cn=x, cn=y
   * returns {x, y, null}).
   *
   * @param dn String containing DN, The DN string has the format "C=SE, O=xx,
   *     OU=yy, CN=zz".
   * @param dnpart String specifying which part of the DN to get, should be "CN"
   *     or "OU" etc.
   * @return ArrayList containing dnparts or empty list if dnpart is not present
   */
  public static List<String> getPartsFromDN(
          final String dn, final String dnpart) {
    return getPartsFromDNInternal(dn, dnpart, false);
  }

  /**
   * @param dn DN
   * @param dnPart Part
   * @param onlyReturnFirstMatch bool
   * @return parts
   */
  public static List<String> getPartsFromDNInternal(
      final String dn,
      final String dnPart,
      final boolean onlyReturnFirstMatch) {
    logPartsBegin(dn, dnPart, onlyReturnFirstMatch);
    final List<String> parts = new ArrayList<String>();
    if (dn != null && dnPart != null) {
      final String dnPartLowerCase = dnPart.toLowerCase();
      final int dnPartLenght = dnPart.length();
      boolean quoted = false;
      boolean escapeNext = false;
      int currentStartPosition = -1;
      for (int i = 0; i < dn.length(); i++) {
        final char current = dn.charAt(i);
        quoted = toggleQuoted(quoted, escapeNext, current);
        // If there is an unescaped and unquoted =-char we need to investigate
        // if it is a match for the sought after part
        if (!quoted && !escapeNext && current == '=' && dnPartLenght <= i
                && (i - dnPartLenght - 1 < 0
              || !Character.isLetter(dn.charAt(i - dnPartLenght - 1)))) {
            boolean match = isMatch(dn, dnPartLowerCase, dnPartLenght, i);
            if (match) {
              currentStartPosition = i + 1;
            }

        }
        // When we have found a start marker, we need to be on the lookout for
        // the ending marker
        if (currentStartPosition != -1
            && (!quoted && !escapeNext && (current == ',' || current == '+')
                || i == dn.length() - 1)) {
          int endPosition = (i == dn.length() - 1) ? dn.length() - 1 : i - 1;
          endPosition = stripEnd(dn, currentStartPosition, endPosition);
          currentStartPosition = stripStart(dn,
                  currentStartPosition, endPosition);
          // Only return the inner value if the part is quoted
          if (currentStartPosition != dn.length()
              && dn.charAt(currentStartPosition) == '"'
              && dn.charAt(endPosition) == '"') {
            currentStartPosition++;
            endPosition--;
          }
          parts.add(
              unescapeFieldValue(
                  dn.substring(currentStartPosition, endPosition + 1)));
          if (onlyReturnFirstMatch) {
            break;
          }
          currentStartPosition = -1;
        }
        escapeNext = handleEscapeNext(quoted, escapeNext, current);
      }
    }
    logPartsEnd(parts);
    return parts;
  }

/**
 * @param parts parts
 */
private static void logPartsEnd(final List<String> parts) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(
          "<getPartsFromDNInternal: resulting DN part=" + parts.toString());
    }
}

/**
 * @param dn DN
 * @param dnPart Part
 * @param onlyReturnFirstMatch bool
 */
private static void logPartsBegin(final String dn,
        final String dnPart, final boolean onlyReturnFirstMatch) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(
          ">getPartsFromDNInternal: dn:'"
              + dn
              + "', dnpart="
              + dnPart
              + ", onlyReturnFirstMatch="
              + onlyReturnFirstMatch);
    }
}

/**
 * @param dn DN
 * @param dnPartLowerCase LS
 * @param dnPartLength Length
 * @param i Pos
 * @return bool
 */
private static boolean isMatch(final String dn, final String dnPartLowerCase,
        final int dnPartLength, final int i) {
    boolean match = true;
    for (int j = 0; j < dnPartLength; j++) {
      if (Character.toLowerCase(dn.charAt(i - dnPartLength + j))
          != dnPartLowerCase.charAt(j)) {
        match = false;
        break;
      }
    }
    return match;
}

  /**
   * Gets a list of all custom OIDs defined in the string. A custom OID is
   * defined as an OID, simply as that. Otherwise, if it is not a custom oid,
   * the DNpart is defined by a name such as CN och rfc822Name. This method only
   * returns a oid once, so if the input string has multiple of the same oid,
   * only one value is returned.
   *
   * @param dn String containing DN, The DN string has the format "C=SE, O=xx,
   *     OU=yy, CN=zz", or "rfc822Name=foo@bar.com", etc.
   * @return ArrayList containing unique oids or empty list if no custom OIDs
   *     are present
   */
  public static ArrayList<String> getCustomOids(final String dn) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getCustomOids: dn:'" + dn);
    }
    final ArrayList<String> parts = new ArrayList<String>();
    if (dn != null) {
      String o;
      final X509NameTokenizer xt = new X509NameTokenizer(dn);
      while (xt.hasMoreTokens()) {
        o = xt.nextToken().trim();
        // Try to see if it is a valid OID
        try {
          final int i = o.indexOf('=');
          // An oid is never shorter than 3 chars and must start with 1.
          if (i > 2 && o.charAt(1) == '.') {
            final String oid = o.substring(0, i);
            // If we have multiple of the same custom oid, don't claim that we
            // have more
            // This method will only return "unique" custom oids.
            if (!parts.contains(oid)) {
              // Check if it is a real oid, if it is not we will ignore it
              // (IllegalArgumentException will be thrown)
              new ASN1ObjectIdentifier(oid);
              parts.add(oid);
            }
          }
        } catch (final IllegalArgumentException e) { // NOPMD
          // Not a valid oid
        }
      }
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<getCustomOids: resulting DN part=" + parts.toString());
    }
    return parts;
  }

  /**
   * Gets subject DN in the format we are sure about (BouncyCastle),supporting
   * UTF8.
   *
   * @param cert Certificate
   * @return String containing the subjects DN.
   */
  public static String getSubjectDN(final Certificate cert) {
    return getDN(cert, 1);
  }

  /**
   * @param value String to enescape
   * @return value in unescaped RDN format
   */
  public static String getUnescapedRdnValue(final String value) {
    if (StringUtils.isNotEmpty(value)) {
      return org.ietf.ldap.LDAPDN.unescapeRDN(value);
    } else {
      return value;
    }
  }

  /**
   * Gets issuer DN in the format we are sure about (BouncyCastle),supporting
   * UTF8.
   *
   * @param cert Certificate
   * @return String containing the issuers DN.
   */
  public static String getIssuerDN(final Certificate cert) {
    return getDN(cert, 2);
  }

  /**
   * Gets subject or issuer DN in the format we are sure about
   * (BouncyCastle),supporting UTF8.
   *
   * @param cert X509Certificate
   * @param which 1 = subjectDN, anything else = issuerDN
   * @return String containing the DN.
   */
  private static String getDN(final Certificate cert, final int which) {
    String ret = null;
    if (cert == null) {
      return null;
    }
    if (cert instanceof X509Certificate) {
      // cert.getType=X.509
      try {
        final String clazz = cert.getClass().getName();
        // The purpose of the below generateCertificate is to create a BC
        // certificate object, because there we know how DN components
        // are handled. If we already have a BC certificate however, we can save
        // a lot of time to not have to encode/decode it.
        final X509Certificate x509cert;
        if (clazz.contains("org.bouncycastle")) {
          x509cert = (X509Certificate) cert;
        } else {
          final CertificateFactory cf = CertTools.getCertificateFactory();
          x509cert =
              (X509Certificate)
                  cf.generateCertificate(
                      new ByteArrayInputStream(cert.getEncoded()));
        }
        String dn = null;
        if (which == 1) {
          dn = x509cert.getSubjectDN().toString();
        } else {
          dn = x509cert.getIssuerDN().toString();
        }
        ret = stringToBCDNString(dn);
      } catch (final CertificateException ce) {
        LOGGER.info("Could not get DN from X509Certificate. "
                + ce.getMessage());
        LOGGER.debug("", ce);
        return null;
      }
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      final CardVerifiableCertificate cvccert =
          (CardVerifiableCertificate) cert;
      try {
        ReferenceField rf = null;
        if (which == 1) {
          rf =
              cvccert
                  .getCVCertificate()
                  .getCertificateBody()
                  .getHolderReference();
        } else {
          rf =
              cvccert
                  .getCVCertificate()
                  .getCertificateBody()
                  .getAuthorityReference();
        }
        if (rf != null) {
          // Construct a "fake" DN which can be used in EJBCA
          // Use only mnemonic and country, since sequence is more of a
          // serialnumber than a DN part
          String dn = "";
          if (rf.getMnemonic() != null) {
            if (StringUtils.isNotEmpty(dn)) {
              dn += ", ";
            }
            dn += "CN=" + rf.getMnemonic();
          }
          if (rf.getCountry() != null) {
            if (StringUtils.isNotEmpty(dn)) {
              dn += ", ";
            }
            dn += "C=" + rf.getCountry();
          }
          ret = stringToBCDNString(dn);
        }
      } catch (final NoSuchFieldException e) {
        LOGGER.error("NoSuchFieldException: ", e);
        return null;
      }
    }
    return ret;
  }

  /**
   * Gets Serial number of the certificate.
   *
   * @param cert Certificate
   * @return BigInteger containing the certificate serial number. Can be 0 for
   *     CVC certificates with alphanumeric serial numbers if the sequence does
   *     not contain any number characters at all.
   * @throws IllegalArgumentException if null input of certificate type is not
   *     handled
   */
  public static BigInteger getSerialNumber(final Certificate cert) {
    if (cert == null) {
      throw new IllegalArgumentException("Null input");
    }
    BigInteger ret = null;
    if (cert instanceof X509Certificate) {
      final X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getSerialNumber();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      // For CVC certificates the sequence field of the HolderReference is kind
      // of a serial number,
      // but if can be alphanumeric which means it can not be made into a
      // BigInteger
      final CardVerifiableCertificate cvccert =
              (CardVerifiableCertificate) cert;
      try {
        final String sequence =
            cvccert
                .getCVCertificate()
                .getCertificateBody()
                .getHolderReference()
                .getSequence();
        ret = getSerialNumberFromString(sequence);
      } catch (final NoSuchFieldException e) {
        LOGGER.error("getSerialNumber: NoSuchFieldException: ", e);
        ret = BigInteger.valueOf(0);
      }
    } else {
      throw new IllegalArgumentException(
          "getSerialNumber: Certificate of type "
              + cert.getType()
              + " is not implemented");
    }
    return ret;
  }

  /**
   * Gets a serial number in numeric form, it takes - either a hex encoded
   * integer with length != 5 (x.509 certificate) - 5 letter numeric string
   * (cvc), will convert the number to an int - 5 letter alfanumeric string vi
   * some numbers in it (cvc), will convert the numbers in it to a numeric
   * string (remove the letters) and convert to int - 5 letter alfanumeric
   * string with only letters (cvc), will convert to integer from string with
   * radix 36.
   *
   * @param sernoString serial
   * @return BigInteger
   */
  public static BigInteger getSerialNumberFromString(final String sernoString) {
    if (sernoString == null) {
      throw new IllegalArgumentException(
          "getSerialNumberFromString: cert is null");
    }
    BigInteger ret;
    try {
        final int cvcLength = 5;
      if (sernoString.length() != cvcLength) {
        // This can not be a CVC certificate sequence, so it must be a hex
        // encoded regular certificate serial number
        ret = new BigInteger(sernoString, 16);
      } else {
        // We try to handle the different cases of CVC certificate sequences,
        // see StringTools.KEY_SEQUENCE_FORMAT
        if (NumberUtils.isNumber(sernoString)) {
          ret = NumberUtils.createBigInteger(sernoString);
        } else {
          // check if input is hexadecimal
          LOGGER.info(
              "getSerialNumber: Sequence is not a numeric string, trying to"
                  + " extract numerical sequence part.");
          final StringBuilder buf = new StringBuilder();
          for (int i = 0; i < sernoString.length(); i++) {
            final char c = sernoString.charAt(i);
            if (CharUtils.isAsciiNumeric(c)) {
              buf.append(c);
            }
          }
          if (buf.length() > 0) {
            ret = NumberUtils.createBigInteger(buf.toString());
          } else {
            LOGGER.info(
                "getSerialNumber: can not extract numeric sequence part,"
                    + " trying alfanumeric value (radix 36).");
            if (sernoString.matches("[0-9A-Z]{1,5}")) {
              final int numSeq = Integer.parseInt(sernoString, 36);
              ret = BigInteger.valueOf(numSeq);
            } else {
              LOGGER.info(
                  "getSerialNumber: Sequence does not contain any numeric"
                      + " parts, returning 0.");
              ret = BigInteger.valueOf(0);
            }
          }
        }
      }
    } catch (final NumberFormatException e) {
      // If we can't make the sequence into a serial number big integer, set it
      // to 0
      LOGGER.debug(
          "getSerialNumber: NumberFormatException for sequence: "
              + sernoString);
      ret = BigInteger.valueOf(0);
    }
    return ret;
  }

  /**
   * Gets Serial number of the certificate as a string. For X509 Certificate
   * this means a HEX encoded BigInteger, and for CVC certificate is means the
   * sequence field of the holder reference.
   *
   * <p>For X509 certificates, the value is normalized (uppercase without
   * leading zeros), so there's no need to normalize the returned value.
   *
   * @param cert Certificate
   * @return String to be displayed, or used in RoleMember objects
   */
  public static String getSerialNumberAsString(final Certificate cert) {
    String ret = null;
    if (cert == null) {
      throw new IllegalArgumentException("getSerialNumber: cert is null");
    }
    if (cert instanceof X509Certificate) {
      final X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getSerialNumber().toString(16).toUpperCase();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      // For CVC certificates the sequence field of the HolderReference is kind
      // of a serial number,
      // but if can be alphanumeric which means it can not be made into a
      // BigInteger
      final CardVerifiableCertificate cvccert =
              (CardVerifiableCertificate) cert;
      try {
        ret =
            cvccert
                .getCVCertificate()
                .getCertificateBody()
                .getHolderReference()
                .getSequence();
      } catch (final NoSuchFieldException e) {
        LOGGER.error("getSerialNumber: NoSuchFieldException: ", e);
        ret = "N/A";
      }
    } else {
      throw new IllegalArgumentException(
          "getSerialNumber: Certificate of type "
              + cert.getType()
              + " is not implemented");
    }
    return ret;
  }

  /**
   * Gets the signature value (the raw signature bits) from the certificate. For
   * an X509 certificate this is the ASN.1 definition which is: signature BIT
   * STRING
   *
   * @param cert Certificate
   * @return byte[] containing the certificate signature bits, if cert is null a
   *     byte[] of size 0 is returned.
   */
  public static byte[] getSignature(final Certificate cert) {
    byte[] ret = null;
    if (cert == null) {
      ret = new byte[0];
    } else {
      if (cert instanceof X509Certificate) {
        final X509Certificate xcert = (X509Certificate) cert;
        ret = xcert.getSignature();
      } else if (StringUtils.equals(cert.getType(), "CVC")) {
        final CardVerifiableCertificate cvccert =
                (CardVerifiableCertificate) cert;
        try {
          ret = cvccert.getCVCertificate().getSignature();
        } catch (final NoSuchFieldException e) {
          LOGGER.error("NoSuchFieldException: ", e);
          return null;
        }
      }
    }
    return ret;
  }

  /**
   * Gets issuer DN for CRL in the format we are sure about
   * (BouncyCastle),supporting UTF8.
   *
   * @param crl X509RL
   * @return String containing the DN.
   */
  public static String getIssuerDN(final X509CRL crl) {
    String dn = null;
    try {
      final CertificateFactory cf = CertTools.getCertificateFactory();
      final X509CRL x509crl =
          (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl.getEncoded()));
      // log.debug("Created certificate of class: " +
      // x509crl.getClass().getName());
      dn = x509crl.getIssuerDN().toString();
    } catch (final CRLException ce) {
      LOGGER.error("CRLException: ", ce);
      return null;
    }
    return stringToBCDNString(dn);
  }

  /**
   * @param cert Cert
   * @return Start date
   */
  public static Date getNotBefore(final Certificate cert) {
    Date ret = null;
    if (cert == null) {
      throw new IllegalArgumentException("getNotBefore: cert is null");
    }
    if (cert instanceof X509Certificate) {
      final X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getNotBefore();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      final CardVerifiableCertificate cvccert =
              (CardVerifiableCertificate) cert;
      try {
        ret = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
      } catch (final NoSuchFieldException e) {
        // it is not uncommon that this field is missing in CVC certificate
        // requests (it's not in the EAC standard so)
        LOGGER.debug("NoSuchFieldException: " + e.getMessage());
        return null;
      }
    }
    return ret;
  }

  /**
   * @param cert Cert
   * @return Expiry
   */
  public static Date getNotAfter(final Certificate cert) {
    Date ret = null;
    if (cert == null) {
      throw new IllegalArgumentException("getNotAfter: cert is null");
    }
    if (cert instanceof X509Certificate) {
      final X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getNotAfter();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      final CardVerifiableCertificate cvccert =
          (CardVerifiableCertificate) cert;
      try {
        ret = cvccert.getCVCertificate().getCertificateBody().getValidTo();
      } catch (final NoSuchFieldException e) {
        // it is not uncommon that this field is missing in CVC certificate
        // requests (it's not in the EAC standard so)
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("NoSuchFieldException: " + e.getMessage());
        }
        return null;
      }
    }
    return ret;
  }

  /**
   * Returns a CertificateFactory that can be used to create certificates from
   * byte arrays and such.
   *
   * @param provider Security provider that should be used to create
   *     certificates, default BC is null is passed.
   * @return CertificateFactory
   */
  public static CertificateFactory getCertificateFactory(
      final String provider) {
    final String prov;
    if (provider == null) {
      prov = BouncyCastleProvider.PROVIDER_NAME;
    } else {
      prov = provider;
    }
    if (BouncyCastleProvider.PROVIDER_NAME.equals(prov)) {
      CryptoProviderUtil.installBCProviderIfNotAvailable();
    }
    try {
      return CertificateFactory.getInstance("X.509", prov);
    } catch (final NoSuchProviderException nspe) {
      LOGGER.error("NoSuchProvider: ", nspe);
    } catch (final CertificateException ce) {
      LOGGER.error("CertificateException: ", ce);
    }
    return null;
  }

  /**
   * @return factory
   */
  public static CertificateFactory getCertificateFactory() {
    return getCertificateFactory(BouncyCastleProvider.PROVIDER_NAME);
  }

  /**
   * Reads certificates in PEM-format from a filename. The stream may contain
   * other things between the different certificates.
   *
   * @param certFilename filename of the file containing the certificates in
   *     PEM-format
   * @return Ordered List of Certificates, first certificate first, or empty
   *     List
   * @throws FileNotFoundException if certFile was not found
   * @throws CertificateParsingException if the file contains an incorrect
   *     certificate.
   * @deprecated Use org.cesecore.util.CertTools.getCertsFromPEM(String,
   *     Class&lt;T&gt;) instead
   */
  @Deprecated
  public static List<Certificate> getCertsFromPEM(final String certFilename)
      throws FileNotFoundException, CertificateParsingException {
    return getCertsFromPEM(certFilename, Certificate.class);
  }

  /**
   * Reads certificates in PEM-format from a filename. The stream may contain
   * other things between the different certificates.
   *
   * @param certFilename filename of the file containing the certificates in
   *     PEM-format
   * @param returnType a Class specifying the desired return type. Certificate
   *     can be used if return type is unknown.
   * @param <T> type
   * @return Ordered List of Certificates, first certificate first, or empty
   *     List
   * @throws FileNotFoundException if certFile was not found
   * @throws CertificateParsingException if the file contains an incorrect
   *     certificate.
   */
  public static <T extends Certificate> List<T> getCertsFromPEM(
      final String certFilename, final Class<T> returnType)
      throws FileNotFoundException, CertificateParsingException {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getCertfromPEM: certFilename=" + certFilename);
    }
    InputStream inStrm = null;
    final List<T> certs;
    try {
      inStrm = new FileInputStream(certFilename);
      certs = getCertsFromPEM(inStrm, returnType);
    } finally {
      if (inStrm != null) {
        try {
          inStrm.close();
        } catch (final IOException e) {
          throw new IllegalStateException("Could not clode input stream", e);
        }
      }
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<getCertfromPEM: certFile=" + certFilename);
    }
    return certs;
  }

  /**
   * Reads a CA certificate and its certificate chain by a file. If it is a
   * chain it is a file with multiple PEM encoded certificates. A single
   * certificate is either in PEM or binary format.
   *
   * @param file the full path of the file.
   * @return a byte array containing one PEM or binary certificate, or all
   *     certificates in the chain in PEM format. First is the CA certificate,
   *     followed by its certificate chain.
   * @throws FileNotFoundException if the file cannot be found.
   * @throws IOException on IO error
   * @throws CertificateParsingException if a certificate could not be parsed.
   * @throws CertificateEncodingException if a certificate cannot be encoded.
   */
  public static final byte[] readCertificateChainAsArrayOrThrow(
      final String file)
      throws FileNotFoundException, IOException, CertificateParsingException,
          CertificateEncodingException {

    final List<byte[]> cachain = new ArrayList<byte[]>();
    try (FileInputStream fis = new FileInputStream(file)) {
      final Collection<Certificate> certs =
          CertTools.getCertsFromPEM(fis, Certificate.class);
      final Iterator<Certificate> iter = certs.iterator();
      while (iter.hasNext()) {
        final Certificate cert = iter.next();
        cachain.add(cert.getEncoded());
      }
    } catch (final CertificateParsingException e) {
      // It was perhaps not a PEM chain...see if it was a single binary
      // certificate
      final byte[] certbytes = FileTools.readFiletoBuffer(file);
      final Certificate cert =
          CertTools.getCertfromByteArray(
              certbytes,
              Certificate
                  .class); // check if it is a good cert, decode PEM if it is
                           // PEM, etc
      cachain.add(cert.getEncoded());
    }

    try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
      for (final byte[] bytes : cachain) {
        bos.write(bytes);
      }
      final byte[] result = bos.toByteArray();
      return result;
    }
  }

/**
 * @param bytes Bytes
 * @return Certs
 * @throws CertificateParsingException Fail
 */
  public static final List<CertificateWrapper>
      bytesToListOfCertificateWrapperOrThrow(final byte[] bytes)
          throws CertificateParsingException {
    Collection<Certificate> certs = null;
    try {
      certs =
          CertTools.getCertsFromPEM(
              new ByteArrayInputStream(bytes),
              Certificate.class);
    } catch (final CertificateException e) {
      LOGGER.debug("Input stream is not PEM certificate(s): " + e.getMessage());
      // See if it is a single binary certificate
      final Certificate cert =
          CertTools.getCertfromByteArray(
              bytes, Certificate.class);
      certs = new ArrayList<Certificate>();
      certs.add(cert);
    }
    return EJBUtil.wrapCertCollection(certs);
  }

  /**
   * Reads certificates in PEM-format from an InputStream. The stream may
   * contain other things between the different certificates.
   *
   * @param certstream the input stream containing the certificates in
   *     PEM-format
   * @return Ordered List of Certificates, first certificate first, or empty
   *     List
   * @throws CertificateParsingException if the stream contains an incorrect
   *     certificate.
   * @deprecated Use org.cesecore.util.CertTools.getCertsFromPEM(InputStream,
   *     Class&lt;T&gt;) instead.
   */
  @Deprecated
  public static List<Certificate> getCertsFromPEM(final InputStream certstream)
      throws CertificateParsingException {
    return getCertsFromPEM(certstream, Certificate.class);
  }

  /**
   * Reads certificates in PEM-format from an InputStream. The stream may
   * contain other things between the different certificates.
   *
   * @param certstream the input stream containing the certificates in
   *     PEM-format
   * @param returnType specifies the desired certificate type. Certificate can
   *     be used if certificate type is unknown.
   * @param <T> type
   * @return Ordered List of Certificates, first certificate first, or empty
   *     List
   * @exception CertificateParsingException if the stream contains an incorrect
   *     certificate.
   */
  public static <T extends Certificate> List<T> getCertsFromPEM(
      final InputStream certstream, final Class<T> returnType)
      throws CertificateParsingException {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getCertfromPEM");
    }
    final ArrayList<T> ret = new ArrayList<>();
    final String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
    final String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
    BufferedReader bufRdr = null;
    ByteArrayOutputStream ostr = null;
    PrintStream opstr = null;
    try {
      try {
        bufRdr =
            new BufferedReader(
                new InputStreamReader(
                    new SecurityFilterInputStream(certstream)));
        while (bufRdr.ready()) {
          ostr = new ByteArrayOutputStream();
          opstr = new PrintStream(ostr);
          String temp;
          while ((temp = bufRdr.readLine()) != null
              && !(temp.equals(CertTools.BEGIN_CERTIFICATE)
                  || temp.equals(beginKeyTrust))) {
            continue; // NOPMD (do-nothing statement)
          }
          if (temp == null) {
            if (ret.isEmpty()) {
              // There was no certificate in the file
              throw new CertificateParsingException(
                  "Error in "
                      + certstream.toString()
                      + ", missing "
                      + CertTools.BEGIN_CERTIFICATE
                      + " boundary");
            } else {
              // There were certificates, but some blank lines or something in
              // the end
              // anyhow, the file has ended so we can break here.
              break;
            }
          }
          while ((temp = bufRdr.readLine()) != null
              && !(temp.equals(CertTools.END_CERTIFICATE)
                  || temp.equals(endKeyTrust))) {
            opstr.print(temp);
          }
          assertNotAtEnd(certstream, temp);
          opstr.close();

          final byte[] certbuf = Base64Util.decode(ostr.toByteArray());
          ostr.close();
          // Phweeew, were done, now decode the cert from file back to
          // Certificate object
          final T cert = getCertfromByteArray(certbuf, returnType);
          ret.add(cert);
        }

      } finally {
        closeReaders(bufRdr, ostr, opstr);
      }
    } catch (final IOException e) {
      throw new IllegalStateException(
          "Exception caught when attempting to read stream, see underlying"
              + " IOException",
          e);
    }
    logSize(ret);
    return ret;
  }

/**
 * @param <T> Type
 * @param ret val
 */
private static <T extends Certificate> void logSize(final ArrayList<T> ret) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<getcertfromPEM:" + ret.size());
    }
}

/**
 * @param certstream stream
 * @param temp temp
 * @throws IllegalArgumentException fail
 */
private static void assertNotAtEnd(final InputStream certstream,
        final String temp) throws IllegalArgumentException {
    if (temp == null) {
        throw new IllegalArgumentException(
            "Error in "
                + certstream.toString()
                + ", missing "
                + CertTools.END_CERTIFICATE
                + " boundary");
      }
}

/**
 * @param bufRdr a
 * @param ostr b
 * @param opstr c
 * @throws IOException fail
 */
private static void closeReaders(final BufferedReader bufRdr,
        final ByteArrayOutputStream ostr, final PrintStream opstr)
        throws IOException {
    if (bufRdr != null) {
      bufRdr.close();
    }
    if (opstr != null) {
      opstr.close();
    }
    if (ostr != null) {
      ostr.close();
    }
}

  /**
   * Converts a regular array of certificates into an ArrayList, using the
   * provided provided.
   *
   * @param certs Certificate[] of certificates to convert
   * @param provider provider for example "SUN" or "BC", use null for the
   *     default provider (BC)
   * @return An ArrayList of certificates in the same order as the passed in
   *     array
   * @throws NoSuchProviderException if provider not found
   * @throws CertificateException if certifiate cannot be parsed
   */
  public static List<Certificate> getCertCollectionFromArray(
      final Certificate[] certs, final String provider)
      throws CertificateException, NoSuchProviderException {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getCertCollectionFromArray: " + provider);
    }
    final ArrayList<Certificate> ret = new ArrayList<Certificate>();
    String prov = provider;
    if (prov == null) {
      prov = "BC";
    }
    for (int i = 0; i < certs.length; i++) {
      final Certificate cert = certs[i];
      final Certificate newcert = getCertfromByteArray(cert.getEncoded(), prov);
      ret.add(newcert);
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<getCertCollectionFromArray: " + ret.size());
    }
    return ret;
  }

  /**
   * Returns a certificate in PEM-format.
   *
   * @param certs Collection of Certificate to convert to PEM
   * @return byte array containing PEM certificate
   * @exception CertificateException if the stream does not contain a correct
   *     certificate.
   * @deprecated Since 6.0.0, use
   *     org.cesecore.util.CertTools.getPemFromCertificateChain(Collection&lt;Certificate&gt;)
   *     instead
   */
  @Deprecated
  public static byte[] getPEMFromCerts(final Collection<Certificate> certs)
      throws CertificateException {
    return getPemFromCertificateChain(certs);
  }

  /**
   * Returns a certificate in PEM-format.
   *
   * @param certs Collection of Certificate to convert to PEM
   * @return byte array containing PEM certificate
   * @throws CertificateEncodingException if an encoding error occurred
   */
  public static byte[] getPemFromCertificateChain(
          final Collection<Certificate> certs)
      throws CertificateEncodingException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (PrintStream printStream = new PrintStream(baos)) {
      for (final Certificate certificate : certs) {
        if (certificate != null) {
          printStream.println(
              "Subject: " + CertTools.getSubjectDN(certificate));
          printStream.println("Issuer: " + CertTools.getIssuerDN(certificate));
          writeAsPemEncoded(
              printStream,
              certificate.getEncoded(),
              BEGIN_CERTIFICATE,
              END_CERTIFICATE);
        }
      }
    }
    return baos.toByteArray();
  }
  /**
   * Returns a certificate in PEM-format.
   *
   * @param cacert a Certificate to convert to PEM
   * @return byte array containing PEM certificate
   * @throws CertificateEncodingException if an encoding error occurred
   */
  public static String getPemFromCertificate(final Certificate cacert)
      throws CertificateEncodingException {
    final byte[] enccert = cacert.getEncoded();
    final byte[] b64cert = Base64Util.encode(enccert);
    String out = BEGIN_CERTIFICATE_WITH_NL;
    out += new String(b64cert);
    out += END_CERTIFICATE_WITH_NL;
    return out;
  }

  /**
   * @param crlBytes CRL
   * @return a CRL in PEM-format as a byte array.
   */
  public static byte[] getPEMFromCrl(final byte[] crlBytes) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (PrintStream printStream = new PrintStream(baos)) {
      writeAsPemEncoded(
          printStream, crlBytes, BEGIN_X509_CRL_KEY, END_X509_CRL_KEY);
    }
    return baos.toByteArray();
  }

  /**
   * @param publicKeyBytes key
   * @return a PublicKey in PEM-format as a byte array.
   */
  public static byte[] getPEMFromPublicKey(final byte[] publicKeyBytes) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (PrintStream printStream = new PrintStream(baos)) {
      writeAsPemEncoded(
          printStream, publicKeyBytes, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
    }
    return baos.toByteArray();
  }

  /**
   * @param privateKeyBytes Bytes
   * @return PEM
   */
  public static byte[] getPEMFromPrivateKey(final byte[] privateKeyBytes) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (PrintStream printStream = new PrintStream(baos)) {
      writeAsPemEncoded(
          printStream, privateKeyBytes, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
    }
    return baos.toByteArray();
  }

  /**
   * @param certificateRequestBytes key
   * @return a PublicKey in PEM-format as a byte array.
   */
  public static byte[] getPEMFromCertificateRequest(
      final byte[] certificateRequestBytes) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (PrintStream printStream = new PrintStream(baos)) {
      writeAsPemEncoded(
          printStream,
          certificateRequestBytes,
          BEGIN_CERTIFICATE_REQUEST,
          END_CERTIFICATE_REQUEST);
    }
    return baos.toByteArray();
  }

  /**
   * Generates PEM from binary pkcs#7 data.
   *
   * @param pkcs7Binary pkcs#7 binary data
   * @return a pkcs#7 PEM encoded
   */
  public static byte[] getPemFromPkcs7(final byte[] pkcs7Binary) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (PrintStream printStream = new PrintStream(baos)) {
      writeAsPemEncoded(printStream, pkcs7Binary, BEGIN_PKCS7, END_PKCS7);
    }
    return baos.toByteArray();
  }

  /**
   * Write the supplied bytes to the printstream as Base64 using beginKey and
   * endKey around it.
   *
   * @param printStream stream
   * @param unencodedData data
   * @param beginKey key start
   * @param endKey key end
   */
  private static void writeAsPemEncoded(
      final PrintStream printStream,
      final byte[] unencodedData,
      final String beginKey,
      final String endKey) {
    printStream.println(beginKey);
    printStream.println(new String(Base64Util.encode(unencodedData)));
    printStream.println(endKey);
  }

  /**
   * Creates Certificate from byte[], can be either an X509 certificate or a
   * CVCCertificate.
   *
   * @param cert byte array containing certificate in binary (DER) format, or
   *     PEM encoded X.509 certificate
   * @param provider provider for example "SUN" or "BC", use null for the
   *     default provider (BC)
   * @return a Certificate
   * @throws CertificateParsingException if certificate couldn't be parsed from
   *     cert
   * @deprecated Use org.cesecore.util.CertTools.getCertfromByteArray(byte[],
   *     String, Class&lt;Y&gt;) instead.
   */
  @Deprecated
  public static Certificate getCertfromByteArray(
          final byte[] cert, final String provider)
      throws CertificateParsingException {
    return getCertfromByteArray(cert, provider, Certificate.class);
  }

  /**
   * Creates Certificate from byte[], can be either an X509 certificate or a
   * CVCCertificate.
   *
   * @param cert byte array containing certificate in binary (DER) format, or
   *     PEM encoded X.509 certificate
   * @param provider provider for example "SUN" or "BC", use null for the
   *     default provider (BC)
   * @param returnType the type of Certificate to be returned. Certificate can
   *     be used if certificate type is unknown.
   * @param <T> type
   * @return a Certificate
   * @throws CertificateParsingException if certificate couldn't be parsed from
   *     cert, or if the incorrect return type was specified.
   */
  @SuppressWarnings("unchecked")
  public static <T extends Certificate> T getCertfromByteArray(
      final byte[] cert, final String provider, final Class<T> returnType)
      throws CertificateParsingException {
    T ret = null;
    String prov = provider;
    if (provider == null) {
      prov = BouncyCastleProvider.PROVIDER_NAME;
    }

    if (returnType.equals(X509Certificate.class)) {
      ret = (T) parseX509Certificate(prov, cert);
    } else if (returnType.equals(CardVerifiableCertificate.class)) {
      ret = (T) parseCardVerifiableCertificate(prov, cert);
    } else {
      // Let's guess...
      try {
        ret = (T) parseX509Certificate(prov, cert);
      } catch (final CertificateParsingException e) {
        try {
          ret = (T) parseCardVerifiableCertificate(prov, cert);
        } catch (final CertificateParsingException e1) {
          throw new CertificateParsingException(
              "No certificate could be parsed from byte array. See debug logs"
                  + " for details.");
        }
      }
    }

    return ret;
  }

  /**
   * @param provider a provider name
   * @param cert a byte array containing an encoded certificate
   * @return a decoded X509Certificate
   * @throws CertificateParsingException if the byte array wasn't valid, or
   *     contained a certificate other than an X509 Certificate.
   */
  private static X509Certificate parseX509Certificate(
      final String provider, final byte[] cert)
              throws CertificateParsingException {
    final CertificateFactory cf = CertTools.getCertificateFactory(provider);
    X509Certificate result;
    try {
      result =
          (X509Certificate)
              cf.generateCertificate(
                  new SecurityFilterInputStream(
                      new ByteArrayInputStream(cert)));
    } catch (final CertificateException e) {
      throw new CertificateParsingException(
          "Could not parse byte array as X509Certificate."
              + e.getCause().getMessage(),
          e);
    }
    if (result != null) {
      return result;
    } else {
      throw new CertificateParsingException(
          "Could not parse byte array as X509Certificate.");
    }
  }

  private static CardVerifiableCertificate parseCardVerifiableCertificate(
      final String provider, final byte[] cert) // NOPMD: keep signature
              throws CertificateParsingException {
    // We could not create an X509Certificate, see if it is a CVC certificate
    // instead
    try {
      final CVCertificate parsedObject =
          CertificateParser.parseCertificate(cert);
      return new CardVerifiableCertificate(parsedObject);
    } catch (final ParseException e) {
      throw new CertificateParsingException(
          "ParseException trying to read CVCCertificate.", e);
    } catch (final ConstructionException e) {
      throw new CertificateParsingException(
          "ConstructionException trying to read CVCCertificate.", e);
    }
  }

  /**
   * @param cert vertificate
   * @return certificate
   * @throws CertificateParsingException if the byte array does not contain a
   *     proper certificate.
   * @deprecated Use org.cesecore.util.CertTools.getCertfromByteArray(byte[],
   *     Class&lt;T&gt;) to specify return type instead.
   */
  @Deprecated
  public static Certificate getCertfromByteArray(final byte[] cert)
      throws CertificateParsingException {
    return getCertfromByteArray(cert, Certificate.class);
  }

  /**
   * @param cert certificate as byte array
   * @param <T> type
   * @param returnType the type of Certificate to be returned, for example
   *     X509Certificate.class. Certificate.class can be used if certificate
   *     type is unknown.
   * @return Certificate
   * @throws CertificateParsingException if the byte array does not contain a
   *     proper certificate.
   */
  public static <T extends Certificate> T getCertfromByteArray(
      final byte[] cert, final Class<T> returnType)
              throws CertificateParsingException {
    return getCertfromByteArray(
        cert, BouncyCastleProvider.PROVIDER_NAME, returnType);
  }

  /**
   * Creates X509CRL from byte[].
   *
   * @param crl byte array containing CRL in DER-format
   * @return X509CRL
   * @throws CRLException if the byte array does not contain a correct CRL.
   */
  public static X509CRL getCRLfromByteArray(
          final byte[] crl) throws CRLException {
    LOGGER.trace(">getCRLfromByteArray");
    if (crl == null) {
      throw new CRLException("No content in crl byte array");
    }
    final CertificateFactory cf = CertTools.getCertificateFactory();
    final X509CRL x509crl =
            (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl));
    LOGGER.trace("<getCRLfromByteArray");

    return x509crl;
  } // getCRLfromByteArray

  /**
   * Checks if a certificate is self signed by verifying if subject and issuer
   * are the same.
   *
   * @param cert the certificate that shall be checked.
   * @return boolean true if the certificate has the same issuer and subject,
   *     false otherwise.
   */
  public static boolean isSelfSigned(final Certificate cert) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(
          ">isSelfSigned: cert: "
              + CertTools.getIssuerDN(cert)
              + "\n"
              + CertTools.getSubjectDN(cert));
    }
    final boolean ret =
        CertTools.getSubjectDN(cert).equals(CertTools.getIssuerDN(cert));
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<isSelfSigned:" + ret);
    }
    return ret;
  } // isSelfSigned

  /**
   * Checks if a certificate is valid.
   *
   * @param warnIfAboutToExpire Also print a WARN log message if the certificate
   *     is about to expire. If false, it is still printed at DEBUG level.
   * @param signerCert the certificate to be tested
   * @return true if the certificate is valid
   */
  public static boolean isCertificateValid(
      final X509Certificate signerCert, final boolean warnIfAboutToExpire) {
    try {
      signerCert.checkValidity();
    } catch (final CertificateExpiredException e) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            INTRES.getLocalizedMessage(
                "ocsp.errorcerthasexpired",
                signerCert.getSerialNumber().toString(16),
                signerCert.getIssuerDN()));
      }
      return false;
    } catch (final CertificateNotYetValidException e) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            INTRES.getLocalizedMessage(
                "ocsp.errornotyetvalid",
                signerCert.getSerialNumber().toString(16),
                signerCert.getIssuerDN()));
      }
      return false;
    }
    final long warnBeforeExpirationTime =
        OcspConfiguration.getWarningBeforeExpirationTime();
    if (warnBeforeExpirationTime < 1) {
      return true;
    }
    final Date warnDate =
        new Date(new Date().getTime() + warnBeforeExpirationTime);
    try {
      signerCert.checkValidity(warnDate);
    } catch (final CertificateExpiredException e) {
      if (warnIfAboutToExpire || LOGGER.isDebugEnabled()) {
        final Level logLevel = warnIfAboutToExpire ? Level.WARN : Level.DEBUG;
        LOGGER.log(
            logLevel,
            INTRES.getLocalizedMessage(
                "ocsp.warncertwillexpire",
                signerCert.getSerialNumber().toString(16),
                signerCert.getIssuerDN(),
                signerCert.getNotAfter()));
      }
    } catch (final CertificateNotYetValidException e) {
      throw new IllegalStateException("This should never happen.", e);
    }
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug(
          "Time for \"certificate will soon expire\" not yet reached. You will"
              + " be warned after: "
              + new Date(
                  signerCert.getNotAfter().getTime()
                      - warnBeforeExpirationTime));
    }
    return true;
  }

  /**
   * Checks if a certificate is a CA certificate according to BasicConstraints
   * (X.509), or role (CVC). If there is no basic constraints extension on a
   * X.509 certificate, false is returned.
   *
   * @param cert the certificate that shall be checked.
   * @return boolean true if the certificate belongs to a CA.
   */
  public static boolean isCA(final Certificate cert) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">isCA");
    }
    boolean ret = false;
    if (cert instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) cert;
      if (x509cert.getBasicConstraints() > -1) {
        ret = true;
      }
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      final CardVerifiableCertificate cvccert =
              (CardVerifiableCertificate) cert;
      try {
        final CVCAuthorizationTemplate templ =
            cvccert
                .getCVCertificate()
                .getCertificateBody()
                .getAuthorizationTemplate();
        final AuthorizationRole role =
                templ.getAuthorizationField().getAuthRole();
        if (role.isCVCA() || role.isDV()) {
          ret = true;
        }
      } catch (final NoSuchFieldException e) {
        LOGGER.error("NoSuchFieldException: ", e);
      }
    }
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<isCA:" + ret);
    }
    return ret;
  }

  /**
   * Is OCSP extended key usage set for a certificate?
   *
   * @param cert to check.
   * @return true if the extended key usage for OCSP is check
   */
  public static boolean isOCSPCert(final X509Certificate cert) {
    final List<String> keyUsages;
    try {
      keyUsages = cert.getExtendedKeyUsage();
    } catch (final CertificateParsingException e) {
      return false;
    }
    return keyUsages != null
        && keyUsages.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
  }

  /**
   * Generate a selfsigned certificate.
   *
   * @param dn subject and issuer DN
   * @param validity in days
   * @param policyId policy string ('2.5.29.32.0') or null
   * @param privKey private key
   * @param pubKey public key
   * @param sigAlg signature algorithm, you can use one of the contants
   *     AlgorithmConstants.SIGALG_XXX
   * @param isCA boolean true or false
   * @return X509Certificate, self signed
   * @throws CertificateException If cert cannot be parsed
   * @throws OperatorCreationException if creation fails
   */
  public static X509Certificate genSelfCert(
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA)
      throws OperatorCreationException, CertificateException {
    return genSelfCert(
        dn,
        validity,
        policyId,
        privKey,
        pubKey,
        sigAlg,
        isCA,
        BouncyCastleProvider.PROVIDER_NAME);
  }

  /**
   * Generates a self signed certificate with keyUsage X509KeyUsage.keyCertSign
   * + X509KeyUsage.cRLSign, i.e. a CA certificate
   *
   * @param dn subject and issuer DN
   * @param validity in days
   * @param policyId policy string ('2.5.29.32.0') or null
   * @param privKey private key
   * @param pubKey public key
   * @param sigAlg signature algorithm, you can use one of the contants
   *     AlgorithmConstants.SIGALG_XXX
   * @param isCA boolean true or false
   * @param provider jce provider
   * @param ldapOrder true to sort
   * @return X509Certificate, self signed
   * @throws CertificateParsingException If cert cannot be parsed
   * @throws OperatorCreationException if creation fails
   */
  public static X509Certificate genSelfCert(
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final String provider,
      final boolean ldapOrder)
      throws CertificateParsingException, OperatorCreationException {
    final int keyUsage;
    if (isCA) {
      keyUsage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
    } else {
      keyUsage = 0;
    }
    return genSelfCertForPurpose(
        dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyUsage, null,
        null, provider, ldapOrder);
  } // genselfCert

  /**
   * Generates a self signed certificate with keyUsage X509KeyUsage.keyCertSign
   * + X509KeyUsage.cRLSign, i.e. a CA certificate
   *
   * @param dn subject and issuer DN
   * @param validity in days
   * @param policyId policy string ('2.5.29.32.0') or null
   * @param privKey private key
   * @param pubKey public key
   * @param sigAlg signature algorithm, you can use one of the contants
   *     AlgorithmConstants.SIGALG_XXX
   * @param isCA boolean true or false
   * @param provider JCE provider
   * @return X509Certificate, self signed
   * @throws CertificateException If cert cannot be parsed
   * @throws OperatorCreationException if creation fails
   */
  public static X509Certificate genSelfCert(
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final String provider)
      throws OperatorCreationException, CertificateException {
    return genSelfCert(
        dn, validity, policyId, privKey, pubKey, sigAlg, isCA, provider, true);
  } // genselfCert

  /**
   * Generate a selfsigned certiicate with possibility to specify key usage.
   *
   * @param dn subject and issuer DN
   * @param validity in days
   * @param policyId policy string ('2.5.29.32.0') or null
   * @param privKey private key
   * @param pubKey public key
   * @param sigAlg signature algorithm, you can use one of the contants
   *     AlgorithmConstants.SIGALG_XXX
   * @param isCA boolean true or false
   * @param keyusage as defined by constants in X509KeyUsage
   * @param ldapOrder set true to sort
   * @return X509Certificate, self signed
   * @throws CertificateParsingException If cert cannot be parsed
   * @throws OperatorCreationException if creation fails
   */
  public static X509Certificate genSelfCertForPurpose(
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final int keyusage,
      final boolean ldapOrder)
      throws CertificateParsingException, OperatorCreationException {
    return genSelfCertForPurpose(
        dn,
        validity,
        policyId,
        privKey,
        pubKey,
        sigAlg,
        isCA,
        keyusage,
        null,
        null,
        BouncyCastleProvider.PROVIDER_NAME,
        ldapOrder);
  }

  /**
   * @param dn DN
   * @param validity Validity
   * @param policyId ID
   * @param privKey Key
   * @param pubKey Key
   * @param sigAlg Alg
   * @param isCA CA
   * @param keyusage Usage
   * @param privateKeyNotBefore Start
   * @param privateKeyNotAfter End
   * @param provider Prov
   * @return Cert
   * @throws CertificateParsingException fail
   * @throws OperatorCreationException fail
   */
  public static X509Certificate genSelfCertForPurpose(// NOPMD
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final int keyusage,
      final Date privateKeyNotBefore,
      final Date privateKeyNotAfter,
      final String provider)
      throws CertificateParsingException, OperatorCreationException {
    return genSelfCertForPurpose(
        dn,
        validity,
        policyId,
        privKey,
        pubKey,
        sigAlg,
        isCA,
        keyusage,
        privateKeyNotBefore,
        privateKeyNotAfter,
        provider,
        true);
  }

  /**
   * @param dn DN
   * @param validity Validity
   * @param policyId Policy
   * @param privKey Key
   * @param pubKey Key
   * @param sigAlg Alg
   * @param isCA CA
   * @param keyusage Usage
   * @param privateKeyNotBefore Stary
   * @param privateKeyNotAfter End
   * @param provider Provider
   * @param ldapOrder Order
   * @return Cert
   * @throws CertificateParsingException fail
   * @throws OperatorCreationException fail
   */
  public static X509Certificate genSelfCertForPurpose(// NOPMD
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final int keyusage,
      final Date privateKeyNotBefore,
      final Date privateKeyNotAfter,
      final String provider,
      final boolean ldapOrder)
      throws CertificateParsingException, OperatorCreationException {
    try {
      return genSelfCertForPurpose(
          dn,
          validity,
          policyId,
          privKey,
          pubKey,
          sigAlg,
          isCA,
          keyusage,
          privateKeyNotBefore,
          privateKeyNotAfter,
          provider,
          ldapOrder,
          null);
    } catch (final CertIOException e) {
      throw new IllegalStateException(
          "CertIOException was thrown due to an invalid extension, but no"
              + " extensions were provided.",
          e);
    }
  }

  /**
   * @param dn DN
   * @param validity Validiy
   * @param policyId Policy
   * @param privKey Key
   * @param pubKey Key
   * @param sigAlg Alg
   * @param isCA CA
   * @param keyusage Usage
   * @param privateKeyNotBefore Start
   * @param privateKeyNotAfter End
   * @param provider Provider
   * @param ldapOrder Order
   * @param additionalExtensions Exts
   * @return Cert
   * @throws CertificateParsingException fail
   * @throws OperatorCreationException fail
   * @throws CertIOException fail
   */
  public static X509Certificate genSelfCertForPurpose(// NOPMD
      final String dn,
      final long validity,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final int keyusage,
      final Date privateKeyNotBefore,
      final Date privateKeyNotAfter,
      final String provider,
      final boolean ldapOrder,
      final List<Extension> additionalExtensions)
      throws CertificateParsingException, OperatorCreationException,
          CertIOException {
    // Create self signed certificate
    final Date firstDate = new Date();
    final int tenMins = 10 * 60 * 1000;
    final int oneDay = 24 * 60 * 60 * 1000;
    // Set back startdate ten minutes to avoid some problems with wrongly set
    // clocks.
    firstDate.setTime(firstDate.getTime() - (tenMins));

    final Date lastDate = new Date();

    // validity in days = validity*24*60*60*1000 milliseconds
    lastDate.setTime(lastDate.getTime() + (validity * (oneDay)));

    return genSelfCertForPurpose(
        dn,
        firstDate,
        lastDate,
        policyId,
        privKey,
        pubKey,
        sigAlg,
        isCA,
        keyusage,
        privateKeyNotBefore,
        privateKeyNotAfter,
        provider,
        ldapOrder,
        additionalExtensions);
  }

  /**
   * @param dn DN
   * @param firstDate Start
   * @param lastDate End
   * @param policyId ID
   * @param privKey Key
   * @param pubKey Key
   * @param sigAlg Alg
   * @param isCA CA
   * @param keyusage Usage
   * @param privateKeyNotBefore Start
   * @param privateKeyNotAfter End
   * @param provider Provider
   * @param ldapOrder Order
   * @param additionalExtensions Exyensions
   * @return Cert
   * @throws CertificateParsingException fail
   * @throws OperatorCreationException fail
   * @throws CertIOException fail
   */
  public static X509Certificate genSelfCertForPurpose(// NOPMD: params
      final String dn,
      final Date firstDate,
      final Date lastDate,
      final String policyId,
      final PrivateKey privKey,
      final PublicKey pubKey,
      final String sigAlg,
      final boolean isCA,
      final int keyusage,
      final Date privateKeyNotBefore,
      final Date privateKeyNotAfter,
      final String provider,
      final boolean ldapOrder,
      final List<Extension> additionalExtensions)
      throws CertificateParsingException, OperatorCreationException,
          CertIOException {
    // Transform the PublicKey to be sure we have it in a format that the X509
    // certificate generator handles, it might be
    // a CVC public key that is passed as parameter
        PublicKey publicKey = null;
    if (pubKey instanceof RSAPublicKey) {
      publicKey = getRSAPK(pubKey, publicKey);
    } else if (pubKey instanceof ECPublicKey) {
      publicKey = getECPK(pubKey, publicKey);
    } else {
      LOGGER.debug("Not converting key of class. "
                  + pubKey.getClass().getName());
      publicKey = pubKey;
    }

    // Serialnumber is random bits, where random generator is initialized with
    // Date.getTime() when this
    // bean is created.
    final byte[] serno = new byte[8];
    setRandomSN(serno);

    final SubjectPublicKeyInfo pkinfo =
        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    final X509v3CertificateBuilder certbuilder =
        new X509v3CertificateBuilder(
            CertTools.stringToBcX500Name(dn, ldapOrder),
            new BigInteger(serno).abs(),
            firstDate,
            lastDate,
            CertTools.stringToBcX500Name(dn, ldapOrder),
            pkinfo);

    // Basic constranits is always critical and MUST be present at-least in
    // CA-certificates.
    final BasicConstraints bc = new BasicConstraints(isCA);
    certbuilder.addExtension(Extension.basicConstraints, true, bc);

    // Put critical KeyUsage in CA-certificates
    if (isCA || keyusage != 0) {
      final X509KeyUsage ku = new X509KeyUsage(keyusage);
      certbuilder.addExtension(Extension.keyUsage, true, ku);
    }

    handleExpiry(privateKeyNotBefore, privateKeyNotAfter, certbuilder);

    // Subject and Authority key identifier is always non-critical and MUST be
    // present for certificates to verify in Firefox.
    handleCA(isCA, publicKey, certbuilder);

    // CertificatePolicies extension if supplied policy ID, always non-critical
    handlePolicy(policyId, certbuilder);
    // Add any additional
    if (additionalExtensions != null) {
      for (final Extension extension : additionalExtensions) {
        certbuilder.addExtension(
            extension.getExtnId(),
            extension.isCritical(),
            extension.getParsedValue());
      }
    }
    final ContentSigner signer =
        new BufferingContentSigner(
            new JcaContentSignerBuilder(sigAlg)
                .setProvider(provider)
                .build(privKey),
            20480);
    final X509CertificateHolder certHolder = certbuilder.build(signer);
    X509Certificate selfcert;
    try {
      selfcert =
          (X509Certificate)
              CertTools.getCertfromByteArray(certHolder.getEncoded());
    } catch (final IOException e) {
      throw new IllegalStateException("Unexpected IOException was caught.", e);
    }

    return selfcert;
  } // genselfCertForPurpose

/**
 * @param policyId ID
 * @param certbuilder Cert
 * @throws CertIOException Fail
 */
private static void handlePolicy(final String policyId,
        final X509v3CertificateBuilder certbuilder)
        throws CertIOException {
    if (policyId != null) {
      final PolicyInformation pi =
          new PolicyInformation(new ASN1ObjectIdentifier(policyId));
      final DERSequence seq = new DERSequence(pi);
      certbuilder.addExtension(Extension.certificatePolicies, false, seq);
    }
}

/**
 * @param privateKeyNotBefore date
 * @param privateKeyNotAfter date
 * @param certbuilder builder
 * @throws CertIOException fail
 */
private static void handleExpiry(final Date privateKeyNotBefore,
        final Date privateKeyNotAfter,
        final X509v3CertificateBuilder certbuilder) throws CertIOException {
    if (privateKeyNotBefore != null || privateKeyNotAfter != null) {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      if (privateKeyNotBefore != null) {
        v.add(
            new DERTaggedObject(
                false, 0, new DERGeneralizedTime(privateKeyNotBefore)));
      }
      if (privateKeyNotAfter != null) {
        v.add(
            new DERTaggedObject(
                false, 1, new DERGeneralizedTime(privateKeyNotAfter)));
      }
      certbuilder.addExtension(
          Extension.privateKeyUsagePeriod, false, new DERSequence(v));
    }
}

/**
 * @param isCA bool
 * @param publicKey Key
 * @param certbuilder Builder
 */
private static void handleCA(final boolean isCA, final PublicKey publicKey,
        final X509v3CertificateBuilder certbuilder) {
    try {
      if (isCA) {
        final JcaX509ExtensionUtils extensionUtils =
            new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
        final SubjectKeyIdentifier ski =
            extensionUtils.createSubjectKeyIdentifier(publicKey);
        final AuthorityKeyIdentifier aki =
            extensionUtils.createAuthorityKeyIdentifier(publicKey);
        certbuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        certbuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
      }
    } catch (final IOException e) { // NOPMD do nothing
    }
}

/**
 * @param serno serial
 * @throws IllegalStateException fail
 */
private static void setRandomSN(final byte[] serno)
        throws IllegalStateException {
    SecureRandom random;
    try {
      random = SecureRandom.getInstance("SHA1PRNG");
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA1PRNG was not a known algorithm", e);
    }
    random.setSeed(new Date().getTime());
    random.nextBytes(serno);
}

/**
 * @param pubKey in
 * @param opk out
 * @return out
 * @throws IllegalStateException fail
 */
private static PublicKey getECPK(final PublicKey pubKey,
        final PublicKey opk)
        throws IllegalStateException {
    PublicKey pk = opk;
    final ECPublicKey ecpk = (ECPublicKey) pubKey;
      try {
        final ECPublicKeySpec ecspec =
            new ECPublicKeySpec(
                ecpk.getW(),
                ecpk.getParams()); // will throw NPE if key is "implicitlyCA"
        final String algo = ecpk.getAlgorithm();
        if (algo.equals(AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
          try {
            pk =
                KeyFactory.getInstance("ECGOST3410").generatePublic(ecspec);
          } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "ECGOST3410 was not a known algorithm", e);
          }
        } else if (algo.equals(AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
          try {
            pk =
                KeyFactory.getInstance("DSTU4145").generatePublic(ecspec);
          } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "DSTU4145 was not a known algorithm", e);
          }
        } else {
          try {
            pk = KeyFactory.getInstance("EC").generatePublic(ecspec);
          } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC was not a known algorithm", e);
          }
        }
      } catch (final InvalidKeySpecException e) {
        LOGGER.error("Error creating ECPublicKey from spec: ", e);
        pk = pubKey;
      } catch (final NullPointerException e) {
        LOGGER.debug(
            "NullPointerException, probably it is implicitlyCA generated keys: "
                + e.getMessage());
        pk = pubKey;
      }
    return pk;
}

/**
 * @param pubKey in
 * @param opk out
 * @return out
 * @throws IllegalStateException fail
 */
private static PublicKey getRSAPK(final PublicKey pubKey,
        final PublicKey opk) throws IllegalStateException {
    PublicKey pk = opk;
    final RSAPublicKey rsapk = (RSAPublicKey) pubKey;
      final RSAPublicKeySpec rSAPublicKeySpec =
          new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());
      try {
        pk =
            KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
      } catch (final InvalidKeySpecException e) {
        LOGGER.error("Error creating RSAPublicKey from spec: ", e);
        pk = pubKey;
      } catch (final NoSuchAlgorithmException e) {
        throw new IllegalStateException("RSA was not a known algorithm", e);
      }
    return pk;
}

  /**
   * Get the authority key identifier from a certificate extensions.
   *
   * @param certificate certificate containing the extension
   * @return byte[] containing the authority key identifier, or null if it does
   *     not exist
   */
  public static byte[] getAuthorityKeyId(final Certificate certificate) {
    if (certificate != null && certificate instanceof X509Certificate) {
      final ASN1Primitive asn1Sequence =
          getExtensionValue(
              (X509Certificate) certificate,
              Extension.authorityKeyIdentifier.getId()); // "2.5.29.35"
      if (asn1Sequence != null) {
        return AuthorityKeyIdentifier.getInstance(asn1Sequence)
            .getKeyIdentifier();
      }
    }
    return null;
  }

  /**
   * Get the subject key identifier from a certificate extensions.
   *
   * @param certificate certificate containing the extension
   * @return byte[] containing the subject key identifier, or null if it does
   *     not exist
   */
  public static byte[] getSubjectKeyId(final Certificate certificate) {
    if (certificate != null && certificate instanceof X509Certificate) {
      final ASN1Primitive asn1Sequence =
          getExtensionValue(
              (X509Certificate) certificate,
              Extension.subjectKeyIdentifier.getId()); // "2.5.29.14"
      if (asn1Sequence != null) {
        return SubjectKeyIdentifier.getInstance(asn1Sequence)
            .getKeyIdentifier();
      }
    }
    return null;
  }

  /**
   * Get a certificate policy ID from a certificate policies extension.
   *
   * @param certificate certificate containing the extension
   * @param pos position of the policy id, if several exist, the first is as pos
   *     0
   * @return String with the certificate policy OID, or null if an id at the
   *     given position does not exist
   * @throws IOException if extension can not be parsed
   */
  public static String getCertificatePolicyId(
          final Certificate certificate, final int pos)
      throws IOException {
    if (certificate != null && certificate instanceof X509Certificate) {
      final ASN1Sequence asn1Sequence =
          (ASN1Sequence)
              getExtensionValue(
                  (X509Certificate) certificate,
                  Extension.certificatePolicies.getId());
      if (asn1Sequence != null
        // Check the size so we don't ArrayIndexOutOfBounds
        && asn1Sequence.size() >= pos + 1) {
          return PolicyInformation.getInstance(asn1Sequence.getObjectAt(pos))
              .getPolicyIdentifier()
              .getId();

      }
    }
    return null;
  }

  /**
   * Get a list of certificate policy IDs from a certificate policies extension.
   *
   * @param certificate certificate containing the extension
   * @return List of ObjectIdentifiers, or empty list if no policies exist
   * @throws IOException if extension can not be parsed
   */
  public static List<ASN1ObjectIdentifier> getCertificatePolicyIds(
      final Certificate certificate) throws IOException {
    final List<ASN1ObjectIdentifier> ret =
            new ArrayList<ASN1ObjectIdentifier>();
    if (certificate != null && certificate instanceof X509Certificate) {
      final ASN1Sequence asn1Sequence =
          (ASN1Sequence)
              getExtensionValue(
                  (X509Certificate) certificate,
                  Extension.certificatePolicies.getId());
      if (asn1Sequence != null) {
        for (final ASN1Encodable asn1Encodable : asn1Sequence) {
          final PolicyInformation pi =
                  PolicyInformation.getInstance(asn1Encodable);
          ret.add(pi.getPolicyIdentifier());
        }
      }
    }
    return ret;
  }

  /**
   * Get a list of certificate policy information from a certificate policies
   * extension.
   *
   * @param certificate certificate containing the extension
   * @return List of PolicyInformation, or empty list if no policies exist
   * @throws IOException if extension can not be parsed
   */
  public static List<PolicyInformation> getCertificatePolicies(
      final Certificate certificate) throws IOException {
    final List<PolicyInformation> ret = new ArrayList<PolicyInformation>();
    if (certificate != null && certificate instanceof X509Certificate) {
      final ASN1Sequence asn1Sequence =
          (ASN1Sequence)
              getExtensionValue(
                  (X509Certificate) certificate,
                  Extension.certificatePolicies.getId());
      if (asn1Sequence != null) {
        for (final ASN1Encodable asn1Encodable : asn1Sequence) {
          final PolicyInformation pi =
                  PolicyInformation.getInstance(asn1Encodable);
          ret.add(pi);
        }
      }
    }
    return ret;
  }

  /**
   * Gets the Microsoft specific UPN altName (altName, OtherName).
   *
   * <p>UPN is an OtherName Subject Alternative Name:
   *
   * <p>OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT
   * ANY DEFINED BY type-id }
   *
   * <p>UPN ::= UTF8String
   *
   * @param cert certificate containing the extension
   * @return String with the UPN name or null if the altName does not exist
   * @throws IOException On disk error
   * @throws CertificateParsingException if cert parse fails
   */
  public static String getUPNAltName(final Certificate cert)
      throws IOException, CertificateParsingException {
    return getUTF8AltNameOtherName(cert, CertTools.UPN_OBJECTID);
  }

  /**
   * Gets a UTF8 OtherName altName (altName, OtherName).
   *
   * <p>Like UPN and XmpAddr
   *
   * <p>An OtherName Subject Alternative Name:
   *
   * <p>OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT
   * ANY DEFINED BY type-id }
   *
   * <p>UPN ::= UTF8String
   * (subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:username@some.domain)
   * XmppAddr ::= UTF8String
   * (subjectAltName=otherName:1.3.6.1.5.5.7.8.5;UTF8:username@some.domain)
   *
   * <p>CertTools.UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
   * CertTools.XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
   * CertTools.SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
   *
   * @param cert certificate containing the extension
   * @param oid the OID of the OtherName
   * @return String with the UTF8 name or null if the altName does not exist
   * @throws IOException On disk error
   * @throws CertificateParsingException if cert parse fails
   */
  public static String getUTF8AltNameOtherName(
      final Certificate cert, final String oid)
      throws IOException, CertificateParsingException {
    String ret = null;
    if (cert instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) cert;
      final Collection<List<?>> altNames =
              x509cert.getSubjectAlternativeNames();
      if (altNames != null) {
        for (final List<?> next : altNames) {
          ret = getUTF8StringFromSequence(getAltnameSequence(next), oid);
          if (ret != null) {
            break;
          }
        }
      }
    }
    return ret;
  }

  /**
   * Helper method for the above method.
   *
   * @param seq the OtherName sequence
   * @param oid OID
   * @return String which is the decoded ASN.1 UTF8 String of the (simple)
   *     OtherName
   */
  private static String getUTF8StringFromSequence(
      final ASN1Sequence seq, final String oid) {
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (id.getId().equals(oid)) {
        final ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // Due to bug in java cert.getSubjectAltName regarding OtherName, it can
        // be tagged an extra time...
        ASN1Primitive obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        final DERUTF8String str = DERUTF8String.getInstance(obj);
        return str.getString();
      }
    }
    return null;
  }

  /**
   * Helper method.
   *
   * @param seq the OtherName sequence
   * @param oid OID
   * @return String which is the decoded ASN.1 IA5String of the (simple)
   *     OtherName
   */
  private static String getIA5StringFromSequence(
      final ASN1Sequence seq, final String oid) {
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (id.getId().equals(oid)) {
        final ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // Due to bug in java cert.getSubjectAltName regarding OtherName, it can
        // be tagged an extra time...
        ASN1Primitive obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        final DERIA5String str = DERIA5String.getInstance(obj);
        return str.getString();
      }
    }
    return null;
  }

  /**
   * Helper method.
   *
   * @param seq the OtherName sequence
   * @param oid OID
   * @return bytes which is the decoded ASN.1 Octet String of the (simple)
   *     OtherName
   */
  private static byte[] getOctetStringFromSequence(
      final ASN1Sequence seq, final String oid) {
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (id.getId().equals(oid)) {
        final ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // Due to bug in java cert.getSubjectAltName regarding OtherName, it can
        // be tagged an extra time...
        ASN1Primitive obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        final ASN1OctetString str = ASN1OctetString.getInstance(obj);
        return str.getOctets();
      }
    }
    return null;
  }

  /**
   * Gets the Permanent Identifier (altName, OtherName).
   *
   * <p>permanentIdentifier is an OtherName Subject Alternative Name:
   *
   * <p>OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT
   * ANY DEFINED BY type-id }
   *
   * <p>-- Permanent Identifier
   *
   * <p>permanentIdentifier OTHER-NAME ::= { PermanentIdentifier IDENTIFIED BY
   * id-on-permanentIdentifier }
   *
   * <p>PermanentIdentifier ::= SEQUENCE { identifierValue UTF8String OPTIONAL,
   * -- if absent, use the serialNumber attribute -- if there is a single such
   * attribute present -- in the subject DN assigner OBJECT IDENTIFIER OPTIONAL
   * -- if absent, the assigner is -- the certificate issuer }
   *
   * @param cert certificate containing the extension
   * @return String with the permanentIdentifier name or null if the altName
   *     does not exist
   * @throws IOException On disk error
   * @throws CertificateParsingException if cert parse fails
   */
  public static String getPermanentIdentifierAltName(final Certificate cert)
      throws IOException, CertificateParsingException {
    String ret = null;
    if (cert instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) cert;
      final Collection<List<?>> altNames =
              x509cert.getSubjectAlternativeNames();
      if (altNames != null) {
        final Iterator<List<?>> i = altNames.iterator();
        while (i.hasNext()) {
          final ASN1Sequence seq = getAltnameSequence(i.next());
          ret = getPermanentIdentifierStringFromSequence(seq);
          if (ret != null) {
            break;
          }
        }
      }
    }
    return ret;
  } // getPermanentIdentifierAltName

  /**
   * (This method intentionally has package level visibility to be able to be
   * invoked from JUnit tests).
   *
   * @param seq asn.1 sequence
   * @return The extension values encoded as an permanentIdentifierString
   */
  static String getPermanentIdentifierStringFromSequence(// NOPMD
          final ASN1Sequence seq) {
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (id.getId().equals(CertTools.PERMANENTIDENTIFIER_OBJECTID)) {
        String identifierValue = null;
        String assigner = null;

        // Get the PermanentIdentifier sequence
        final ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // Due to bug in java cert.getSubjectAltName regarding OtherName, it can
        // be tagged an extra time...
        ASN1Primitive obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        final ASN1Sequence piSeq = ASN1Sequence.getInstance(obj);

        final Enumeration<?> e = piSeq.getObjects();
        if (e.hasMoreElements()) {
          Object element = e.nextElement();
          if (element instanceof DERUTF8String) {
            identifierValue = ((DERUTF8String) element).getString();
            if (e.hasMoreElements()) {
              element = e.nextElement();
            }
          }
          if (element instanceof ASN1ObjectIdentifier) {
            assigner = ((ASN1ObjectIdentifier) element).getId();
          }
        }

        final StringBuilder buff = new StringBuilder();
        if (identifierValue != null) {
          buff.append(escapePermanentIdentifierValue(identifierValue));
        }
        buff.append(PERMANENTIDENTIFIER_SEP);
        if (assigner != null) {
          buff.append(assigner);
        }
        return buff.toString();
      }
    }
    return null;
  }

  private static String escapePermanentIdentifierValue(final String realValue) {
    return realValue.replace(
        PERMANENTIDENTIFIER_SEP, "\\" + PERMANENTIDENTIFIER_SEP);
  }

  private static String unescapePermanentIdentifierValue(
          final String escapedValue) {
    return escapedValue.replace(
        "\\" + PERMANENTIDENTIFIER, PERMANENTIDENTIFIER);
  }

  /**
   * (This method intentionally has package level visibility to be able to be
   * invoked from JUnit tests).
   *
   * @param permanentIdentifierString filter
   * @return A two elements String array with the extension values
   */
  static String[] getPermanentIdentifierValues(// NOPMD
      final String permanentIdentifierString) {
    final String[] result = new String[2];
    final int sepPos = permanentIdentifierString
            .lastIndexOf(PERMANENTIDENTIFIER_SEP);
    if (sepPos == -1) {
      if (!permanentIdentifierString.isEmpty()) {
        result[0] = unescapePermanentIdentifierValue(permanentIdentifierString);
      }
    } else if (sepPos == 0) {
      if (permanentIdentifierString.length() > 1) {
        result[1] = permanentIdentifierString.substring(1);
      }
    } else if (permanentIdentifierString.charAt(
            sepPos - PERMANENTIDENTIFIER_SEP.length())
        != '\\') {
      result[0] =
          unescapePermanentIdentifierValue(
              permanentIdentifierString.substring(0, sepPos));
      if (permanentIdentifierString.length()
          > sepPos + PERMANENTIDENTIFIER_SEP.length()) {
        result[1] = permanentIdentifierString.substring(sepPos + 1);
      }
    }
    return result;
  }

  /**
   * Helper method to get MS GUID from GeneralName otherName sequence.
   *
   * @param seq the OtherName sequence
   * @return GUID
   */
  private static String getGUIDStringFromSequence(final ASN1Sequence seq) {
    String ret = null;
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (id.getId().equals(CertTools.GUID_OBJECTID)) {
        final ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // Due to bug in java cert.getSubjectAltName regarding OtherName, it can
        // be tagged an extra time...
        ASN1Primitive obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        final ASN1OctetString str = ASN1OctetString.getInstance(obj);
        ret = new String(Hex.encode(str.getOctets()));
      }
    }
    return ret;
  }

  /**
   * Helper method for getting kerberos 5 principal name (altName, OtherName)
   *
   * <p>Krb5PrincipalName is an OtherName Subject Alternative Name
   *
   * <p>String representation is in form "principalname1/principalname2@realm"
   *
   * <p>KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1]
   * PrincipalName }
   *
   * <p>Realm ::= KerberosString
   *
   * <p>PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1]
   * SEQUENCE OF KerberosString }
   *
   * <p>The new (post-RFC 1510) type KerberosString, defined below, is a
   * GeneralString that is constrained to contain only characters in IA5String.
   *
   * <p>KerberosString ::= GeneralString (IA5String)
   *
   * <p>Int32 ::= INTEGER (-2147483648..2147483647) -- signed values
   * representable in 32 bits
   *
   * @param seq the OtherName sequence
   * @return String with the krb5 name in the form of
   *     "principal1/principal2@realm" or null if the altName does not exist
   */
  @SuppressWarnings("unchecked")
  protected static String getKrb5PrincipalNameFromSequence(
          final ASN1Sequence seq) {
    String ret = null;
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
      if (id.getId().equals(CertTools.KRB5PRINCIPAL_OBJECTID)) {
        // Get the KRB5PrincipalName sequence
        final ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // Due to bug in java cert.getSubjectAltName regarding OtherName, it can
        // be tagged an extra time...
        ASN1Primitive obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        final ASN1Sequence krb5Seq = ASN1Sequence.getInstance(obj);
        // Get the Realm tagged as 0
        final ASN1TaggedObject robj = (ASN1TaggedObject) krb5Seq.getObjectAt(0);
        final DERGeneralString realmObj =
            DERGeneralString.getInstance(robj.getObject());
        final String realm = realmObj.getString();
        // Get the PrincipalName tagged as 1
        final ASN1TaggedObject pobj = (ASN1TaggedObject) krb5Seq.getObjectAt(1);
        // This is another sequence of type and name
        final ASN1Sequence nseq = ASN1Sequence.getInstance(pobj.getObject());
        // Get the name tagged as 1
        final ASN1TaggedObject nobj = (ASN1TaggedObject) nseq.getObjectAt(1);
        // The name is yet another sequence of GeneralString
        final ASN1Sequence sseq = ASN1Sequence.getInstance(nobj.getObject());
        final Enumeration<ASN1Object> en = sseq.getObjects();
        while (en.hasMoreElements()) {
          final ASN1Primitive o = (ASN1Primitive) en.nextElement();
          final DERGeneralString str = DERGeneralString.getInstance(o);
          if (ret != null) {
            ret += "/" + str.getString();
          } else {
            ret = str.getString();
          }
        }
        // Add the realm in the end so we have "principal@realm"
        ret += "@" + realm;
      }
    }
    return ret;
  }

  /**
   * Gets the Microsoft specific GUID altName, that is encoded as an octect
   * string.
   *
   * @param cert certificate containing the extension
   * @return String with the hex-encoded GUID byte array or null if the altName
   *     does not exist
   * @throws IOException On disk error
   * @throws CertificateParsingException if cert parse fails
   */
  public static String getGuidAltName(final Certificate cert)
      throws IOException, CertificateParsingException {
    if (cert instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) cert;
      final Collection<List<?>> altNames
          = x509cert.getSubjectAlternativeNames();
      if (altNames != null) {
        final Iterator<List<?>> i = altNames.iterator();
        while (i.hasNext()) {
          final ASN1Sequence seq = getAltnameSequence(i.next());
          if (seq != null) {
            final String guid = CertTools.getGUIDStringFromSequence(seq);
            if (guid != null) {
              return guid;
            }
          }
        }
      }
    }
    return null;
  } // getGuidAltName

  /**
   * Helper for the above methods.
   *
   * @param listitem item
   * @return asn.1
   */
  private static ASN1Sequence getAltnameSequence(final List<?> listitem) {
    final Integer no = (Integer) listitem.get(0);
    if (no.intValue() == 0) {
      final byte[] altName = (byte[]) listitem.get(1);
      return getAltnameSequence(altName);
    }
    return null;
  }

  private static ASN1Sequence getAltnameSequence(final byte[] value) {
    ASN1Primitive oct = null;
    try {
      oct = ASN1Primitive.fromByteArray(value);
    } catch (final IOException e) {
      throw new CesecoreRuntimeException("Could not read ASN1InputStream", e);
    }
    if (oct instanceof ASN1TaggedObject) {
      oct = ((ASN1TaggedObject) oct).getObject();
    }
    final ASN1Sequence seq = ASN1Sequence.getInstance(oct);
    return seq;
  }

  /**
   * Gets an altName string from an X509Extension.
   *
   * @param ext X509Extension with AlternativeNames
   * @return String as defined in method getSubjectAlternativeName
   */
  public static String getAltNameStringFromExtension(final Extension ext) {
    String altName = null;
    // GeneralNames, the actual encoded name
    final GeneralNames names = getGeneralNamesFromExtension(ext);
    if (names != null) {
      try {
        final GeneralName[] gns = names.getNames();
        for (final GeneralName gn : gns) {
          final int tag = gn.getTagNo();
          final ASN1Encodable name = gn.getName();
          final String str = CertTools.getGeneralNameString(tag, name);
          if (str == null) {
            continue;
          }
          if (altName == null) {
            altName = escapeFieldValue(str);
          } else {
            altName += ", " + escapeFieldValue(str);
          }
        }
      } catch (final IOException e) {
        LOGGER.error("IOException parsing altNames: ", e);
        return null;
      }
    }
    return altName;
  }

  /**
   * Gets GeneralNames from an X509Extension.
   *
   * @param ext X509Extension with AlternativeNames
   * @return GeneralNames with all Alternative Names
   */
  public static GeneralNames getGeneralNamesFromExtension(final Extension ext) {
    final ASN1Encodable gnames = ext.getParsedValue();
    if (gnames != null) {
      final GeneralNames names = GeneralNames.getInstance(gnames);
      return names;
    }
    return null;
  }

  /**
   * Escapes a value of a field in a DN, SAN or directory attributes. Unlike
   * LDAPDN.escapeRDN, this method allows empty values (e.g. DNSNAME=)
   *
   * @param value Value to escape, with or without the XX=
   * @return Escaped string
   */
  protected static String escapeFieldValue(final String value) {
    if (value == null) {
      return null;
    } else if (value.indexOf('=') == value.length() - 1) {
      return value;
    } else {
      return LDAPDN.escapeRDN(value);
    }
  }

  /**
   * Unescapes a value of a field in a DN, SAN or directory attributes. Unlike
   * LDAPDN.unescapeRDN, this method handles value without the field name (e.g.
   * example.com) and empty values (e.g. DNSNAME=)
   *
   * @param value Value to unescape
   * @return Unescaped string
   */
  protected static String unescapeFieldValue(final String value) {
    if (value == null) {
      return null;
    } else {
      return UNESCAPE_FIELD_REGEX.matcher(value).replaceAll("$1");
    }
  }

  /**
   * SubjectAltName ::= GeneralNames.
   *
   * <p>GeneralNames :: = SEQUENCE SIZE (1..MAX) OF GeneralName
   *
   * <p>GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1]
   * IA5String, dNSName [2] IA5String, x400Address [3] ORAddress, directoryName
   * [4] Name, ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6]
   * IA5String, iPAddress [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER}
   *
   * <p>SubjectAltName is of form \"rfc822Name=&lt;email&gt;, dNSName=&lt;host
   * name&gt;, uniformResourceIdentifier=&lt;http://host.com/&gt;,
   * iPAddress=&lt;address&gt;, guid=&lt;globally unique id&gt;,
   * directoryName=&lt;CN=testDirName|dir|name&gt;,
   * permanentIdentifier=&lt;identifierValue/assigner|identifierValue|/assigner|/&gt;
   *
   * <p>Supported altNames are upn, krb5principal, rfc822Name,
   * uniformResourceIdentifier, dNSName, iPAddress, directoryName,
   * permanentIdentifier
   *
   * @author Marco Ferrante, (c) 2005 CSITA - University of Genoa (Italy)
   * @author Tomas Gustavsson
   * @param certificate containing alt names
   * @return String containing altNames of form "rfc822Name=email,
   *     dNSName=hostname, uniformResourceIdentifier=uri, iPAddress=ip, upn=upn,
   *     directoryName=CN=testDirName|dir|name",
   *     permanentIdentifier=identifierValue/assigner or empty string if no
   *     altNames exist. Values in returned String is from CertTools constants.
   *     AltNames not supported are simply not shown in the resulting string.
   */
  public static String getSubjectAlternativeName(
          final Certificate certificate) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getSubjectAlternativeName");
    }
    String result = "";
    if (certificate instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) certificate;

      Collection<List<?>> altNames = parseAltNamesFromCert(x509cert);

      if (altNames == null) {
        return null;
      }
      final Iterator<List<?>> iter = altNames.iterator();
      String append = "";
      List<?> item = null;
      Integer type = null;
      Object value = null;
      while (iter.hasNext()) {
        item = iter.next();
        type = (Integer) item.get(0);
        value = item.get(1);
        append = appendCommaIfNeeded(result, append);
        String rdn = null;
        switch (type.intValue()) {
          case 0:
            // OtherName, can be a lot of different things
            rdn = setRDNfromOID(item, rdn);

            break;
          case 1:
            rdn = CertTools.EMAIL + "=" + (String) value;
            break;
          case 2:
            rdn = CertTools.DNS + "=" + (String) value;
            break;
          case 3: // SubjectAltName of type x400Address not supported
            break;
          case 4:
            rdn = CertTools.DIRECTORYNAME + "=" + (String) value;
            break;
          case 5: // SubjectAltName of type ediPartyName not supported
            break;
          case 6:
            rdn = CertTools.URI + "=" + (String) value;
            break;
          case 7:
            rdn = CertTools.IPADDR + "=" + (String) value;
            break;
          case 8:
            // OID names are returned as Strings according to the JDK
            // X509Certificate javadoc
            rdn = CertTools.REGISTEREDID + "=" + (String) value;
            break;
          default: // SubjectAltName of unknown type
            break;
        }
        if (rdn != null) {
          // The rdn might contain commas, so escape it.
          result += append + escapeFieldValue(rdn);
        }
      }
      logAltNameResult(result);
      if (StringUtils.isEmpty(result)) {
        return null;
      }
    }
    return result;
  }

/**
 * @param result result
 */
private static void logAltNameResult(final String result) {
    if (LOGGER.isTraceEnabled()) {
        LOGGER.trace("<getSubjectAlternativeName: " + result);
      }
}

/**
 * @param result res
 * @param append vsal
 * @return append
 */
private static String appendCommaIfNeeded(
        final String result, final String append) {
    String ret = append;
    if (!StringUtils.isEmpty(result)) {
      // Result already contains one altname, so we have to add comma if
      // there are more altNames
      ret = ", ";
    }
    return ret;
}

/**
 * @param item item
 * @param ordn rdn
 * @return rdn
 */
private static String setRDNfromOID(final List<?> item, final String ordn) {
    String rdn = ordn;
    final ASN1Sequence sequence = getAltnameSequence(item);
    final ASN1ObjectIdentifier oid =
        ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
    switch (oid.getId()) {
      case CertTools.UPN_OBJECTID:
        rdn =
            CertTools.UPN
                + "="
                + getUTF8StringFromSequence(
                    sequence, CertTools.UPN_OBJECTID);
        break;
      case CertTools.PERMANENTIDENTIFIER_OBJECTID:
        rdn =
            CertTools.PERMANENTIDENTIFIER
                + "="
                + getPermanentIdentifierStringFromSequence(sequence);
        break;
      case CertTools.KRB5PRINCIPAL_OBJECTID:
        rdn =
            CertTools.KRB5PRINCIPAL
                + "="
                + getKrb5PrincipalNameFromSequence(sequence);
        break;
      case RFC4683Util.SUBJECTIDENTIFICATIONMETHOD_OBJECTID:
        final String sim = RFC4683Util.getSimStringSequence(sequence);
        rdn = RFC4683Util.SUBJECTIDENTIFICATIONMETHOD + "=" + sim;
        break;
      case CertTools.GUID_OBJECTID:
        rdn =
            CertTools.GUID + "=" + getGUIDStringFromSequence(sequence);
        break;
      case CertTools.XMPPADDR_OBJECTID:
        rdn =
            CertTools.XMPPADDR
                + "="
                + getUTF8StringFromSequence(
                    sequence, CertTools.XMPPADDR_OBJECTID);
        break;
      case CertTools.SRVNAME_OBJECTID:
        rdn =
            CertTools.SRVNAME
                + "="
                + getIA5StringFromSequence(
                    sequence, CertTools.SRVNAME_OBJECTID);
        break;
      case CertTools.FASCN_OBJECTID:
        // PIV FASC-N (FIPS 201-2) is an OCTET STRING, we'll return if
        // as a hex encoded String
        rdn =
            CertTools.FASCN
                + "="
                + new String(
                    Hex.encode(
                        getOctetStringFromSequence(
                            sequence, CertTools.FASCN_OBJECTID)));
        break;
        default: break; // no-op
    }
    return rdn;
}

/**
 * @param x509cert cert
 * @return names
 * @throws CesecoreRuntimeException fail
 */
private static Collection<List<?>> parseAltNamesFromCert(
        final X509Certificate x509cert)
        throws CesecoreRuntimeException {
    Collection<List<?>> altNames = null;

      try {
        altNames = x509cert.getSubjectAlternativeNames();
      } catch (final CertificateParsingException e) {
        throw new CesecoreRuntimeException("Could not parse certificate", e);
      }
    return altNames;
}

  /**
   * From an altName string as defined in getSubjectAlternativeName.
   *
   * @param altName name
   * @return ASN.1 GeneralNames
   * @see #getSubjectAlternativeName
   */
  public static GeneralNames getGeneralNamesFromAltName(final String altName) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">getGeneralNamesFromAltName: " + altName);
    }
    final ASN1EncodableVector vec = new ASN1EncodableVector();

    for (final String email : CertTools.getEmailFromDN(altName)) {
      vec.add(new GeneralName(1, /*new DERIA5String(iter.next())*/ email));
    }

    for (final String dns : CertTools.getPartsFromDN(altName, CertTools.DNS)) {
      vec.add(new GeneralName(2, new DERIA5String(dns)));
    }

    final String directoryName = getDirectoryStringFromAltName(altName);
    if (directoryName != null) {
      final X500Name x500DirectoryName =
          new X500Name(CeSecoreNameStyle.INSTANCE, directoryName);
      final GeneralName gn = new GeneralName(4, x500DirectoryName);
      vec.add(gn);
    }
    gnGetUris(altName, vec);

    gnGetIps(altName, vec);
    for (final String oid
        : CertTools.getPartsFromDN(altName, CertTools.REGISTEREDID)) {
      vec.add(new GeneralName(GeneralName.registeredID, oid));
    }

    // UPN is an OtherName see method getUpn... for asn.1 definition
    gnSetUPN(altName, vec);

    // XmpAddr is an OtherName see method getUTF8String...... for asn.1
    // definition
    gnSetXmppAddr(altName, vec);

    // srvName is an OtherName see method getIA5String...... for asn.1
    // definition
    gnSetSrvName(altName, vec);

    // FASC-N is an OtherName see method getOctetString...... for asn.1
    // definition (PIV FIPS 201-2)
    // We take the input as being a hex encoded octet string
    gnSetFascN(altName, vec);

    // PermanentIdentifier is an OtherName see method
    // getPermananentIdentifier... for asn.1 definition
    gnSetPID(altName, vec);

    gnSetGuid(altName, vec);

    // Krb5PrincipalName is an OtherName, see method getKrb5Principal...for
    // ASN.1 definition
    gnSetKrb5Name(altName, vec);

    // SIM is an OtherName. See RFC-4683
    gnSetSimString(altName, vec);

    // To support custom OIDs in altNames, they must be added as an OtherName of
    // plain type UTF8String
    gnGetOids(altName, vec);

    if (vec.size() > 0) {
      return GeneralNames.getInstance(new DERSequence(vec));
    }
    return null;
  }

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnGetIps(final String altName,
        final ASN1EncodableVector vec) {
    for (final String addr
        : CertTools.getPartsFromDN(altName, CertTools.IPADDR)) {
      final byte[] ipoctets = StringUtil.ipStringToOctets(addr);
      if (ipoctets.length > 0) {
        final GeneralName gn = new GeneralName(7, new DEROctetString(ipoctets));
        vec.add(gn);
      } else {
        LOGGER.error("Cannot parse/encode ip address, ignoring: " + addr);
      }
    }
}

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnGetUris(final String altName,
        final ASN1EncodableVector vec) {
    final int uriTag = 6;
    for (final String uri : CertTools.getPartsFromDN(altName, CertTools.URI)) {
      vec.add(new GeneralName(uriTag, new DERIA5String(uri)));
    }
    for (final String uri : CertTools.getPartsFromDN(altName, CertTools.URI1)) {
      vec.add(new GeneralName(uriTag, new DERIA5String(uri)));
    }
    for (final String uri : CertTools.getPartsFromDN(altName, CertTools.URI2)) {
      vec.add(new GeneralName(uriTag, new DERIA5String(uri)));
    }
}

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnGetOids(final String altName,
        final ASN1EncodableVector vec) {
    for (final String oid : CertTools.getCustomOids(altName)) {
      for (final String oidValue : CertTools.getPartsFromDN(altName, oid)) {
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier(oid));
        v.add(new DERTaggedObject(true, 0, new DERUTF8String(oidValue)));
        final ASN1Primitive gn =
            new DERTaggedObject(false, 0, new DERSequence(v));
        vec.add(gn);
      }
    }
}

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnSetSimString(final String altName,
        final ASN1EncodableVector vec) {
    for (final String internalSimString
        : CertTools.getPartsFromDN(
            altName, RFC4683Util.SUBJECTIDENTIFICATIONMETHOD)) {
      if (StringUtils.isNotBlank(internalSimString)) {
          final int index = 3;
        final String[] tokens =
            internalSimString.split(RFC4683Util.LIST_SEPARATOR);
        if (tokens.length == index) {
          final ASN1Primitive gn =
              RFC4683Util.createSimGeneralName(
                  tokens[0], tokens[1], tokens[2]);
          vec.add(gn);
          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("SIM GeneralName added: " + gn.toString());
          }
        }
      }
    }
}

/**
 * @param altName Nam
 * @param vec Vec
 */
private static void gnSetKrb5Name(final String altName,
        final ASN1EncodableVector vec) {
    for (final String principalString
        : CertTools.getPartsFromDN(altName, CertTools.KRB5PRINCIPAL)) {
      // Start by parsing the input string to separate it in different parts
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("principalString: " + principalString);
      }
      // The realm is the last part moving back until an @
      final int index = principalString.lastIndexOf('@');
      String realm = "";
      if (index > 0) {
        realm = principalString.substring(index + 1);
      }
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("realm: " + realm);
      }
      // Now we can have several principals separated by /
      final ArrayList<String> principalarr = new ArrayList<String>();
      int jndex = 0;
      int bindex = 0;
      while (jndex < index) {
        // Loop and add all strings separated by /
        jndex = principalString.indexOf('/', bindex);
        if (jndex == -1) {
          jndex = index;
        }
        final String s = principalString.substring(bindex, jndex);
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("adding principal name: " + s);
        }
        principalarr.add(s);
        bindex = jndex + 1;
      }

      // Now we must construct the rather complex asn.1...
      final ASN1EncodableVector v =
          new ASN1EncodableVector(); // this is the OtherName
      v.add(new ASN1ObjectIdentifier(CertTools.KRB5PRINCIPAL_OBJECTID));

      // First the Krb5PrincipalName sequence
      final ASN1EncodableVector krb5p = new ASN1EncodableVector();
      // The realm is the first tagged GeneralString
      krb5p.add(new DERTaggedObject(true, 0, new DERGeneralString(realm)));
      // Second is the sequence of principal names, which is at tagged position
      // 1 in the krb5p
      final ASN1EncodableVector principals = new ASN1EncodableVector();
      // According to rfc4210 the type NT-UNKNOWN is 0, and according to some
      // other rfc this type should be used...
      principals.add(new DERTaggedObject(true, 0, new ASN1Integer(0)));
      // The names themselves are yet another sequence
      final ASN1EncodableVector names = new ASN1EncodableVector();
      for (final String principalName : principalarr) {
        names.add(new DERGeneralString(principalName));
      }
      principals.add(new DERTaggedObject(true, 1, new DERSequence(names)));
      krb5p.add(new DERTaggedObject(true, 1, new DERSequence(principals)));

      v.add(new DERTaggedObject(true, 0, new DERSequence(krb5p)));
      final ASN1Primitive gn =
          new DERTaggedObject(false, 0, new DERSequence(v));
      vec.add(gn);
    }
}

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnSetGuid(final String altName,
        final ASN1EncodableVector vec) {
    for (final String guid
        : CertTools.getPartsFromDN(altName, CertTools.GUID)) {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      final byte[] guidbytes = Hex.decode(guid);
      if (guidbytes != null) {
        v.add(new ASN1ObjectIdentifier(CertTools.GUID_OBJECTID));
        v.add(new DERTaggedObject(true, 0, new DEROctetString(guidbytes)));
        final ASN1Primitive gn =
            new DERTaggedObject(false, 0, new DERSequence(v));
        vec.add(gn);
      } else {
        LOGGER.error("Cannot decode hexadecimal guid, ignoring: " + guid);
      }
    }
}

/**
 * @param altName name
 * @param vec vec
 */
private static void gnSetPID(final String altName,
        final ASN1EncodableVector vec) {
    for (final String permanentIdentifier
        : CertTools.getPartsFromDN(altName, CertTools.PERMANENTIDENTIFIER)) {
      final String[] values = getPermanentIdentifierValues(permanentIdentifier);
      final ASN1EncodableVector v =
          new ASN1EncodableVector(); // this is the OtherName
      v.add(new ASN1ObjectIdentifier(CertTools.PERMANENTIDENTIFIER_OBJECTID));
      // First the PermanentIdentifier sequence
      final ASN1EncodableVector piSeq = new ASN1EncodableVector();
      if (values[0] != null) {
        piSeq.add(new DERUTF8String(values[0]));
      }
      if (values[1] != null) {
        piSeq.add(new ASN1ObjectIdentifier(values[1]));
      }
      v.add(new DERTaggedObject(true, 0, new DERSequence(piSeq)));
      // GeneralName gn = new GeneralName(new DERSequence(v), 0);
      final ASN1Primitive gn =
          new DERTaggedObject(false, 0, new DERSequence(v));
      vec.add(gn);
    }
}

/**
 * @param altName name
 * @param vec vec
 */
private static void gnSetFascN(final String altName,
        final ASN1EncodableVector vec) {
    for (final String fascN
        : CertTools.getPartsFromDN(altName, CertTools.FASCN)) {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1ObjectIdentifier(CertTools.FASCN_OBJECTID));
      v.add(
          new DERTaggedObject(true, 0, new DEROctetString(Hex.decode(fascN))));
      vec.add(
          GeneralName.getInstance(
              new DERTaggedObject(false, 0, new DERSequence(v))));
    }
}

/**
 * @param altName name
 * @param vec vec
 */
private static void gnSetSrvName(final String altName,
        final ASN1EncodableVector vec) {
    for (final String srvName
       :  CertTools.getPartsFromDN(altName, CertTools.SRVNAME)) {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1ObjectIdentifier(CertTools.SRVNAME_OBJECTID));
      v.add(new DERTaggedObject(true, 0, new DERIA5String(srvName)));
      vec.add(
          GeneralName.getInstance(
              new DERTaggedObject(false, 0, new DERSequence(v))));
    }
}

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnSetXmppAddr(final String altName,
        final ASN1EncodableVector vec) {
    for (final String xmppAddr
        : CertTools.getPartsFromDN(altName, CertTools.XMPPADDR)) {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1ObjectIdentifier(CertTools.XMPPADDR_OBJECTID));
      v.add(new DERTaggedObject(true, 0, new DERUTF8String(xmppAddr)));
      vec.add(
          GeneralName.getInstance(
              new DERTaggedObject(false, 0, new DERSequence(v))));
    }
}

/**
 * @param altName Name
 * @param vec Vec
 */
private static void gnSetUPN(final String altName,
        final ASN1EncodableVector vec) {
    for (final String upn : CertTools.getPartsFromDN(altName, CertTools.UPN)) {
      final ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1ObjectIdentifier(CertTools.UPN_OBJECTID));
      v.add(new DERTaggedObject(true, 0, new DERUTF8String(upn)));
      vec.add(
          GeneralName.getInstance(
              new DERTaggedObject(false, 0, new DERSequence(v))));
    }
}

  /**
   * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1] IA5String,
   * dNSName [2] IA5String, x400Address [3] ORAddress, directoryName [4] Name,
   * ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6] IA5String,
   * iPAddress [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER}.
   *
   * @param tag the no tag 0-8
   * @param value the ASN1Encodable value as returned by GeneralName.getName()
   * @return String in form rfc822Name=&lt;email&gt; or uri=&lt;uri&gt; etc
   * @throws IOException on disk error
   * @see #getSubjectAlternativeName
   */
  public static String getGeneralNameString(
          final int tag, final ASN1Encodable value)
      throws IOException {
    String ret = null;
    switch (tag) {
      case 0:

          final ASN1Sequence sequence =
              getAltnameSequence(value.toASN1Primitive().getEncoded());
          ASN1ObjectIdentifier oid =
              ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
          switch (oid.getId()) {
            case CertTools.UPN_OBJECTID:
              ret =
                  CertTools.UPN
                      + "="
                      + getUTF8StringFromSequence(
                          sequence, CertTools.UPN_OBJECTID);
              break;
            case CertTools.PERMANENTIDENTIFIER_OBJECTID:
              ret =
                  CertTools.PERMANENTIDENTIFIER
                      + "="
                      + getPermanentIdentifierStringFromSequence(sequence);
              break;
            case CertTools.KRB5PRINCIPAL_OBJECTID:
              ret =
                  CertTools.KRB5PRINCIPAL
                      + "="
                      + getKrb5PrincipalNameFromSequence(sequence);
              break;
            case RFC4683Util.SUBJECTIDENTIFICATIONMETHOD_OBJECTID:
              ret =
                  RFC4683Util.SUBJECTIDENTIFICATIONMETHOD
                      + "="
                      + RFC4683Util.getSimStringSequence(sequence);
              break;
            case CertTools.XMPPADDR_OBJECTID:
              ret =
                  CertTools.XMPPADDR
                      + "="
                      + getUTF8StringFromSequence(
                          sequence, CertTools.XMPPADDR_OBJECTID);
              break;
            case CertTools.SRVNAME_OBJECTID:
              ret =
                  CertTools.SRVNAME
                      + "="
                      + getIA5StringFromSequence(
                          sequence, CertTools.SRVNAME_OBJECTID);
              break;
            case CertTools.FASCN_OBJECTID:
              ret =
                  CertTools.FASCN
                      + "="
                      + new String(
                          Hex.encode(
                              getOctetStringFromSequence(
                                  sequence, CertTools.FASCN_OBJECTID)));
              break;
              default: break; //no-op
          }

          break;

      case 1:
        ret =
            CertTools.EMAIL + "=" + DERIA5String.getInstance(value).getString();
        break;
      case 2:
        ret = CertTools.DNS + "=" + DERIA5String.getInstance(value).getString();
        break;
      case 3: // SubjectAltName of type x400Address not supported
        break;
      case 4:
        final X500Name name = X500Name.getInstance(value);
        ret = CertTools.DIRECTORYNAME + "=" + name.toString();
        break;
      case 5: // SubjectAltName of type ediPartyName not supported
        break;
      case 6:
        ret = CertTools.URI + "=" + DERIA5String.getInstance(value).getString();
        break;
      case 7:
        final ASN1OctetString oct = ASN1OctetString.getInstance(value);
        ret =
            CertTools.IPADDR
                + "="
                + StringUtil.ipOctetsToString(oct.getOctets());
        break;
      case 8:
        // BC GeneralName stores the actual object value, which is an OID
        oid = ASN1ObjectIdentifier.getInstance(value);
        ret = CertTools.REGISTEREDID + "=" + oid.getId();
        break;
      default: // SubjectAltName of unknown type
        break;
    }
    return ret;
  }

  /**
   * Check the certificate with CA certificate.
   *
   * @param certificate certificate to verify
   * @param caCertChain collection of X509Certificates
   * @param date Date to verify at, or null to use current time.
   * @param pkixCertPathCheckers optional PKIXCertPathChecker implementations to
   *     use during cert path validation
   * @return true if verified OK
   * @throws CertPathValidatorException if certificate could not be validated
   */
  public static boolean verify(
      final X509Certificate certificate,
      final Collection<X509Certificate> caCertChain,
      final Date date,
      final PKIXCertPathChecker... pkixCertPathCheckers)
      throws CertPathValidatorException {
    try {
      final ArrayList<X509Certificate> certlist = new ArrayList<>();
      // Create CertPath
      certlist.add(certificate);
      // Add other certs...
      final CertPath cp =
          CertificateFactory.getInstance(
                  "X.509", BouncyCastleProvider.PROVIDER_NAME)
              .generateCertPath(certlist);

      // Create TrustAnchor. Since EJBCA use BouncyCastle provider, we assume
      // certificate already in correct order
      final X509Certificate[] cac =
          caCertChain.toArray(new X509Certificate[caCertChain.size()]);
      final TrustAnchor anchor = new TrustAnchor(cac[0], null);
      // Set the PKIX parameters
      final PKIXParameters params =
              new PKIXParameters(Collections.singleton(anchor));
      for (final PKIXCertPathChecker pkixCertPathChecker
          : pkixCertPathCheckers) {
        params.addCertPathChecker(pkixCertPathChecker);
      }
      params.setRevocationEnabled(false);
      params.setDate(date);
      final CertPathValidator cpv =
          CertPathValidator.getInstance(
              "PKIX", BouncyCastleProvider.PROVIDER_NAME);
      final PKIXCertPathValidatorResult result =
          (PKIXCertPathValidatorResult) cpv.validate(cp, params);
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Certificate verify result: " + result.toString());
      }
    } catch (final CertPathValidatorException cpve) {
      throw new CertPathValidatorException(
          "Invalid certificate or certificate not issued by specified CA: "
              + cpve.getMessage());
    } catch (final CertificateException e) {
      throw new IllegalArgumentException(
          "Something was wrong with the supplied certificate", e);
    } catch (final NoSuchProviderException e) {
      throw new IllegalStateException("BouncyCastle provider not found.", e);
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("Algorithm PKIX was not found.", e);
    } catch (final InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException(
          "Either ca certificate chain was empty, or the certificate was on an"
              + " inappropraite type for a PKIX path checker.",
          e);
    }
    return true;
  }

  /**
   * Check the certificate with CA certificate.
   *
   * @param certificate certificate to verify
   * @param caCertChain collection of X509Certificates
   * @return true if verified OK
   * @throws CertPathValidatorException if verification failed
   */
  public static boolean verify(
      final X509Certificate certificate,
      final Collection<X509Certificate> caCertChain)
      throws CertPathValidatorException {
    return verify(certificate, caCertChain, null);
  }

  /**
   * Check the certificate with a list of trusted certificates. The trusted
   * certificates list can either be end entity certificates, in this case, only
   * this certificate by this issuer is trusted; or it could be CA certificates,
   * in this case, all certificates issued by this CA are trusted.
   *
   * @param certificate certificate to verify
   * @param trustedCertificates collection of trusted X509Certificates
   * @param pkixCertPathCheckers optional PKIXCertPathChecker implementations to
   *     use during cert path validation
   * @return true if verified OK
   */
  public static boolean verifyWithTrustedCertificates(
      final X509Certificate certificate,
      final List<Collection<X509Certificate>> trustedCertificates,
      final PKIXCertPathChecker... pkixCertPathCheckers) {

    if (trustedCertificates == null) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
                "Input of trustedCertificates was null. Trusting nothing.");
      }
      return false;
    }

    if (trustedCertificates.size() == 0) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Input of trustedCertificates was empty. Trusting everything.");
      }
      return true;
    }

    final BigInteger certSN = getSerialNumber(certificate);
    for (final Collection<X509Certificate> trustedCertChain
            : trustedCertificates) {
      final X509Certificate trustedCert = trustedCertChain.iterator().next();
      final BigInteger trustedCertSN = getSerialNumber(trustedCert);
      if (certSN.equals(trustedCertSN)
        && trustedCertChain.size() > 1) {
        // If the serial number of the certificate matches the serial number of
        // a certificate in the list, make sure that it in
        // fact is the same certificate by verifying that they were issued by
        // the same issuer.
        // Removing this trusted certificate from the trustedCertChain will
        // leave only the CA's certificate chain, which will be
        // used to verify the issuer.
          trustedCertChain.remove(trustedCert);

      }
      try {
        verify(certificate, trustedCertChain, null, pkixCertPathCheckers);
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(
              "Trusting certificate with SubjectDN '"
                  + getSubjectDN(certificate)
                  + "' and issuerDN '"
                  + getIssuerDN(certificate)
                  + "'.");
        }
        return true;
      } catch (final CertPathValidatorException e) { // NOPMD
        // Do nothing. Just try the next trusted certificate chain in the list
      }
    }
    return false;
  }

  /**
   * Checks that the given date is within the certificate's validity period. In
   * other words, this determines whether the certificate would be valid at the
   * given date/time.
   *
   * <p>This utility class is only a helper to get the same behavior as the
   * standard java.security.cert API regardless if using X.509 or CV
   * Certificate.
   *
   * @param cert certificate to verify, if null the method returns immediately,
   *     null does not have a validity to check.
   * @param date the Date to check against to see if this certificate is valid
   *     at that date/time.
   * @throws CertificateExpiredException - if the certificate has expired with
   *     respect to the date supplied.
   * @throws CertificateNotYetValidException - if the certificate is not yet
   *     valid with respect to the date supplied.
   * @see java.security.cert.X509Certificate#checkValidity(Date)
   */
  public static void checkValidity(final Certificate cert, final Date date)
      throws CertificateExpiredException, CertificateNotYetValidException {
    if (cert != null) {
      if (cert instanceof X509Certificate) {
        final X509Certificate xcert = (X509Certificate) cert;
        xcert.checkValidity(date);
      } else if (StringUtils.equals(cert.getType(), "CVC")) {
        final CardVerifiableCertificate cvccert =
            (CardVerifiableCertificate) cert;
        try {
          final Date start =
              cvccert.getCVCertificate().getCertificateBody().getValidFrom();
          final Date end =
              cvccert.getCVCertificate().getCertificateBody().getValidTo();
          if (start.after(date)) {
            final String msg =
                "CV Certificate startDate '"
                    + start
                    + "' is after check date '"
                    + date
                    + "'. Subject: "
                    + CertTools.getSubjectDN(cert);
            if (LOGGER.isTraceEnabled()) {
              LOGGER.trace(msg);
            }
            throw new CertificateNotYetValidException(msg);
          }
          if (end.before(date)) {
            final String msg =
                "CV Certificate endDate '"
                    + end
                    + "' is before check date '"
                    + date
                    + "'. Subject: "
                    + CertTools.getSubjectDN(cert);
            if (LOGGER.isTraceEnabled()) {
              LOGGER.trace(msg);
            }
            throw new CertificateExpiredException(msg);
          }
        } catch (final NoSuchFieldException e) {
          LOGGER.error("NoSuchFieldException: ", e);
        }
      }
    }
  }

  /**
   * Return the first CRL distribution points. The CRL distributions points are
   * URL specified in the certificate extension CRLDistributionPoints with OID
   * 2.5.29.31.
   *
   * <p>The CRLDistributionPoints extension contains a sequece of
   * DistributionPoint, which has the following structure:
   *
   * <p>DistributionPoint ::= SEQUENCE { distributionPoint [0]
   * DistributionPointName OPTIONAL, reasons [1] ReasonFlags OPTIONAL, cRLIssuer
   * [2] GeneralNames OPTIONAL }
   *
   * <p>This method extracts "distributionPoint" (tag 0) from the first
   * DistributionPoint included in the extension. No other tags are read.
   *
   * @param certificate certificate
   * @return A URL, or null if no CRL distribution points were found
   */
  public static URL getCrlDistributionPoint(final Certificate certificate) {
    if (certificate instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) certificate;
      final Collection<URL> cdps = getCrlDistributionPoints(x509cert, true);
      if (!cdps.isEmpty()) {
        return cdps.iterator().next();
      }
    }
    return null;
  }

  /**
   * Return a list of CRL distribution points. The CRL distributions points are
   * URL specified in the certificate extension CRLDistributionPoints with OID
   * 2.5.29.31.
   *
   * <p>The CRLDistributionPoints extension contains a sequece of
   * DistributionPoint, which has the following structure:
   *
   * <p>DistributionPoint ::= SEQUENCE { distributionPoint [0]
   * DistributionPointName OPTIONAL, reasons [1] ReasonFlags OPTIONAL, cRLIssuer
   * [2] GeneralNames OPTIONAL }
   *
   * <p>This method extracts "distributionPoint" (tag 0) from every
   * DistributionPoint included in the extension. No other tags are read.
   *
   * @param x509cert X.509 cert
   * @return A list of URLs
   */
  public static Collection<URL> getCrlDistributionPoints(
      final X509Certificate x509cert) {
    return getCrlDistributionPoints(x509cert, false);
  }

  private static Collection<URL> getCrlDistributionPoints(
      final X509Certificate x509cert, final boolean onlyfirst) {
    final ArrayList<URL> cdps = new ArrayList<URL>();
    final ASN1Primitive obj =
        getExtensionValue(x509cert, Extension.cRLDistributionPoints.getId());
    if (obj == null) {
      return cdps;
    }

    final ASN1Sequence crlDistributionPoints = (ASN1Sequence) obj;
    for (int i = 0; i < crlDistributionPoints.size(); i++) {
      final ASN1Sequence distributionPoint =
          (ASN1Sequence) crlDistributionPoints.getObjectAt(i);
      for (int j = 0; j < distributionPoint.size(); j++) {
        final ASN1TaggedObject tagged =
            (ASN1TaggedObject) distributionPoint.getObjectAt(j);
        if (tagged.getTagNo() == 0) {
          final String url = getStringFromGeneralNames(tagged.getObject());
          if (url != null) {
            try {
              cdps.add(new URL(url));
            } catch (final MalformedURLException e) {
              if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                    "Error parsing '"
                        + url
                        + "' as a URL. "
                        + e.getLocalizedMessage());
              }
            }
          }
          if (onlyfirst) {
            return cdps; // returning only the first URL
          }
        }
      }
    }
    return cdps;
  }

  /**
   * This utility method extracts the Authority Information Access Extention's
   * URLs.
   *
   * @param crl a CRL to parse
   * @return the Authority Information Access Extention's URLs, or an empty
   *     Collection if none were found
   */
  public static Collection<String> getAuthorityInformationAccess(
          final CRL crl) {
    final Collection<String> result = new ArrayList<String>();
    if (crl instanceof X509CRL) {
      final X509CRL x509crl = (X509CRL) crl;
      final ASN1Primitive derObject =
          getExtensionValue(x509crl, Extension.authorityInfoAccess.getId());
      if (derObject != null) {
        final AuthorityInformationAccess authorityInformationAccess =
            AuthorityInformationAccess.getInstance(derObject);
        final AccessDescription[] accessDescriptions =
            authorityInformationAccess.getAccessDescriptions();
        if (accessDescriptions != null && accessDescriptions.length > 0) {
          for (final AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription
                .getAccessMethod()
                .equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
              final GeneralName generalName =
                      accessDescription.getAccessLocation();
              if (generalName.getTagNo()
                  == GeneralName.uniformResourceIdentifier) {
                // Due to bug in java getting some ASN.1 objects, it can be
                // tagged an extra time...
                ASN1Primitive obj = generalName.toASN1Primitive();
                if (obj instanceof ASN1TaggedObject) {
                  obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                final DERIA5String deria5String = DERIA5String.getInstance(obj);
                result.add(deria5String.getString());
              }
            }
          }
        }
      }
    }
    return result;
  }

  /**
   * @param cert cert
   * @return all CA issuer URI that are inside AuthorityInformationAccess
   *     extension or an empty list
   */
  public static List<String> getAuthorityInformationAccessCAIssuerUris(
      final Certificate cert) {
    return getAuthorityInformationAccessCaIssuerUris(cert, false);
  }

  /**
   * @return the first OCSP URL that is inside AuthorityInformationAccess
   *     extension, or null.
   * @param cert is the certificate to parse
   */
  public static String getAuthorityInformationAccessOcspUrl(
          final Certificate cert) {
    final Collection<String> urls = getAuthorityInformationAccessOcspUrls(cert);
    if (!urls.isEmpty()) {
      return urls.iterator().next();
    }
    return null;
  }

  /**
   * @param cert cert
   * @return all OCSP URL that is inside AuthorityInformationAccess extension or
   *     an empty list
   */
  public static List<String> getAuthorityInformationAccessOcspUrls(
      final Certificate cert) {
    return getAuthorityInformationAccessOcspUrls(cert, false);
  }

  /**
   * @param cert cert
   * @param onlyfirst only return first result if true
   * @return all CA issuer URI that are inside AuthorityInformationAccess
   *     extension or an empty list.
   */
  private static List<String> getAuthorityInformationAccessCaIssuerUris(
      final Certificate cert, final boolean onlyfirst) {
    final List<String> urls = new ArrayList<>();
    if (cert instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) cert;
      final ASN1Primitive obj =
          getExtensionValue(x509cert, Extension.authorityInfoAccess.getId());
      if (obj != null) {
        final AccessDescription[] accessDescriptions =
            AuthorityInformationAccess.getInstance(obj).getAccessDescriptions();
        if (accessDescriptions != null) {
          for (final AccessDescription accessDescription : accessDescriptions) {
            // OID 1.3.6.1.5.5.7.48.2: 2 times in Bouncy Castle
            // X509ObjectIdentifiers class.
            // X509ObjectIdentifiers.id_ad_caIssuers =
            // X509ObjectIdentifiers.crlAccessMethod
            if (accessDescription
                .getAccessMethod()
                .equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
              final GeneralName generalName =
                  accessDescription.getAccessLocation();
              if (generalName.getTagNo()
                  == GeneralName.uniformResourceIdentifier) {
                // After encoding in a cert, it is tagged an extra time...
                ASN1Primitive gnobj = generalName.toASN1Primitive();
                if (gnobj instanceof ASN1TaggedObject) {
                  gnobj = ASN1TaggedObject.getInstance(gnobj).getObject();
                }
                final DERIA5String str = DERIA5String.getInstance(gnobj);
                if (str != null) {
                  urls.add(str.getString());
                }
                if (onlyfirst) {
                  return urls; // returning only the first URL
                }
              }
            }
          }
        }
      }
    }
    return urls;
  }

  /**
   * @param cert cert
   * @param onlyfirst only return first result if true
   * @return all OCSP URL that is inside AuthorityInformationAccess extension or
   *     an empty list
   */
  private static List<String> getAuthorityInformationAccessOcspUrls(
      final Certificate cert, final boolean onlyfirst) {
    final List<String> urls = new ArrayList<>();
    if (cert instanceof X509Certificate) {
      final X509Certificate x509cert = (X509Certificate) cert;
      final ASN1Primitive obj =
          getExtensionValue(x509cert, Extension.authorityInfoAccess.getId());
      if (obj != null) {
        final AccessDescription[] accessDescriptions =
            AuthorityInformationAccess.getInstance(obj).getAccessDescriptions();
        if (accessDescriptions != null) {
          for (final AccessDescription accessDescription : accessDescriptions) {
            // OID 1.3.6.1.5.5.7.48.1: 2 times in Bouncy Castle
            // X509ObjectIdentifiers class.
            // X509ObjectIdentifiers.id_ad_ocsp =
            // X509ObjectIdentifiers.ocspAccessMethod
            if (accessDescription
                .getAccessMethod()
                .equals(X509ObjectIdentifiers.ocspAccessMethod)) {
              final GeneralName generalName =
                  accessDescription.getAccessLocation();
              if (generalName.getTagNo()
                  == GeneralName.uniformResourceIdentifier) {
                // After encoding in a cert, it is tagged an extra time...
                ASN1Primitive gnobj = generalName.toASN1Primitive();
                if (gnobj instanceof ASN1TaggedObject) {
                  gnobj = ASN1TaggedObject.getInstance(gnobj).getObject();
                }
                final DERIA5String str = DERIA5String.getInstance(gnobj);
                if (str != null) {
                  urls.add(str.getString());
                }
                if (onlyfirst) {
                  return urls; // returning only the first URL
                }
              }
            }
          }
        }
      }
    }
    return urls;
  }

  /**
   * @param cert cert
   * @return PrivateKeyUsagePeriod extension from a certificate
   */
  public static PrivateKeyUsagePeriod getPrivateKeyUsagePeriod(
      final X509Certificate cert) {
    PrivateKeyUsagePeriod res = null;
    final byte[] extvalue =
        cert.getExtensionValue(Extension.privateKeyUsagePeriod.getId());
    if (extvalue != null && extvalue.length > 0) {
      if (LOGGER.isTraceEnabled()) {
        LOGGER.trace(
            "Found a PrivateKeyUsagePeriod in the certificate with subject: "
                + cert.getSubjectDN().toString());
      }
      res =
          PrivateKeyUsagePeriod.getInstance(
              DEROctetString.getInstance(extvalue).getOctets());
    }
    return res;
  }

  /**
   * @param cert An X509Certificate
   * @param oid An OID for an extension
   * @return an Extension ASN1Primitive from a certificate, or null
   */
  protected static ASN1Primitive getExtensionValue(
      final X509Certificate cert, final String oid) {
    if (cert == null) {
      return null;
    }
    return getDerObjectFromByteArray(cert.getExtensionValue(oid));
  }

  /**
   * @param crl an X509CRL
   * @param oid An OID for an extension
   * @return an Extension ASN1Primitive from a CRL
   */
  protected static ASN1Primitive getExtensionValue(
          final X509CRL crl, final String oid) {
    if (crl == null || oid == null) {
      return null;
    }
    return getDerObjectFromByteArray(crl.getExtensionValue(oid));
  }

  /**
   * @param pkcs10CertificateRequest PKCS10 Request
   * @param oid OID
   * @return the PKCS#10's extension of the specified OID or null if no such
   *     extension exists
   */
  public static Extension getExtension(
      final PKCS10CertificationRequest pkcs10CertificateRequest,
      final String oid) {
    if (pkcs10CertificateRequest != null && oid != null) {
      final Extensions extensions =
          getPKCS10Extensions(pkcs10CertificateRequest);
      if (extensions != null) {
        return extensions.getExtension(new ASN1ObjectIdentifier(oid));
      }
    }
    return null;
  }

  /**
   * @param pkcs10CertificateRequest PKCS10 request
   * @return the first found extensions or null if
   *     PKCSObjectIdentifiers.pkcs_9_at_extensionRequest was not present in the
   *     PKCS#10
   */
  private static Extensions getPKCS10Extensions(
      final PKCS10CertificationRequest pkcs10CertificateRequest) {
    final Attribute[] attributes =
        pkcs10CertificateRequest.getAttributes(
            PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
    for (final Attribute attribute : attributes) {
      final ASN1Set attributeValues = attribute.getAttrValues();
      if (attributeValues.size() > 0) {
        return Extensions.getInstance(attributeValues.getObjectAt(0));
      }
    }
    return null;
  }

  private static ASN1Primitive getDerObjectFromByteArray(final byte[] bytes) {
    if (bytes == null) {
      return null;
    }
    try {
      return ASN1Primitive.fromByteArray(
          ASN1OctetString.getInstance(bytes).getOctets());
    } catch (final IOException e) {
      throw new CesecoreRuntimeException("Caught an unexected IOException", e);
    }
  }

  /**
   * Gets a URI string from a GeneralNames structure.
   *
   * @param names DER GeneralNames object, that is a sequence of DERTaggedObject
   * @return String with URI if tagNo is 6 (uniformResourceIdentifier), null
   *     otherwise
   */
  private static String getStringFromGeneralNames(final ASN1Primitive names) {
    final ASN1Sequence namesSequence =
        ASN1Sequence.getInstance((ASN1TaggedObject) names, false);
    if (namesSequence.size() == 0) {
      return null;
    }
    final ASN1TaggedObject taggedObject =
        (ASN1TaggedObject) namesSequence.getObjectAt(0);
    if (taggedObject.getTagNo()
        != GeneralName
            .uniformResourceIdentifier) { // uniformResourceIdentifier [6]
                                          // IA5String,
      return null;
    }
    return new String(
        ASN1OctetString.getInstance(taggedObject, false).getOctets());
  } // getStringFromGeneralNames

  /**
   * Generate SHA1 fingerprint of certificate in string representation.
   *
   * @param cert Certificate.
   * @return String containing hex format of SHA1 fingerprint (lower case), or
   *     null if input is null.
   */
  public static String getFingerprintAsString(final Certificate cert) {
    if (cert == null) {
      return null;
    }
    try {
      final byte[] res = generateSHA1Fingerprint(cert.getEncoded());

      return new String(Hex.encode(res));
    } catch (final CertificateEncodingException cee) {
      LOGGER.error("Error encoding certificate.", cee);
    }

    return null;
  }

  /**
   * Generate SHA1 fingerprint of CRL in string representation.
   *
   * @param crl X509CRL.
   * @return String containing hex format of SHA1 fingerprint.
   */
  public static String getFingerprintAsString(final X509CRL crl) {
    try {
      final byte[] res = generateSHA1Fingerprint(crl.getEncoded());

      return new String(Hex.encode(res));
    } catch (final CRLException ce) {
      LOGGER.error("Error encoding CRL.", ce);
    }

    return null;
  }

  /**
   * Generate SHA1 fingerprint of byte array in string representation.
   *
   * @param in byte array to fingerprint.
   * @return String containing hex format of SHA1 fingerprint.
   */
  public static String getFingerprintAsString(final byte[] in) {
    final byte[] res = generateSHA1Fingerprint(in);
    return new String(Hex.encode(res));
  }

  /**
   * Generate SHA256 fingerprint of byte array in string representation.
   *
   * @param in byte array to fingerprint.
   * @return String containing hex format of SHA256 fingerprint.
   */
  public static String getSHA256FingerprintAsString(final byte[] in) {
    final byte[] res = generateSHA256Fingerprint(in);
    return new String(Hex.encode(res));
  }

  /**
   * Generate a SHA1 fingerprint from a byte array containing a certificate.
   *
   * @param ba Byte array containing DER encoded Certificate or CRL.
   * @return Byte array containing SHA1 hash of DER encoded certificate.
   */
  public static byte[] generateSHA1Fingerprint(final byte[] ba) {
    // log.trace(">generateSHA1Fingerprint");
    try {
      final MessageDigest md = MessageDigest.getInstance("SHA1");
      return md.digest(ba);
    } catch (final NoSuchAlgorithmException nsae) {
      LOGGER.error("SHA1 algorithm not supported", nsae);
    }
    // log.trace("<generateSHA1Fingerprint");
    return null;
  } // generateSHA1Fingerprint

  /**
   * Generate a SHA256 fingerprint from a byte array containing a certificate.
   *
   * @param ba Byte array containing DER encoded Certificate or CRL.
   * @return Byte array containing SHA256 hash of DER encoded certificate.
   */
  public static byte[] generateSHA256Fingerprint(final byte[] ba) {
    try {
      final MessageDigest md = MessageDigest.getInstance("SHA-256");
      return md.digest(ba);
    } catch (final NoSuchAlgorithmException nsae) {
      LOGGER.error("SHA-256 algorithm not supported", nsae);
    }
    return null;
  } // generateSHA256Fingerprint

  /**
   * Generate a MD5 fingerprint from a byte array containing a certificate.
   *
   * @param ba Byte array containing DER encoded Certificate.
   * @return Byte array containing MD5 hash of DER encoded certificate (raw
   *     binary hash).
   */
  public static byte[] generateMD5Fingerprint(final byte[] ba) {
    try {
      final MessageDigest md = MessageDigest.getInstance("MD5");
      return md.digest(ba);
    } catch (final NoSuchAlgorithmException nsae) {
      LOGGER.error("MD5 algorithm not supported", nsae);
    }

    return null;
  } // generateMD5Fingerprint

  /**
   * Converts Sun Key usage bits to Bouncy castle key usage kits.
   *
   * @param sku key usage bit fields according to
   *     java.security.cert.X509Certificate#getKeyUsage, must be a boolean aray
   *     of size 9.
   * @return key usage int according to
   *     org.bouncycastle.jce.X509KeyUsage#X509KeyUsage, or -1 if input is null.
   * @see java.security.cert.X509Certificate#getKeyUsage
   * @see org.bouncycastle.jce.X509KeyUsage#X509KeyUsage
   */
  public static int sunKeyUsageToBC(final boolean[] sku) { // NOPMD: complexity
    if (sku == null) {
      return -1;
    }
    int bcku = 0;
    if (sku[0]) {
      bcku = bcku | X509KeyUsage.digitalSignature;
    }
    if (sku[1]) {
      bcku = bcku | X509KeyUsage.nonRepudiation;
    }
    if (sku[2]) {
      bcku = bcku | X509KeyUsage.keyEncipherment;
    }
    if (sku[3]) {
      bcku = bcku | X509KeyUsage.dataEncipherment;
    }
    if (sku[4]) {
      bcku = bcku | X509KeyUsage.keyAgreement;
    }
    if (sku[5]) {
      bcku = bcku | X509KeyUsage.keyCertSign;
    }
    if (sku[6]) {
      bcku = bcku | X509KeyUsage.cRLSign;
    }
    if (sku[7]) {
      bcku = bcku | X509KeyUsage.encipherOnly;
    }
    if (sku[8]) {
      bcku = bcku | X509KeyUsage.decipherOnly;
    }
    return bcku;
  }

  /**
   * Converts DERBitString ResonFlags to a RevokedCertInfo constant.
   *
   * @param reasonFlags DERBITString received from
   *     org.bouncycastle.asn1.x509.ReasonFlags.
   * @return int according to org.cesecore.certificates.crl.RevokedCertInfo
   */
  public static int bitStringToRevokedCertInfo(// NOPMD: complexity
          final DERBitString reasonFlags) {
    int ret = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
    if (reasonFlags == null) {
      return ret;
    }
    final int val = reasonFlags.intValue();
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Int value of bitString revocation reason: " + val);
    }
    if ((val & ReasonFlags.aACompromise) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE;
    }
    if ((val & ReasonFlags.affiliationChanged) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED;
    }
    if ((val & ReasonFlags.cACompromise) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
    }
    if ((val & ReasonFlags.certificateHold) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
    }
    if ((val & ReasonFlags.cessationOfOperation) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION;
    }
    if ((val & ReasonFlags.keyCompromise) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE;
    }
    if ((val & ReasonFlags.privilegeWithdrawn) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN;
    }
    if ((val & ReasonFlags.superseded) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_SUPERSEDED;
    }
    if ((val & ReasonFlags.unused) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
    }
    return ret;
  }

  /**
   * Method used to insert a CN postfix into DN by extracting the first found CN
   * appending cnpostfix and then replacing the original CN with the new one in
   * DN.
   *
   * <p>If no CN could be found in DN then should the given DN be returned
   * untouched
   *
   * @param dn the DN to manipulate, cannot be null
   * @param cnpostfix the postfix to insert, cannot be null
   * @param nameStyle Controls how the name is encoded. Usually it should be a
   *     CeSecoreNameStyle.
   * @return the new DN
   */
  public static String insertCNPostfix(
      final String dn, final String cnpostfix, final X500NameStyle nameStyle) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(">insertCNPostfix: dn=" + dn + ", cnpostfix=" + cnpostfix);
    }
    if (dn == null) {
      return null;
    }
    final RDN[] rdns = IETFUtils.rDNsFromString(dn, nameStyle);
    final X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
    boolean replaced = false;
    for (final RDN rdn : rdns) {
      final AttributeTypeAndValue[] attributeTypeAndValues =
          rdn.getTypesAndValues();
      for (final AttributeTypeAndValue atav : attributeTypeAndValues) {
        if (atav.getType() != null) {
          final String currentSymbol =
              CeSecoreNameStyle.DEFAULT_SYMBOLS.get(atav.getType());
          if (!replaced && "CN".equals(currentSymbol)) {
            nameBuilder.addRDN(
                atav.getType(),
                IETFUtils.valueToString(atav.getValue()) + cnpostfix);
            replaced = true;
          } else {
            nameBuilder.addRDN(atav);
          }
        }
      }
    }
    final String ret = nameBuilder.build().toString();
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace("<reverseDN: " + ret);
    }
    return ret;
  }

  /**
   * Splits a DN into components.
   *
   * @param dn DN
   * @return DN components
   * @see X509NameTokenizer
   */
  public static List<String> getX500NameComponents(final String dn) {
    final List<String> ret = new ArrayList<String>();
    final X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
    while (tokenizer.hasMoreTokens()) {
      ret.add(tokenizer.nextToken());
    }
    return ret;
  }

  /**
   * Returns the parent DN of a DN string, e.g. if the input is
   * "cn=User,dc=example,dc=com" then it would return "dc=example,dc=com".
   * Returns an empty string if there is no parent DN.
   *
   * @param dn DN
   * @return Parent DN
   */
  public static String getParentDN(final String dn) {
    final X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
    tokenizer.nextToken();
    return tokenizer.getRemainingString();
  }

  /**
   * class for breaking up an X500 Name into it's component tokens, ala
   * java.util.StringTokenizer.
   */
  private static class X509NameTokenizer {
      /** Value. */
    private final String value;
    /** Index. */
    private int index;
    /** Sep. */
    private final char separator;
    /** Buffer. */
    private final StringBuffer buf = new StringBuffer();

    /**
     * Creates the object, using the default comma (,) as separator for
     * tokenization.
     *
     * @param oid OID
     */
    X509NameTokenizer(final String oid) {
      this(oid, ',');
    }

    X509NameTokenizer(final String oid, final char aSeparator) {
      this.value = oid;
      this.index = -1;
      this.separator = aSeparator;
    }

    public boolean hasMoreTokens() {
      return index != value.length();
    }

    public String nextToken() {
      if (index == value.length()) {
        return null;
      }

      int end = index + 1;
      boolean quoted = false;
      boolean escaped = false;

      buf.setLength(0);

      while (end != value.length()) {
        final char c = value.charAt(end);

        if (c == '"') {
          if (!escaped) {
            quoted = !quoted;
          } else {
            if (c == '#' && buf.charAt(buf.length() - 1) == '=') {
              buf.append('\\');
            } else if (c == '+' && separator != '+') {
              buf.append('\\');
            }
            buf.append(c);
          }
          escaped = false;
        } else {
          if (escaped || quoted) {
            if (c == '#' && buf.charAt(buf.length() - 1) == '=') {
              buf.append('\\');
            } else if (c == '+' && separator != '+') {
              buf.append('\\');
            }
            buf.append(c);
            escaped = false;
          } else if (c == '\\') {
            escaped = true;
          } else if (c == separator) {
            break;
          } else {
            buf.append(c);
          }
        }
        end++;
      }

      index = end;
      return buf.toString().trim();
    }

    /** @return the remaining (not yet tokenized) part of the DN. */
    protected String getRemainingString() {
      return index + 1 < value.length() ? value.substring(index + 1) : "";
    }
  }

  /**
   * class for breaking up an X500 Name into it's component tokens, ala
   * java.util.StringTokenizer. Taken from BouncyCastle, but does NOT use or
   * consider escaped characters. Used for reversing DNs without unescaping.
   */
  private static class BasicX509NameTokenizer {
      /** OID. */
    private final String oid;
    /** Index. */
    private int index = -1;
    /**
     * Since this class isn't thread safe anyway, we can use the slightly faster
     * StringBuilder instead of StringBuffer.
     */
    private final StringBuilder buf = new StringBuilder();

    BasicX509NameTokenizer(final String anOid) {
      this.oid = anOid;
    }

    public boolean hasMoreTokens() {
      return index != oid.length();
    }

    public String nextToken() {
      if (index == oid.length()) {
        return null;
      }

      int end = index + 1;
      boolean quoted = false;
      boolean escaped = false;

      buf.setLength(0);

      while (end != oid.length()) {
        final char c = oid.charAt(end);

        if (c == '"') {
          if (!escaped) {
            buf.append(c);
            quoted ^= true; // Faster than "quoted = !quoted;"
          } else {
            buf.append(c);
          }
          escaped = false;
        } else {
          if (escaped || quoted) {
            buf.append(c);
            escaped = false;
          } else if (c == '\\') {
            buf.append(c);
            escaped = true;
          } else if (c == ',' && !escaped) {
            break;
          } else {
            buf.append(c);
          }
        }
        end++;
      }

      index = end;
      return buf.toString().trim();
    }
  } // BasicX509NameTokenizer

  /**
   * Obtains a List with the ASN1ObjectIdentifiers for dNObjects names, in the
   * specified order.
   *
   * @param order an array of DN objects.
   * @return a List with ASN1ObjectIdentifiers defining the known order we
   *     require
   * @see org.cesecore.certificates.util.DnComponents#getDnObjects(boolean) for
   *     definition of the contents of the input array
   */
  private static List<ASN1ObjectIdentifier> getX509FieldOrder(
          final String[] order) {
    final List<ASN1ObjectIdentifier> fieldOrder =
        new ArrayList<ASN1ObjectIdentifier>();
    for (final String dNObject : order) {
      fieldOrder.add(DnComponents.getOid(dNObject));
    }
    return fieldOrder;
  }
  /**
   * Obtains a List with the ASN1ObjectIdentifiers for dNObjects names, in the
   * specified pre-defined order.
   *
   * @param ldaporder if true the returned order are as defined in LDAP RFC
   *     (CN=foo,O=bar,C=SE), otherwise the order is a defined in X.500
   *     (C=SE,O=bar,CN=foo).
   * @return a List with ASN1ObjectIdentifiers defining the known order we
   *     require
   * @see org.cesecore.certificates.util.DnComponents#getDnObjects(boolean)
   */
  public static List<ASN1ObjectIdentifier> getX509FieldOrder(
      final boolean ldaporder) {
    return getX509FieldOrder(DnComponents.getDnObjects(ldaporder));
  }

  /**
   * EJBCA accepts extension OIDs on different formats, e.g. "1.2.3.4" and
   * "1.2.3.4.value". Method returns the OID only given any OID string
   *
   * @param oidString to parse
   * @return String containing OID only
   */
  public static String getOidFromString(final String oidString) {
    String retval = oidString;
    // Matches anything but numerical and dots
    final Pattern pattern = Pattern.compile("[^0-9.]");
    final Matcher matcher = pattern.matcher(oidString);
    if (matcher.find()) {
      final int endIndex = matcher.start();
      retval = oidString.substring(0, endIndex - 1);
    }
    return retval;
  }

  /**
   * Returns the regex match pattern given an OID wildcard.
   *
   * @param oidWildcard wildcard. E.g. 1.2.*.3
   * @return regex match pattern
   */
  public static String getOidWildcardPattern(final String oidWildcard) {
    // First escape all '.' which are interpreted as regex wildcards themselves.
    // Secondly, generate the pattern where '*' is the wildcard character
    final String wildcardMatchPattern =
        oidWildcard.replaceAll("\\.", "\\\\.").replaceAll("\\*", "([0-9.]*)");
    return wildcardMatchPattern;
  }

  /**
   * Obtain a X500Name reordered, if some fields from original X500Name doesn't
   * appear in "ordering" parameter, they will be added at end in the original
   * order.
   *
   * @param x500Name the X500Name that is unordered
   * @param ldaporder true if LDAP ordering of DN should be used (default in
   *     EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
   *     order is the reverse
   * @param order specified order, which overrides 'ldaporder', care must be
   *     taken constructing this String array, ignored if null or empty
   * @param applyLdapToCustomOrder specifies if the ldaporder setting should
   *     apply to an order (custom order) if this is not empty
   * @param nameStyle Controls how the name is encoded. Usually it should be a
   *     CeSecoreNameStyle.
   * @return X500Name with ordered conmponents according to the orcering vector
   */
  private static X500Name getOrderedX500Name(
      final X500Name x500Name,
      final boolean ldaporder,
      final String[] order,
      final boolean applyLdapToCustomOrder,
      final X500NameStyle nameStyle) {
    // -- New order for the X509 Fields
    final List<ASN1ObjectIdentifier> newOrdering =
        new ArrayList<ASN1ObjectIdentifier>();
    final List<ASN1Encodable> newValues = new ArrayList<ASN1Encodable>();
    // -- Add ordered fields
    final ASN1ObjectIdentifier[] allOids = x500Name.getAttributeTypes();

    // Guess order of the input name
    final boolean isLdapOrder = !isDNReversed(x500Name.toString());
    // If we think the DN is in LDAP order, first order it as a LDAP DN, if we
    // don't think it's LDAP order
    // order it as a X.500 DN. If we haven't specified our own ordering
    final List<ASN1ObjectIdentifier> ordering;
    final boolean useCustomOrder = order != null && order.length > 0;
    if (useCustomOrder) {
      LOGGER.debug("Using custom DN order");
      ordering = getX509FieldOrder(order);
    } else {
      ordering = getX509FieldOrder(isLdapOrder);
    }

    final HashSet<ASN1ObjectIdentifier> hs =
        new HashSet<ASN1ObjectIdentifier>(allOids.length + ordering.size());
    for (final ASN1ObjectIdentifier oid : ordering) {
      if (!hs.contains(oid)) {
        hs.add(oid);
        final RDN[] valueList = x500Name.getRDNs(oid);
        // -- Only add the OID if has not null value
        for (final RDN value : valueList) {
          newOrdering.add(oid);
          newValues.add(value.getFirst().getValue());
        }
      }
    }
    // -- Add unexpected fields to the end
    for (final ASN1ObjectIdentifier oid : allOids) {
      if (!hs.contains(oid)) {
        hs.add(oid);
        final RDN[] valueList = x500Name.getRDNs(oid);
        // -- Only add the OID if has not null value
        for (final RDN value : valueList) {
          newOrdering.add(oid);
          newValues.add(value.getFirst().getValue());
          if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("added --> " + oid + " val: " + value);
          }
        }
      }
    }
    // If the requested ordering was the reverse of the ordering the input
    // string was in (by our guess in the beginning)
    // we have to reverse the vectors.
    // Unless we have specified a custom order, and choose to not apply LDAP
    // Order to this custom order, in which case we will not change the order
    // from the custom
    reverseLDAP(ldaporder, applyLdapToCustomOrder, newOrdering,
            newValues, isLdapOrder, useCustomOrder);


    final X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
    for (int i = 0; i < newOrdering.size(); i++) {
      nameBuilder.addRDN(newOrdering.get(i), newValues.get(i));
    }
    // -- Return X500Name with the ordered fields
    return nameBuilder.build();
  } //

/**
 * @param ldaporder ldap
 * @param applyLdapToCustomOrder bool
 * @param newOrdering ids
 * @param newValues encodable
 * @param isLdapOrder bool
 * @param useCustomOrder bool
 */
private static void reverseLDAP(final boolean ldaporder,
        final boolean applyLdapToCustomOrder,
        final List<ASN1ObjectIdentifier> newOrdering,
        final List<ASN1Encodable> newValues, final boolean isLdapOrder,
        final boolean useCustomOrder) {
    if ((useCustomOrder && applyLdapToCustomOrder || !useCustomOrder)
      && ldaporder != isLdapOrder) {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(
              "Reversing order of DN, ldaporder="
                  + ldaporder
                  + ", isLdapOrder="
                  + isLdapOrder);
        }
        Collections.reverse(newOrdering);
        Collections.reverse(newValues);
      }
}

  /**
   * Obtain the directory string for the directoryName generation form the
   * Subject Alternative Name String.
   *
   * @param altName name
   * @return directory
   */
  private static String getDirectoryStringFromAltName(final String altName) {
    final String directoryName =
        CertTools.getPartFromDN(altName, CertTools.DIRECTORYNAME);
    // DNFieldExtractor dnfe = new DNFieldExtractor(altName,
    // DNFieldExtractor.TYPE_SUBJECTALTNAME);
    // String directoryName = dnfe.getField(DNFieldExtractor.DIRECTORYNAME, 0);
    /* TODO: Validate or restrict the directoryName Fields? */
    return "".equals(directoryName) ? null : directoryName;
  } // getDirectoryStringFromAltName

  /**
   * Method to create certificate path and to check it's validity from a list of
   * certificates. The list of certificates should only contain one root
   * certificate. The created certificate chain is checked to be valid at the
   * current date and time.
   *
   * @param certlistin List of certificates to create certificate chain from.
   * @return the certificatepath with the root CA at the end
   * @throws CertPathValidatorException if the certificate chain can not be
   *     constructed or validated
   * @throws InvalidAlgorithmParameterException If params are invalid
   * @throws NoSuchProviderException If provider not found
   * @throws NoSuchAlgorithmException If algorithm not found
   * @throws CertificateException If certificate cannot be parsed
   */
  public static List<Certificate> createCertChain(
          final Collection<?> certlistin)
      throws CertPathValidatorException, InvalidAlgorithmParameterException,
          NoSuchAlgorithmException, NoSuchProviderException,
          CertificateException {
    return createCertChain(certlistin, new Date());
  }

  /**
   * Method to create certificate path and to check it's validity from a list of
   * certificates. The list of certificates should only contain one root
   * certificate.
   *
   * @param certlistin List of certificates (X.509, CVC, or other supported) to
   *     create certificate chain from.
   * @param now Date to use when checking if the CAs chain is valid.
   * @return the certificate path with the root CA at the end
   * @throws CertPathValidatorException if the certificate chain can not be
   *     constructed
   * @throws InvalidAlgorithmParameterException If params are invalid
   * @throws NoSuchProviderException If provider not found
   * @throws NoSuchAlgorithmException If algorithm not found
   * @throws CertificateException If certificate cannot be parsed
   */
  public static List<Certificate> createCertChain(
      final Collection<?> certlistin, final Date now)
      throws CertPathValidatorException, InvalidAlgorithmParameterException,
          NoSuchAlgorithmException, NoSuchProviderException,
          CertificateException {
    final List<Certificate> returnval = new ArrayList<Certificate>();

    final Collection<Certificate> certlist = orderCertificateChain(certlistin);
    // Verify that the chain contains a Root CA certificate
    Certificate rootca = null;
    for (final Certificate crt : certlist) {
      if (CertTools.isSelfSigned(crt)) {
        rootca = crt;
      }
    }
    if (rootca == null) {
      throw new CertPathValidatorException(
          "No root CA certificate found in certificate list");
    }

    // set certificate chain
    Certificate rootcert = null;
    final ArrayList<Certificate> calist = new ArrayList<Certificate>();
    for (final Certificate next : certlist) {
      if (CertTools.isSelfSigned(next)) {
        rootcert = next;
      } else {
        calist.add(next);
      }
    }

    if (calist.isEmpty()) {
      // only one root cert, no certchain
      returnval.add(rootcert);
    } else {
      // We need a bit special handling for CV certificates because those can
      // not be handled using a PKIX CertPathValidator
      final Certificate test = calist.get(0);
      if (test.getType().equals("CVC")) {
        if (calist.size() == 1) {
          returnval.add(test);
          returnval.add(rootcert);
        } else {
          throw new CertPathValidatorException(
              "CVC certificate chain can not be of length longer than two.");
        }
      } else {
        // Normal X509 certificates
        final HashSet<TrustAnchor> trustancors = new HashSet<TrustAnchor>();
        TrustAnchor trustanchor = null;
        trustanchor = new TrustAnchor((X509Certificate) rootcert, null);
        trustancors.add(trustanchor);

        // Create the parameters for the validator
        final PKIXParameters params = new PKIXParameters(trustancors);

        // Disable CRL checking since we are not supplying any CRLs
        params.setRevocationEnabled(false);
        params.setDate(now);

        // Create the validator and validate the path
        final CertPathValidator certPathValidator =
            CertPathValidator.getInstance(
                CertPathValidator.getDefaultType(), "BC");
        final CertificateFactory fact = CertTools.getCertificateFactory();
        final CertPath certpath = fact.generateCertPath(calist);

        final CertPathValidatorResult result =
            certPathValidator.validate(certpath, params);

        // Get the certificates validate in the path
        final PKIXCertPathValidatorResult pkixResult =
            (PKIXCertPathValidatorResult) result;
        returnval.addAll(certpath.getCertificates());

        // Get the CA used to validate this path
        final TrustAnchor ta = pkixResult.getTrustAnchor();
        final X509Certificate cert = ta.getTrustedCert();
        returnval.add(cert);
      }
    }
    return returnval;
  } // createCertChain

  /**
   * Method ordering a list of certificate (X.509, CVC, or other supported type)
   * into a certificate path with the root CA at the end. Does not check
   * validity or verification of any kind, just ordering by issuerdn.
   *
   * @param certlist list of certificates to order can be collection of
   *     Certificate or byte[] (der encoded certs), must contain a full chain.
   * @return List with certificatechain, Root CA last.
   * @throws CertPathValidatorException if validation fails
   */
  private static List<Certificate> orderCertificateChain(
          final Collection<?> certlist)
      throws CertPathValidatorException {
    final ArrayList<Certificate> returnval = new ArrayList<Certificate>();
    Certificate rootca = null;
    final HashMap<String, Certificate> cacertmap
        = new HashMap<String, Certificate>();
    for (final Object possibleCertificate : certlist) {
      Certificate cert = getCertFromPossible(possibleCertificate);
      if (CertTools.isSelfSigned(cert)) {
        rootca = cert;
      } else {
        LOGGER.debug(
            "Adding to cacertmap with index '"
                + CertTools.getIssuerDN(cert)
                + "'");
        cacertmap.put(CertTools.getIssuerDN(cert), cert);
      }
    }

    if (rootca == null) {
      throw new CertPathValidatorException(
          "No root CA certificate found in certificatelist");
    }
    returnval.add(0, rootca);
    Certificate currentcert = rootca;
    int i = 0;
    while (certlist.size() != returnval.size() && i <= certlist.size()) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Looking in cacertmap for '"
                + CertTools.getSubjectDN(currentcert)
                + "'");
      }
      final Certificate nextcert = cacertmap.get(
              CertTools.getSubjectDN(currentcert));
      if (nextcert == null) {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Dumping keys of CA certificate map:");
          for (final String issuerDn : cacertmap.keySet()) {
            LOGGER.debug(issuerDn);
          }
        }
        throw new CertPathValidatorException(
            "Error building certificate path. Could find certificate with"
                + " SubjectDN "
                + CertTools.getSubjectDN(currentcert)
                + " in certificate map. See debug log for details.");
      }
      returnval.add(0, nextcert);
      currentcert = nextcert;
      i++;
    }

    if (i > certlist.size()) {
      throw new CertPathValidatorException("Error building certificate path");
    }

    return returnval;
  } // orderCertificateChain

/**
 * @param possibleCertificate Cert
 * @return Cert
 * @throws CertPathValidatorException Fail
 */
private static Certificate getCertFromPossible(
        final Object possibleCertificate) throws CertPathValidatorException {
    Certificate cert = null;
      try {
        cert = (Certificate) possibleCertificate;
      } catch (final ClassCastException e) {
        // This was not a certificate, is it byte encoded?
        final byte[] certBytes = (byte[]) possibleCertificate;
        try {
          cert = CertTools.getCertfromByteArray(certBytes);
        } catch (final CertificateParsingException e1) {
          throw new CertPathValidatorException(e1);
        }
      }
    return cert;
}

  /**
   * Method ordering a list of X509 certificate into a certificate path with the
   * root CA, or topmost Sub CA at the end. Does not check validity or
   * verification of any kind, just ordering by issuerdn/keyId. This is mostly a
   * wrapper around CertPath.generateCertPath, but we do regression test this
   * ordering.
   *
   * @param certlist list of certificates to order can be collection of
   *     Certificate or byte[] (der encoded certs).
   * @return List with certificate chain with leaf certificate first, and root
   *     CA, or last sub CA, in the end, does not have to contain a Root CA is
   *     input does not.
   * @throws CertPathValidatorException if validation fails
   */
  @SuppressWarnings("unchecked")
  public static List<X509Certificate> orderX509CertificateChain(
      final List<X509Certificate> certlist) throws CertPathValidatorException {
    CertPath cp;
    try {
      cp =
          CertificateFactory.getInstance(
                  "X.509", BouncyCastleProvider.PROVIDER_NAME)
              .generateCertPath(certlist);
    } catch (final CertificateException e) {
      // Wasn't a certificate after all?
      throw new CertPathValidatorException(e);
    } catch (final NoSuchProviderException e) {
      // This is really bad
      throw new IllegalStateException(
          "BouncyCastle was not found as a provider.", e);
    }
    return (List<X509Certificate>) cp.getCertificates();
  } // orderX509CertificateChain

  /**
   * @param chainA first chain
   * @param chainB second chain
   * @return true if the chains are nonempty, contain the same certificates in
   *     the same order
   */
  public static boolean compareCertificateChains(
      final Certificate[] chainA, final Certificate[] chainB) {
    if (chainA == null || chainB == null) {
      return false;
    }
    if (chainA.length != chainB.length) {
      return false;
    }
    for (int i = 0; i < chainA.length; i++) {
      if (chainA[i] == null || !chainA[i].equals(chainB[i])) {
        return false;
      }
    }
    return true;
  }

  /**
   * Dumps a certificate (cvc or x.509) to string format, suitable for manual
   * inspection/debugging.
   *
   * @param cert Certificate
   * @return String with cvc or asn.1 dump.
   */
  public static String dumpCertificateAsString(final Certificate cert) {
    String ret = null;
    if (cert instanceof X509Certificate) {
      try {
        final Certificate c = getCertfromByteArray(cert.getEncoded());
        ret = c.toString();
        // ASN1InputStream ais = new ASN1InputStream(new
        // ByteArrayInputStream(cert.getEncoded()));
        // ASN1Primitive obj = ais.readObject();
        // ret = ASN1Dump.dumpAsString(obj);
      } catch (final CertificateException e) {
        ret = e.getMessage();
      }
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      final CardVerifiableCertificate cvccert =
          (CardVerifiableCertificate) cert;
      final CVCObject obj = cvccert.getCVCertificate();
      ret = obj.getAsText("");
    } else {
      throw new IllegalArgumentException(
          "dumpCertificateAsString: Certificate of type "
              + cert.getType()
              + " is not implemented");
    }
    return ret;
  }

  /**
   * Creates PKCS10CertificateRequest object from PEM encoded certificate
   * request.
   *
   * @param pemEncodedCsr PEM encoded CSR
   * @return PKCS10CertificateRequest object
   */
  public static PKCS10CertificationRequest getCertificateRequestFromPem(
      final String pemEncodedCsr) {
    if (pemEncodedCsr == null) {
      return null;
    }
    PKCS10CertificationRequest csr = null;
    final ByteArrayInputStream pemStream =
        new ByteArrayInputStream(
            pemEncodedCsr.getBytes(StandardCharsets.UTF_8));
    try (PEMParser pemParser =
        new PEMParser(new BufferedReader(new InputStreamReader(pemStream))); ) {
      final Object parsedObj = pemParser.readObject();
      if (parsedObj instanceof PKCS10CertificationRequest) {
        csr = (PKCS10CertificationRequest) parsedObj;
      }
    } catch (IOException
        | DecoderException
            e) { // IOException that will be wrapped as (runtime)
                 // DecoderException
      LOGGER.info(
          "IOException while decoding certificate request from PEM: "
              + e.getMessage());
      LOGGER.debug("IOException while decoding certificate request from PEM.",
              e);
    }
    return csr;
  }

  /**
   * Generates a PKCS10CertificationRequest.
   *
   * <p>Code Example: ------------- An example of putting AltName and a password
   * challenge in an 'attributes' set (taken from
   * RequestMessageTest.test01Pkcs10RequestMessage() ):
   *
   * <p>{@code // Create a P10 with extensions, in this case altNames with a DNS
   * name ASN1EncodableVector altnameattr = new ASN1EncodableVector();
   * altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest); //
   * AltNames GeneralNames san =
   * CertTools.getGeneralNamesFromAltName("dNSName=foo1.bar.com");
   * ExtensionsGenerator extgen = new ExtensionsGenerator();
   * extgen.addExtension(Extension.subjectAlternativeName, false, san );
   * Extensions exts = extgen.generate(); altnameattr.add(new DERSet(exts));
   *
   * <p>// Add a challenge password as well ASN1EncodableVector pwdattr = new
   * ASN1EncodableVector();
   * pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
   * ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
   * pwdvalues.add(new DERUTF8String("foo123")); pwdattr.add(new
   * DERSet(pwdvalues));
   *
   * <p>// Complete the Attribute section of the request, the set (Attributes)
   * // contains one sequence (Attribute) ASN1EncodableVector v = new
   * ASN1EncodableVector(); v.add(new DERSequence(altnameattr)); v.add(new
   * DERSequence(pwdattr)); DERSet attributes = new DERSet(v); }
   *
   * @param signatureAlgorithm the signature algorithm to sign the CSR.
   * @param subject the request's subject DN.
   * @param publickey the public key of the CSR.
   * @param attributes a set of attributes, for example, extensions, challenge
   *     password, etc.
   * @param privateKey the private key used to sign the CSR.
   * @param oprovider the JCA/JCE provider to use.
   * @return a PKCS10CertificateRequest based on the input parameters.
   * @throws OperatorCreationException if an error occurred while creating the
   *     signing key
   */
  // Should sign with. other private as well!
  public static PKCS10CertificationRequest genPKCS10CertificationRequest(
      final String signatureAlgorithm,
      final X500Name subject,
      final PublicKey publickey,
      final ASN1Set attributes,
      final PrivateKey privateKey,
      final String oprovider)
      throws OperatorCreationException {

    ContentSigner signer;
    CertificationRequestInfo reqInfo;
    try {
      final SubjectPublicKeyInfo pkinfo =
          SubjectPublicKeyInfo.getInstance(publickey.getEncoded());
      reqInfo = new CertificationRequestInfo(subject, pkinfo, attributes);

      String provider;
      if (oprovider == null) {
        provider = BouncyCastleProvider.PROVIDER_NAME;
      } else {
          provider = oprovider;
      }
      final int bufferSize = 20480;
      signer =
          new BufferingContentSigner(
              new JcaContentSignerBuilder(signatureAlgorithm)
                  .setProvider(provider)
                  .build(privateKey),
              bufferSize);
      signer.getOutputStream().write(reqInfo.getEncoded(ASN1Encoding.DER));
      signer.getOutputStream().flush();
    } catch (final IOException e) {
      throw new IllegalStateException("Unexpected IOException was caught.", e);
    }
    final byte[] sig = signer.getSignature();
    final DERBitString sigBits = new DERBitString(sig);

    final CertificationRequest req =
        new CertificationRequest(
            reqInfo, signer.getAlgorithmIdentifier(), sigBits);
    return new PKCS10CertificationRequest(req);
  }

  /**
   * Create a "certs-only" PKCS#7 / CMS from the provided chain.
   *
   * @param x509CertificateChain chain of certificates with the leaf in the
   *     first position and root in the last or just a leaf certificate.
   * @return a byte array containing the CMS
   * @throws CertificateEncodingException if the provided list of certificates
   *     could not be parsed correctly
   * @throws CMSException if there was a problem creating the certs-only CMS
   *     message
   */
  public static byte[] createCertsOnlyCMS(
      final List<X509Certificate> x509CertificateChain)
      throws CertificateEncodingException, CMSException {
    if (LOGGER.isDebugEnabled()) {
      final String subjectdn =
          x509CertificateChain != null && x509CertificateChain.size() > 0
              ? x509CertificateChain.get(0).getSubjectDN().toString()
              : "null";
      LOGGER.debug("Creating a certs-only CMS for " + subjectdn);
    }
    final List<JcaX509CertificateHolder> certList =
        CertTools.convertToX509CertificateHolder(x509CertificateChain);
    final CMSSignedDataGenerator cmsSignedDataGenerator =
        new CMSSignedDataGenerator();
    cmsSignedDataGenerator.addCertificates(
        new CollectionStore<JcaX509CertificateHolder>(certList));
    final CMSSignedData cmsSignedData =
        cmsSignedDataGenerator.generate(new CMSAbsentContent(), true);
    try {
      return cmsSignedData.getEncoded();
    } catch (final IOException e) {
      throw new CMSException(e.getMessage());
    }
  }

  /**
   * Generated Generates a ContentVerifierProvider.
   *
   * @param pubkey Key
   * @return a JcaContentVerifierProvider. Useful for verifying the signiture in
   *     a PKCS10CertificationRequest
   * @throws OperatorCreationException On fail
   */
  public static ContentVerifierProvider genContentVerifierProvider(
      final PublicKey pubkey) throws OperatorCreationException {
    return new JcaContentVerifierProviderBuilder()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(pubkey);
  }

  /**
   * @param chain cert chain
   * @return a Certificate Collection as a X509Certificate list
   * @throws ClassCastException if one of the Certificates in the collection is
   *     not an X509Certificate
   */
  public static final List<X509Certificate> convertCertificateChainToX509Chain(
      final Collection<Certificate> chain) throws ClassCastException {
    final List<X509Certificate> ret = new ArrayList<>();
    for (final Certificate certificate : chain) {
      ret.add((X509Certificate) certificate);
    }
    return ret;
  }

  /**
   * @param chain cert chain
   * @return a X509Certificate Collection as a Certificate list
   */
  public static final List<Certificate> convertCertificateChainToGenericChain(
      final Collection<X509Certificate> chain) {
    final List<Certificate> ret = new ArrayList<>();
    for (final Certificate certificate : chain) {
      ret.add(certificate);
    }
    return ret;
  }

  /**
   * Converts a X509Certificate chain into a JcaX509CertificateHolder chain.
   *
   * @param certificateChain input chain to be converted
   * @return the result
   * @throws CertificateEncodingException if there is a problem extracting the
   *     certificate information.
   */
  public static final JcaX509CertificateHolder[] convertToX509CertificateHolder(
      final X509Certificate[] certificateChain)
              throws CertificateEncodingException {
    final JcaX509CertificateHolder[] certificateHolderChain =
        new JcaX509CertificateHolder[certificateChain.length];
    for (int i = 0; i < certificateChain.length; ++i) {
      certificateHolderChain[i] =
          new JcaX509CertificateHolder(certificateChain[i]);
    }
    return certificateHolderChain;
  }

  /**
   * Converts a X509Certificate chain into a JcaX509CertificateHolder chain.
   *
   * @param certificateChain input chain to be converted
   * @return the result
   * @throws CertificateEncodingException if there is a problem extracting the
   *     certificate information.
   */
  public static final List<JcaX509CertificateHolder>
      convertToX509CertificateHolder(
              final List<X509Certificate> certificateChain)
          throws CertificateEncodingException {
    final List<JcaX509CertificateHolder> certificateHolderChain =
        new ArrayList<JcaX509CertificateHolder>();
    for (final X509Certificate certificate : certificateChain) {
      certificateHolderChain.add(new JcaX509CertificateHolder(certificate));
    }
    return certificateHolderChain;
  }

  /**
   * Converts a X509CertificateHolder chain into a X509Certificate chain.
   *
   * @param certificateHolderChain input chain to be converted
   * @return the result
   * @throws CertificateException if there is a problem extracting the
   *     certificate information.
   */
  public static final List<X509Certificate> convertToX509CertificateList(
      final Collection<X509CertificateHolder> certificateHolderChain)
      throws CertificateException {
    final List<X509Certificate> ret = new ArrayList<X509Certificate>();
    final JcaX509CertificateConverter jcaX509CertificateConverter =
        new JcaX509CertificateConverter();
    for (final X509CertificateHolder certificateHolder
        : certificateHolderChain) {
      ret.add(jcaX509CertificateConverter.getCertificate(certificateHolder));
    }
    return ret;
  }

  /**
   * Converts a X509CertificateHolder chain into a X509Certificate chain.
   *
   * @param certificateHolderChain input chain to be converted
   * @return the result
   * @throws CertificateException if there is a problem extracting the
   *     certificate information.
   */
  public static final X509Certificate[] convertToX509CertificateArray(
      final Collection<X509CertificateHolder> certificateHolderChain)
      throws CertificateException {
    return convertToX509CertificateList(certificateHolderChain)
        .toArray(new X509Certificate[0]);
  }

  /**
   * Converts a X509CertificateHolder chain into a X509Certificate chain.
   *
   * @param crlHolders input chain to be converted
   * @return the result
   * @throws CRLException if there is a problem extracting the CRL information.
   */
  public static final List<X509CRL> convertToX509CRLList(
      final Collection<X509CRLHolder> crlHolders) throws CRLException {
    final List<X509CRL> ret = new ArrayList<X509CRL>();
    final JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
    for (final X509CRLHolder crlHolder : crlHolders) {
      ret.add(jcaX509CRLConverter.getCRL(crlHolder));
    }
    return ret;
  }

  /**
   * Checks that the given SubjectDN / SAN satisfies the Name Constraints of the
   * given issuer (if there are any). This method checks the Name Constraints in
   * the given issuer only. A complete implementation of name constraints should
   * check the whole certificate chain.
   *
   * @param issuer Issuing CA.
   * @param subjectDNName Subject DN to check. Optional.
   * @param subjectAltName Subject Alternative Name to check. Optional.
   * @throws IllegalNameException if the name(s) didn't pass naming constraints
   */
  public static void checkNameConstraints(
      final X509Certificate issuer,
      final X500Name subjectDNName,
      final GeneralNames subjectAltName)
      throws IllegalNameException {
    final byte[] ncbytes =
        issuer.getExtensionValue(Extension.nameConstraints.getId());
    final ASN1OctetString ncstr =
        ncbytes != null ? DEROctetString.getInstance(ncbytes) : null;
    final ASN1Sequence ncseq =
        ncbytes != null ? DERSequence.getInstance(ncstr.getOctets()) : null;
    final NameConstraints nc =
        ncseq != null ? NameConstraints.getInstance(ncseq) : null;

    if (nc != null) {
      if (subjectDNName != null) {
        // Skip check for root CAs
        final X500Name issuerDNName =
            X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        if (issuerDNName.equals(subjectDNName)) {
          return;
        }
      }

      final PKIXNameConstraintValidator validator =
          new PKIXNameConstraintValidator();

      final GeneralSubtree[] permitted = nc.getPermittedSubtrees();
      final GeneralSubtree[] excluded = nc.getExcludedSubtrees();

      if (permitted != null) {
        validator.intersectPermittedSubtree(permitted);
      }
      if (excluded != null) {
        for (final GeneralSubtree subtree : excluded) {
          validator.addExcludedSubtree(subtree);
        }
      }

      validateSubjectDNName(subjectDNName, validator);

      validateSubjectAltName(subjectAltName, validator);
    }
  }

/**
 * @param subjectDNName DN
 * @param validator Validator
 * @throws IllegalNameException Fail
 */
private static void validateSubjectDNName(final X500Name subjectDNName,
        final PKIXNameConstraintValidator validator)
        throws IllegalNameException {
    if (subjectDNName != null) {
        final GeneralName dngn = new GeneralName(subjectDNName);
        try {
          validator.checkPermitted(dngn);
          validator.checkExcluded(dngn);
        } catch (final PKIXNameConstraintValidatorException e) {
          final String dnStr = subjectDNName.toString();
          final boolean isLdapOrder =
              dnHasMultipleComponents(dnStr) && !isDNReversed(dnStr);
          if (isLdapOrder) {
            final String msg =
                INTRES.getLocalizedMessage(
                    "nameconstraints.x500dnorderrequired");
            throw new IllegalNameException(msg);
          } else {
            final String msg =
                INTRES.getLocalizedMessage(
                    "nameconstraints.forbiddensubjectdn", subjectDNName);
            throw new IllegalNameException(msg, e);
          }
        }
      }
}

/**
 * @param subjectAltName AltName
 * @param validator Validator
 * @throws IllegalNameException Fail
 */
private static void validateSubjectAltName(final GeneralNames subjectAltName,
        final PKIXNameConstraintValidator validator)
                throws IllegalNameException {
    if (subjectAltName != null) {
        for (final GeneralName sangn : subjectAltName.getNames()) {
          try {
            validator.checkPermitted(sangn);
            validator.checkExcluded(sangn);
          } catch (final PKIXNameConstraintValidatorException e) {
            final String msg =
                INTRES.getLocalizedMessage(
                    "nameconstraints.forbiddensubjectaltname", sangn);
            throw new IllegalNameException(msg, e);
          }
        }
      }
}

  /**
   * Creates a public key fingerprint with the given digest algorithm.
   *
   * @param publicKey the public key.
   * @param algorithm the digest algorithm (i.e. MD-5, SHA-1, SHA-256, etc.)
   * @return the public key fingerprint or null.
   */
  public static final String createPublicKeyFingerprint(
      final PublicKey publicKey, final String algorithm) {
    try {
      final MessageDigest digest = MessageDigest.getInstance(algorithm);
      digest.reset();
      digest.update(publicKey.getEncoded());
      final String result = Hex.toHexString(digest.digest());
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Fingerprint "
                + result
                + " created for public key: "
                + new String(Base64Util.encode(publicKey.getEncoded())));
      }
      return result;
    } catch (final NoSuchAlgorithmException e) {
      LOGGER.warn("Could not create fingerprint for public key ", e);
      return null;
    }
  }
}
