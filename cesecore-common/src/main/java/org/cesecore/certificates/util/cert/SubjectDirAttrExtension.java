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
package org.cesecore.certificates.util.cert;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.cesecore.util.CertTools;

/**
 * A class for reading values from SubjectDirectoryAttributes extension.
 *
 * @version $Id: SubjectDirAttrExtension.java 25905 2017-05-27 00:53:42Z jeklund
 *     $
 */
public final class SubjectDirAttrExtension extends CertTools {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(SubjectDirAttrExtension.class);

  /** inhibits creation of new SubjectDirAttrExtension. */
  private SubjectDirAttrExtension() { }

  /**
   * SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute.
   *
   * <p>Attribute ::= SEQUENCE { type AttributeType, values SET OF
   * AttributeValue } -- at least one value is required
   *
   * <p>AttributeType ::= OBJECT IDENTIFIER AttributeValue ::= ANY
   *
   * <p>SubjectDirectoryAttributes is of form dateOfBirth=&lt;19590927&gt;,
   * placeOfBirth=&lt;string&gt;, gender=&lt;M/F&gt;,
   * countryOfCitizenship=&lt;two letter ISO3166&gt;, countryOfResidence=&lt;two
   * letter ISO3166&gt;
   *
   * <p>Supported subjectDirectoryAttributes are the ones above
   *
   * @param certificate containing subject directory attributes
   * @return String containing directoryAttributes of form the form specified
   *     above or null if no directoryAttributes exist. Values in returned
   *     String is from CertTools constants. DirectoryAttributes not supported
   *     are simply not shown in the resulting string.
   * @throws java.text.ParseException when id_pda_dateOfBirth is malformed
   */
  public static String getSubjectDirectoryAttributes(
          final Certificate certificate)
      throws ParseException {
    LOG.debug("Search for SubjectDirectoryAttributes");
    String result = "";
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      ASN1Primitive obj =
          CertTools.getExtensionValue(
              x509cert, Extension.subjectDirectoryAttributes.getId());
      if (obj == null) {
        return null;
      }
      ASN1Sequence seq = (ASN1Sequence) obj;

      String prefix = "";
      SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMdd");
      for (int i = 0; i < seq.size(); i++) {
        Attribute attr = Attribute.getInstance(seq.getObjectAt(i));
        if (!StringUtils.isEmpty(result)) {
          prefix = ", ";
        }
        result = handleDOB(result, prefix, dateF, attr);
        if (attr.getAttrType().getId().equals(ID_PDA_PLACE_OF_BIRTH)) {
          ASN1Set set = attr.getAttrValues();
          // same here only one placeOfBirth
          String pb = ((ASN1String) set.getObjectAt(0)).getString();
          result += prefix + "placeOfBirth=" + pb;
        }
        if (attr.getAttrType().getId().equals(ID_PDA_GENDER)) {
          ASN1Set set = attr.getAttrValues();
          // same here only one gender
          String g = ((ASN1String) set.getObjectAt(0)).getString();
          result += prefix + "gender=" + g;
        }
        if (attr.getAttrType().getId().equals(ID_PDA_COUNTRY_OF_CITIZENSHIP)) {
          ASN1Set set = attr.getAttrValues();
          // same here only one citizenship
          String g = ((ASN1String) set.getObjectAt(0)).getString();
          result += prefix + "countryOfCitizenship=" + g;
        }
        if (attr.getAttrType().getId().equals(ID_PDA_COUNTRY_OF_RESIDENCE)) {
          ASN1Set set = attr.getAttrValues();
          // same here only one residence
          String g = ((ASN1String) set.getObjectAt(0)).getString();
          result += prefix + "countryOfResidence=" + g;
        }
      }
    }
    if (StringUtils.isEmpty(result)) {
      return null;
    }
    return result;
  }

/**
 * @param r res
 * @param prefix pre
 * @param dateF form
 * @param attr attr
 * @return result
 * @throws ParseException fail
 */
private static String handleDOB(final String r,
        final String prefix, final SimpleDateFormat dateF,
        final Attribute attr)
        throws ParseException {
    String result = r;
    if (attr.getAttrType().getId().equals(ID_PDA_DATE_OF_BIRTH)) {
      ASN1Set set = attr.getAttrValues();
      // Come on, we'll only allow one dateOfBirth, we're not allowing such
      // frauds with multiple birth dates
      ASN1GeneralizedTime time =
          ASN1GeneralizedTime.getInstance(set.getObjectAt(0));
      Date date = time.getDate();
      String dateStr = dateF.format(date);
      result += prefix + "dateOfBirth=" + dateStr;
    }
    return result;
}

  /**
   * From subjectDirAttributes string as defined in getSubjectDirAttribute.
   *
   * @param dirAttr string of SubjectDirectoryAttributes
   * @return A Collection of ASN.1 Attribute (org.bouncycastle.asn1.x509), or an
   *     empty Collection, never null
   * @see #getSubjectDirectoryAttributes(Certificate)
   */
  public static Collection<Attribute> getSubjectDirectoryAttributes(
       final String dirAttr) {
    ArrayList<Attribute> ret = new ArrayList<Attribute>();
    Attribute attr = null;
    String value = CertTools.getPartFromDN(dirAttr, "countryOfResidence");
    if (!StringUtils.isEmpty(value)) {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new DERPrintableString(value));
      attr =
          new Attribute(
              new ASN1ObjectIdentifier(ID_PDA_COUNTRY_OF_RESIDENCE),
              new DERSet(vec));
      ret.add(attr);
    }
    value = CertTools.getPartFromDN(dirAttr, "countryOfCitizenship");
    if (!StringUtils.isEmpty(value)) {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new DERPrintableString(value));
      attr =
          new Attribute(
              new ASN1ObjectIdentifier(ID_PDA_COUNTRY_OF_CITIZENSHIP),
              new DERSet(vec));
      ret.add(attr);
    }
    value = CertTools.getPartFromDN(dirAttr, "gender");
    if (!StringUtils.isEmpty(value)) {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new DERPrintableString(value));
      attr =
          new Attribute(
              new ASN1ObjectIdentifier(ID_PDA_GENDER), new DERSet(vec));
      ret.add(attr);
    }
    value = CertTools.getPartFromDN(dirAttr, "placeOfBirth");
    if (!StringUtils.isEmpty(value)) {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      X509DefaultEntryConverter conv = new X509DefaultEntryConverter();
      ASN1Primitive obj =
          conv.getConvertedValue(
              new ASN1ObjectIdentifier(ID_PDA_PLACE_OF_BIRTH), value);
      vec.add(obj);
      attr =
          new Attribute(
              new ASN1ObjectIdentifier(ID_PDA_PLACE_OF_BIRTH), new DERSet(vec));
      ret.add(attr);
    }
    // dateOfBirth that is a GeneralizedTime
    // The correct format for this is YYYYMMDD, it will be padded to
    // YYYYMMDD120000Z
    value = CertTools.getPartFromDN(dirAttr, "dateOfBirth");
    if (!StringUtils.isEmpty(value)) {
      if (value.length() == 8) {
        value += "120000Z"; // standard format according to rfc3739
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new DERGeneralizedTime(value));
        attr =
            new Attribute(
                new ASN1ObjectIdentifier(ID_PDA_DATE_OF_BIRTH),
                new DERSet(vec));
        ret.add(attr);
      } else {
        LOG.error(
            "Wrong length of data for 'dateOfBirth', should be of format"
                + " YYYYMMDD, skipping...");
      }
    }
    return ret;
  }
}
