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
package org.cesecore.certificates.certificate.certextensions;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.InternalResources;

/**
 * The default basic certificate extension that has two property.
 *
 * <p>'value' : The value returned 'encoding' : How the value is encoded.
 *
 * <p>Optionally, a new property can be defined:
 *
 * <p>'nvalues' : number of values of type 'encoding'
 *
 * <p>Thus, the extension will be of type 'SEQUENCE OF ENCODING' with a size of
 * nvalues. The members will be: 'value1', 'value2' and so on.
 *
 * <p>Optionally, an other property can be defined:
 *
 * <p>'dynamic' : true/false if the extension value(s) should be allowed to be
 * overridden by value(s) put as extensiondata in ExtendedInformation. Default
 * is 'false'.
 *
 * <p>See documentation for more information.
 *
 * @version $Id: BasicCertificateExtension.java 30583 2018-11-22 17:32:11Z
 *     samuellb $
 */
public class BasicCertificateExtension extends CertificateExtension
    implements CustomCertificateExtension {

  private static final long serialVersionUID = 6896964791897238060L;

  /** Logger. */
  @SuppressWarnings("unused")
  private static final Logger LOG =
      Logger.getLogger(BasicCertificateExtension.class);

  /** Internal resource. */
  private static final InternalResources INT_RES =
      InternalResources.getInstance();

  /** Display name. */
  private static final String DISPLAY_NAME = "Basic Certificate Extension";

  private enum Encoding {
    /** Bitstring. */
    ENCODING_DERBITSTRING("DERBITSTRING"),
    /** Int. */
    ENCODING_DERINTEGER("DERINTEGER"),
    /** ASCII. */
    ENCODING_DEROCTETSTRING("DEROCTETSTRING"),
    /** Boolean. */
    ENCODING_DERBOOLEAN("DERBOOLEAN"),
    /** Printable. */
    ENCODING_DERPRINTABLESTRING("DERPRINTABLESTRING"),
    /** UTF-8. */
    ENCODING_DERUTF8STRING("DERUTF8STRING"),
    /** IA5 String. */
    ENCODING_DERIA5STRING("DERIA5STRING"),
    /** DER Null. */
    ENCODING_DERNULL("DERNULL"),
    /** DER Object. */
    ENCODING_DEROBJECT("DEROBJECT"),
    /** DER OID. */
    ENCODING_DEROID("DERBOJECTIDENTIFIER");

    /** lookup map. */
    private static final Map<String, Encoding> LOOKUP_MAP =
        new HashMap<String, Encoding>();

    static {
      for (Encoding encoding : Encoding.values()) {
        LOOKUP_MAP.put(encoding.value(), encoding);
      }
    }

    /** Value. */
    private final String value;

    Encoding(final String avalue) {
      this.value = avalue;
    }

    public String value() {
      return value;
    }

    public boolean equals(final Encoding otherValue) {
      if (otherValue == null) {
        return false;
      }
      return value.equalsIgnoreCase(otherValue.value());
    }

    public static Encoding fromString(final String value) {
      return LOOKUP_MAP.get(StringUtils.upperCase(value, Locale.ROOT));
    }
  }

  /**
   * The value is expected to by hex encoded and is added as an byte array as
   * the extension value.
   */
  private static final String ENCODING_RAW = "RAW";
  /** DER null . */
  private static final String ENCODING_DERNULL = "DERNULL";

  // Defined Properties
  /** Value. */
  private static final String PROPERTY_VALUE = "value";
  /** Encoding. */
  private static final String PROPERTY_ENCODING = "encoding";
  /** Nvalues. */
  private static final String PROPERTY_NVALUES = "nvalues";
  /** Dynamic. */
  private static final String PROPERTY_DYNAMIC = "dynamic";

  /** Properties. */
  private static final Map<String, String[]> PROPERTIES_MAP =
      new HashMap<String, String[]>();

  static {
    Encoding[] encodings = Encoding.values();
    // +1 because we need to add RAW as well in the end
    String[] encodingValues = new String[encodings.length + 1];
    for (int i = 0; i < encodings.length; i++) {
      encodingValues[i] = encodings[i].value;
    }
    // Add RAW last
    encodingValues[encodingValues.length - 1] = ENCODING_RAW;

    PROPERTIES_MAP.put(PROPERTY_ENCODING, encodingValues);
    PROPERTIES_MAP.put(PROPERTY_VALUE, new String[] {});
    PROPERTIES_MAP.put(PROPERTY_DYNAMIC, CustomCertificateExtension.BOOLEAN);
  }

  /**
   * Constructor.
   */
  public BasicCertificateExtension() {
    setDisplayName(DISPLAY_NAME);
  }

  /**
   * @param userData User
   * @param ca CA
   * @param certProfile profile
   * @param userPublicKey key
   * @param caPublicKey key
   * @param val val
   * @return asn.1
   * @throws CertificateExtensionException on fail
   * @deprecated use getValueEncoded instead. */
  public ASN1Encodable getValue(
      final EndEntityInformation userData,
      final CA ca,
      final CertificateProfile certProfile,
      final PublicKey userPublicKey,
      final PublicKey caPublicKey,
      final CertificateValidity val)
      throws CertificateExtensionException {
    throw new UnsupportedOperationException("Use getValueEncoded instead");
  }

  /**
   * Returns the defined property 'value' in the encoding specified in
   * 'encoding'.
   *
   * <p>This certificate extension implementations overrides this method as it
   * want to be able to return a byte[] with the extension value. Otherwise the
   * implementation could have been put in the getValue method as the super
   * class CertificateExtension has a default implementation for getValueEncoded
   * which calls getValue.
   *
   * @param userData Used to lookup extension data
   * @param ca not used
   * @param certProfile not used
   * @see
   *     org.cesecore.certificates.certificate.certextensions.CertificateExtension#getValueEncoded(EndEntityInformation,
   *     CA, CertificateProfile, PublicKey, PublicKey, CertificateValidity)
   */
  @Override
  public byte[] getValueEncoded(
      final EndEntityInformation userData,
      final CA ca,
      final CertificateProfile certProfile,
      final PublicKey userPublicKey,
      final PublicKey caPublicKey,
      final CertificateValidity val)
      throws CertificateExtensionException {
    String[] values = getValues(userData, null);
    return handleValues(values);
  }

  @Override
  public byte[] getValueEncoded(
      final EndEntityInformation userData,
      final CA ca,
      final CertificateProfile certProfile,
      final PublicKey userPublicKey,
      final PublicKey caPublicKey,
      final CertificateValidity val,
      final String oid)
      throws CertificateExtensionException {
    String[] values = getValues(userData, oid);
    return handleValues(values);
  }

  private byte[] handleValues(final String[] values)
      throws CertificateExtensionException {
    final byte[] result;
    String encoding =
        StringUtils.trim(getProperties().getProperty(PROPERTY_ENCODING));
    if (values == null
        || values.length == 0
        || values[0] == null
            && !encoding.equalsIgnoreCase(ENCODING_DERNULL)) {
      if (!isRequiredFlag()) {
        return null;
      }
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.incorrectvalue",
              Integer.valueOf(getId()),
              getOID()));
    }

    if (encoding.equalsIgnoreCase(ENCODING_RAW)) {
      if (values.length > 1) {
        // nvalues can not be used together with encoding=RAW
        throw new CertificateExtensionException(
            INT_RES.getLocalizedMessage(
                "certext.certextmissconfigured", Integer.valueOf(getId())));
      } else {
        result = parseRaw(values[0]);
      }
    } else {
      try {
        if (values.length > 1) {
          ASN1EncodableVector ev = new ASN1EncodableVector();
          for (String value : values) {
            ASN1Encodable derval = parseValue(encoding, value);
            ev.add(derval);
          }
          result = new DERSequence(ev).getEncoded();
        } else {
          result =
              parseValue(encoding, values[0]).toASN1Primitive().getEncoded();
        }
      } catch (IOException ioe) {
        throw new CertificateExtensionException(ioe.getMessage(), ioe);
      }
    }
    return result;
  }

  /**
   * Get the extension value by first looking in the ExtendedInformation (if
   * dynamic is enabled) and then in the static configuration.
   *
   * @param userData The userdata to get the ExtendedInformation from
   * @param oid OID
   * @return The value(s) for the extension (usually 1) or null if no value
   *     found
   */
  private String[] getValues(
          final EndEntityInformation userData, final String oid) {
    String[] result = null;

    boolean dynamic =
        Boolean.parseBoolean(
            StringUtils.trim(
                getProperties()
                    .getProperty(PROPERTY_DYNAMIC, Boolean.FALSE.toString())));

    String strnvalues = getProperties().getProperty(PROPERTY_NVALUES);
    int nvalues = getInitNvalues(strnvalues);

    if (dynamic) {
      final ExtendedInformation ei = userData.getExtendedInformation();
      if (ei == null) {
        result = null;
      } else {
        if (nvalues < 1) {
          String value = null;
          if (oid != null) {
            value = userData.getExtendedInformation().getExtensionData(oid);
            if (value == null || value.trim().isEmpty()) {
              value =
                  userData
                      .getExtendedInformation()
                      .getExtensionData(oid + "." + PROPERTY_VALUE);
            }
          } else {
            value =
                userData.getExtendedInformation().getExtensionData(getOID());
            if (value == null || value.trim().isEmpty()) {
              value =
                  userData
                      .getExtendedInformation()
                      .getExtensionData(getOID() + "." + PROPERTY_VALUE);
            }
          }
          if (value == null) {
            result = null;
          } else {
            result = new String[] {value};
          }
        } else {
          for (int i = 1; i <= nvalues; i++) {
            String value = null;
            if (oid != null) {
              value =
                  userData
                      .getExtendedInformation()
                      .getExtensionData(
                          oid + "." + PROPERTY_VALUE + Integer.toString(i));
            } else {
              value =
                  userData
                      .getExtendedInformation()
                      .getExtensionData(
                          getOID()
                              + "."
                              + PROPERTY_VALUE
                              + Integer.toString(i));
            }
            if (value != null) {
              if (result == null) {
                result = new String[nvalues];
              }
              result[i - 1] = value;
            }
          }
        }
      }
    }
    if (result == null) {
      if (nvalues < 1) {
        String value = getProperties().getProperty(PROPERTY_VALUE);
        if (value == null || value.trim().equals("")) {
          value = getProperties().getProperty(PROPERTY_VALUE + "1");
        }
        result = new String[] {value};
      } else {
        result = new String[nvalues];
        for (int i = 1; i <= nvalues; i++) {
          result[i - 1] =
              getProperties().getProperty(PROPERTY_VALUE + Integer.toString(i));
        }
      }
    }
    return result;
  }

/**
 * @param strnvalues vaues
 * @return values
 * @throws NumberFormatException fail
 */
private int getInitNvalues(final String strnvalues)
        throws NumberFormatException {
    int nvalues;

    if (strnvalues == null || strnvalues.trim().equals("")) {
      nvalues = 0;
    } else {
      nvalues = Integer.parseInt(strnvalues);
    }
    return nvalues;
}

  private ASN1Encodable parseValue(final String encoding, final String value)
      throws CertificateExtensionException {

    ASN1Encodable toret = null;

    Encoding encodingType = Encoding.fromString(encoding);

    if (encodingType == null) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.incorrectenc",
              encoding,
              Integer.valueOf(getId())));
    }

    if (!Encoding.ENCODING_DERNULL.equals(encodingType)
        && (value == null || value.trim().equals("")) && isRequiredFlag()) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.incorrectvalue",
              Integer.valueOf(getId()),
              getOID()));
    }

    switch (encodingType) {
      case ENCODING_DERBITSTRING:
        toret = parseDERBitString(value);
        break;
      case ENCODING_DERINTEGER:
        toret = parseDERInteger(value);
        break;
      case ENCODING_DEROCTETSTRING:
        toret = parseDEROctetString(value);
        break;
      case ENCODING_DERBOOLEAN:
        toret = parseDERBoolean(value);
        break;
      case ENCODING_DEROID:
        toret = parseDEROID(value);
        break;
      case ENCODING_DERPRINTABLESTRING:
        toret = parseDERPrintableString(value);
        break;
      case ENCODING_DERUTF8STRING:
        toret = parseDERUTF8String(value);
        break;
      case ENCODING_DERIA5STRING:
        toret = parseDERIA5String(value);
        break;
      case ENCODING_DERNULL:
        toret = DERNull.INSTANCE;
        break;
      case ENCODING_DEROBJECT:
        toret = parseHexEncodedDERObject(value);
        break;
      default:
        throw new CertificateExtensionException(
            INT_RES.getLocalizedMessage(
                "certext.basic.incorrectenc",
                encoding,
                Integer.valueOf(getId())));
    }
    return toret;
  }

  private ASN1Encodable parseDERBitString(final String value)
      throws CertificateExtensionException {
    ASN1Encodable retval = null;
    try {
      BigInteger bigInteger = new BigInteger(value, 2);
      int padBits = value.length() - 1 - value.lastIndexOf("1");
      if (padBits == 8) {
        padBits = 0;
      }
      byte[] byteArray = bigInteger.toByteArray();
      if (byteArray[0] == 0) {
        // Remove empty extra byte
        // System.arraycopy handles creating of temporary array when destinatio
        // is the same
        System.arraycopy(byteArray, 1, byteArray, 0, byteArray.length - 1);
      }
      retval = new DERBitString(byteArray, padBits);
    } catch (NumberFormatException e) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }

    return retval;
  }

  private ASN1Encodable parseDEROID(final String value)
      throws CertificateExtensionException {
    ASN1Encodable retval = null;
    try {
      retval = new ASN1ObjectIdentifier(value);
    } catch (Exception e) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }

    return retval;
  }

  private ASN1Encodable parseDERInteger(final String value)
      throws CertificateExtensionException {
    ASN1Encodable retval = null;
    try {
      BigInteger intValue = new BigInteger(value, 10);
      retval = new ASN1Integer(intValue);
    } catch (NumberFormatException e) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }

    return retval;
  }

  private ASN1Encodable parseDEROctetString(final String value)
      throws CertificateExtensionException {
    ASN1Encodable retval = null;
    if (value.matches("^\\p{XDigit}*")) {
      byte[] bytes = Hex.decode(value);
      retval = new DEROctetString(bytes);
    } else {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }
    return retval;
  }

  /**
   * Tries to read the hex-string as an DERObject. If it contains more than one
   * ASN1Encodable object, return a DERSequence of the objects.
   *
   * @param value value
   * @return DER sequence
   * @throws CertificateExtensionException on fail
   */
  private ASN1Encodable parseHexEncodedDERObject(final String value)
      throws CertificateExtensionException {
    ASN1Encodable retval = null;
    if (value.matches("^\\p{XDigit}*")) {
      byte[] bytes = Hex.decode(value);
      try {
        ASN1InputStream ais = new ASN1InputStream(bytes);
        ASN1Encodable firstObject = ais.readObject();
        if (ais.available() > 0) {
          ASN1EncodableVector ev = new ASN1EncodableVector();
          ev.add(firstObject);
          while (ais.available() > 0) {
            ev.add(ais.readObject());
          }
          retval = new DERSequence(ev);
        } else {
          retval = firstObject;
        }
        ais.close();
      } catch (Exception e) {
        throw new CertificateExtensionException(
            INT_RES.getLocalizedMessage(
                "certext.basic.illegalvalue",
                value,
                Integer.valueOf(getId()),
                getOID()));
      }
    } else {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }
    return retval;
  }

  private ASN1Encodable parseDERBoolean(final String value)
      throws CertificateExtensionException {
    ASN1Encodable retval = null;
    if (value.equalsIgnoreCase("TRUE")) {
      retval = ASN1Boolean.TRUE;
    }

    if (value.equalsIgnoreCase("FALSE")) {
      retval = ASN1Boolean.FALSE;
    }

    if (retval == null) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }

    return retval;
  }

  private ASN1Encodable parseDERPrintableString(final String value)
      throws CertificateExtensionException {
    try {
      return new DERPrintableString(value, true);
    } catch (IllegalArgumentException e) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }
  }

  private ASN1Encodable parseDERUTF8String(final String value) {
    return new DERUTF8String(value);
  }

  private ASN1Encodable parseDERIA5String(final String value)
      throws CertificateExtensionException {
    try {
      return new DERIA5String(value, true);
    } catch (IllegalArgumentException e) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.illegalvalue",
              value,
              Integer.valueOf(getId()),
              getOID()));
    }
  }

  private byte[] parseRaw(
          final String value) throws CertificateExtensionException {
    if (value == null) {
      throw new CertificateExtensionException(
          INT_RES.getLocalizedMessage(
              "certext.basic.incorrectvalue",
              Integer.valueOf(getId()),
              getOID()));
    }
    return Hex.decode(value);
  }

  @Override
  public Map<String, String[]> getAvailableProperties() {
    return PROPERTIES_MAP;
  }
}
