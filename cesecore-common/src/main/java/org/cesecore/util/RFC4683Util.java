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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.util.DnComponents;

/**
 * Helper class to handle operations for RFC4683 certificate extension Subject
 * Identification method (SIM) for including a privacy-sensitive identifier in
 * the subjectAltName extension of a certificate. The SIM is an optional feature
 * that may be used by relying parties to determine whether the subject of a
 * particular certificate is also the person corresponding to a particular
 * sensitive identifier (@see <a
 * href="https://tools.ietf.org/html/rfc4683">RFC4683</a>.)
 *
 * @version $Id: RFC4683Tools.java 31882 2019-03-18 13:50:56Z anatom $
 */
public final class RFC4683Util {

  /**
   * List separator to separate the SIM tokens in the internal storage format
   * (also has to be entered by the user).
   */
  public static final String LIST_SEPARATOR = "::";

  /** Label for SIM rendered in the certificate. */
  public static final String SUBJECTIDENTIFICATIONMETHOD =
      "subjectIdentificationMethod";

  /** OID for SIM written into the certificate. */
  public static final String SUBJECTIDENTIFICATIONMETHOD_OBJECTID =
      "1.3.6.1.5.5.7.8.6";

  /** Logger. */
  private static final Logger LOG = Logger.getLogger(RFC4683Util.class);

  /**
   * Gets the allowed hash algorithm object identifiers (@see <a
   * href="https://tools.ietf.org/html/rfc4683#section-4.3">RFC4683</a>).
   *
   * @return a list of ASN1ObjectIdentifier {@link TSPAlgorithms#ALLOWED}.
   */
  @SuppressWarnings("unchecked")
  public static List<ASN1ObjectIdentifier> getAllowedHashAlgorithms() {
    return new ArrayList<ASN1ObjectIdentifier>(TSPAlgorithms.ALLOWED);
  }

  /**
   * Gets the allowed hash algorithm OID strings.
   *
   * @return a list of OID strings {@link TSPAlgorithms#ALLOWED}.
   */
  public static List<String> getAllowedHashAlgorithmOidStrings() {
    final List<ASN1ObjectIdentifier> identifiers = getAllowedHashAlgorithms();
    final List<String> result = new ArrayList<String>(identifiers.size());
    for (ASN1ObjectIdentifier identifier : identifiers) {
      result.add(identifier.getId());
    }
    return result;
  }

  /**
   * This method reads the internal storage format for SAN. If the SAN contains
   * SIM parameters (list of 4 tokens, separated by '::'), the parameters are
   * replaced by the generated SIM strings (list of 3 tokens, separated by '::')
   * {@link RFC4683Util#generateInternalSimString(String, String, String,
   * String)}
   *
   * @param osan the SAN string in internal storage format with SIM as user
   *     parameters.
   * @return SAN string in internal storage format with generated SIM strings.
   * @throws IllegalArgumentException on illegal request
   * @throws NoSuchProviderException If provider not found
   * @throws NoSuchAlgorithmException If algorithm not found
   */
  public static String generateSimForInternalSanFormat(final String osan)
      throws IllegalArgumentException, NoSuchProviderException,
          NoSuchAlgorithmException {
      final int hashIdx = 0;
      final int tokIdx = 1;
      final int typeIdx = 2;
      final int ssiIdx = 3;
      final int length = 4;
      String san = osan;
    if (StringUtils.isNotBlank(san)
        && san.contains(DnComponents.SUBJECTIDENTIFICATIONMETHOD)) {
      final List<String> sims =
          CertTools.getPartsFromDN(
              san, DnComponents.SUBJECTIDENTIFICATIONMETHOD);
      for (String sim : sims) {
        if (LOG.isDebugEnabled()) {
          LOG.info("Store user SIM strings: " + sims);
        }
        if (StringUtils.isNotBlank(sim)) {
          final String[] tokens = sim.split(LIST_SEPARATOR);
          // was entered as hash, password, SSIType and SSI, so generate the SIM
          if (tokens.length == length) {
            final String newSim =
                generateInternalSimString(
                    tokens[hashIdx], tokens[tokIdx],
                    tokens[typeIdx], tokens[ssiIdx]);
            san = san.replace(sim, newSim);
          } else if (tokens.length == length - 1) { // NOPMD
            // NOOP
          } else {
            throw new IllegalArgumentException(
                "Wrong SIM input string with " + tokens.length + " tokens.");
          }
        }
      }
    }
    return san;
  }

  /**
   * Creates a '::' separated string of hashAlogrithmOidString, Authority Random
   * (R) and Privacy-Enhanced Protected Subject Information (PEPSI). Note:
   * RFC4683 Subject Identification Method (SIM = R || PEPSI), and PEPSI = H(H(
   * P || R || SIItype || SII)). The resulting String is used for internal
   * storage.
   *
   * <p>Where R is the Authority Random hash and PEPSI the Privacy-Enhanced
   * Protected Subject Information: PEPSI = H(H( P || R || SIItype || SII))
   * Where P is the user chosen password, SSI the Sensitive Identification
   * Information and SIIType its type.
   *
   * @param hashAlogrithmOidString i.e '1.3.14.3.2.26' for SHA-1
   * @param userChosenPassword (P) FIPS 112 and FIPS 180-1 compliant password up
   *     to 28 characters (see https://tools.ietf.org/html/rfc4683#section-4.2)
   * @param ssiType OID string of an SSI type (see
   *     https://tools.ietf.org/html/rfc4683#section-4.1).
   * @param ssi Sensitive Identification Information (SII) (see
   *     https://tools.ietf.org/html/rfc4683#section-4.1).
   * @return a '::' separated string of hashAlogrithmOidString, R and PEPSI.
   * @throws IllegalArgumentException on illegal request
   * @throws NoSuchProviderException If provider not found
   * @throws NoSuchAlgorithmException If algorithm not found
   */
  public static String generateInternalSimString(
      final String hashAlogrithmOidString,
      final String userChosenPassword,
      final String ssiType,
      final String ssi)
      throws IllegalArgumentException, NoSuchProviderException,
          NoSuchAlgorithmException {
    handleBlankAlgo(hashAlogrithmOidString);
    if (!getAllowedHashAlgorithmOidStrings().contains(hashAlogrithmOidString)) {
      throw new IllegalArgumentException(
          "Hash algorithm with OID '"
              + hashAlogrithmOidString
              + "' is not supparted for RFC4683 (SIM).");
    }
    // TODO Insert check for FIPS 180-1 compliant passwords (better current
    // standards ...)
    if (StringUtils.isBlank(userChosenPassword)
        || userChosenPassword.length() < 8) {
      throw new IllegalArgumentException(
          "The user chosen password must not be null or empty: '"
              + hashAlogrithmOidString
              + "'.");
    }
    if (StringUtils.isBlank(ssiType)) {
      throw new IllegalArgumentException(
          "The sensitve identification information type must not be null or"
              + " empty: '"
              + ssiType
              + "'.");
    }
    if (StringUtils.isBlank(ssi)) {
      throw new IllegalArgumentException(
          "The sensitve identification information must not be null or empty: '"
              + ssi
              + "'.");
    }
    final StringBuilder result = new StringBuilder();
    result.append(hashAlogrithmOidString);

    // 1. Create authority random.
    final String authorityRandomSource =
        Long.toHexString(
            SernoGeneratorRandom.instance(16).getSerno().longValue());
    if (LOG.isDebugEnabled()) {
      LOG.debug("Authority random source created: " + authorityRandomSource);
    }

    // 1b. Get HEX by hash of authority random.
    final MessageDigest digester =
        MessageDigest.getInstance(
            new ASN1ObjectIdentifier(hashAlogrithmOidString).getId(),
            BouncyCastleProvider.PROVIDER_NAME);
    digester.update(authorityRandomSource.getBytes());
    final String authorityRandom = toHexString(digester.digest());
    result.append(LIST_SEPARATOR).append(authorityRandom);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Authority random hash created: " + authorityRandom);
    }

    // 2. Create SIM HEX string, and hash 2 times.
    digester.update(
        new StringBuilder()
            .append(userChosenPassword)
            .append(authorityRandomSource)
            .append(ssiType)
            .append(ssi)
            .toString()
            .getBytes());
    digester.update(digester.digest());
    final String pepsi = toHexString(digester.digest());
    result.append(LIST_SEPARATOR).append(pepsi);
    if (LOG.isDebugEnabled()) {
      LOG.debug("SIM string PEPSI created: " + pepsi);
    }
    return result.toString();
  }

/**
 * @param hashAlogrithmOidString Algo
 * @throws IllegalArgumentException fial
 */
private static void handleBlankAlgo(final String hashAlogrithmOidString)
        throws IllegalArgumentException {
    if (StringUtils.isBlank(hashAlogrithmOidString)) {
      throw new IllegalArgumentException(
          "Hash algorithm OID string must not be null or empty: '"
              + hashAlogrithmOidString
              + "'.");
    }
}

  /**
   * Creates a SIM GeneralName by the internal SIM storage format
   * ('hashAlgorithmOIDString::R::PEPSI') SIM ::= SEQUENCE { hashAlg
   * AlgorithmIdentifier, authorityRandom OCTET STRING, -- RA-chosen random
   * number -- used in computation of -- pEPSI pEPSI OCTET STRING -- hash of
   * HashContent -- with algorithm hashAlg }.
   *
   * @param hashAlgorithmIdentifier the OID string for the hash algorithm used
   *     to hash R and PEPSI.
   * @param authorityRandom the registration authority chosen random value,
   *     hashed with hash of hashAlogrithmOidString (see
   *     https://tools.ietf.org/html/rfc4683#section-4.3).
   * @param pepsi Privacy-Enhanced Protected Subject Information (PEPSI), with
   *     SIM = R || PEPSI.
   * @return the RFC4683 SIM GeneralName (@see <a
   *     href="https://tools.ietf.org/html/rfc4683">RFC4683</a>.).
   */
  public static ASN1Primitive createSimGeneralName(
      final String hashAlgorithmIdentifier,
      final String authorityRandom,
      final String pepsi) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Creating SIM with hash algorithem identifier "
              + hashAlgorithmIdentifier
              + ", authority random "
              + authorityRandom
              + " and PEPSI "
              + pepsi);
    }
    final ASN1EncodableVector otherName = new ASN1EncodableVector();
    otherName.add(
        new ASN1ObjectIdentifier(SUBJECTIDENTIFICATIONMETHOD_OBJECTID));
    final ASN1EncodableVector simVector = new ASN1EncodableVector();
    simVector.add(
        new AlgorithmIdentifier(
            new ASN1ObjectIdentifier(
                hashAlgorithmIdentifier))); // new DERTaggedObject(true, 0,
    simVector.add(new DEROctetString(authorityRandom.getBytes()));
    simVector.add(new DEROctetString(pepsi.getBytes()));
    otherName.add(new DERTaggedObject(true, 0, new DERSequence(simVector)));
    final ASN1Primitive generalName =
        new DERTaggedObject(false, 0, new DERSequence(otherName));
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "GeneralName (type 0 - OtherName) for SIM created "
              + generalName.toString());
    }
    return generalName;
  }

  /**
   * Helper method for getting the SIM name from SAN ASN.1 sequence.
   *
   * @param sequence the OtherName sequence
   * @return the SIM string by the otherName.
   */
  public static String getSimStringSequence(final ASN1Sequence sequence) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Parsing RFC4683 (SIM) from SAN ASN.1 sequence: " + sequence);
    }
    String result = null;
    if (sequence != null) {
      // First in sequence is the object identifier, that we must check
      final ASN1ObjectIdentifier id =
          ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
      if (SUBJECTIDENTIFICATIONMETHOD_OBJECTID.equals(id.getId())) {
        final ASN1Sequence simVector =
            (ASN1Sequence)
                ((ASN1TaggedObject) sequence.getObjectAt(1)).getObject();
        // 1. After certificate issuance the method is called with an algorithm
        // identifier in its ASN.1 sequence.
        // 2. But after reading a stored certificate (PEM or DER) the ASN.1
        // sequence contains a DERSeqence instead.
        String algorithmIdentifier = null;
        if (simVector.getObjectAt(0) instanceof AlgorithmIdentifier) {
          algorithmIdentifier =
              ((AlgorithmIdentifier) simVector.getObjectAt(0))
                  .getAlgorithm()
                  .getId();
        } else {
          final ASN1Encodable encodable =
              ((ASN1Sequence) simVector.getObjectAt(0)).getObjectAt(0);
          algorithmIdentifier = encodable.toASN1Primitive().toString();
        }
        final ASN1OctetString hash = (ASN1OctetString) simVector.getObjectAt(1);
        final ASN1OctetString pepsi =
            (ASN1OctetString) simVector.getObjectAt(2);
        final String hashString = new String(hash.getOctets());
        final String pepsiString = new String(pepsi.getOctets());
        final StringBuilder builder = new StringBuilder();
        result =
            builder
                .append(algorithmIdentifier)
                .append(LIST_SEPARATOR)
                .append(hashString)
                .append(LIST_SEPARATOR)
                .append(pepsiString)
                .toString();
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("SIM parsed from other name: " + result);
    }
    return result;
  }

  /**
   * The method generates the HEX string by digestResult.
   *
   * @param digestResult the resulting byte[] of the digester.
   * @return the HEX string.
   */
  public static String toHexString(final byte[] digestResult) {
    final StringBuffer buf = new StringBuffer(digestResult.length * 2);
    final int mask = 0xff;
    for (int i = 0; i < digestResult.length; i++) {
      int intVal = digestResult[i] & mask;
      if (intVal < 0x10) {
        buf.append("0");
      }
      buf.append(Integer.toHexString(intVal).toUpperCase());
    }
    return buf.toString();
  }

  /** Avoid instantiation. */
  private RFC4683Util() { }
}
