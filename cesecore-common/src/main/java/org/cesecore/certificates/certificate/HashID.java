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
package org.cesecore.certificates.certificate;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * An object of this class is identifying one or several certificates or a CRL.
 *
 * @version $Id: HashID.java 26020 2017-06-14 12:41:08Z mikekushner $
 */
public final class HashID {
  /** Log4j instance for Base. */
  private static final Logger LOG = Logger.getLogger(HashID.class);
  /** True if the ID confirms to a RFC4387 ID. */
  private final boolean isOK;
  /**
   * The RFC4387 identification string. This is a base64 encoding of the hash.
   */
  private final String b64;

  /** The b64 with \ substituted with %2B to be used for URLs. */
  private final String b64url;
  /** Key to be used for hash tables. */
  private final Integer key;
  /** Length. */
  private static final int HASH_LENGTH = 27;

  private HashID(final byte[] hash) {
    final String b64padded = new String(Base64.encode(hash));
    if (b64padded.length() != HASH_LENGTH + 1
            || b64padded.charAt(HASH_LENGTH) != '=') {
      this.isOK = false;
      this.b64 = b64padded;
    } else {
      this.isOK = true;
      this.b64 = b64padded.substring(0, HASH_LENGTH);
    }
    this.b64url = this.b64.replaceAll("\\+", "%2B");
    this.key = Integer.valueOf(new BigInteger(hash).hashCode());
  }

  private static byte[] hashFromPrincipalDN(final X500Principal principal) {
    return CertTools.generateSHA1Fingerprint(principal.getEncoded());
  }

  private static HashID getFromDN(final X500Principal principal) {
    final HashID id = new HashID(hashFromPrincipalDN(principal));
    if (id.isOK) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The DN '"
                + principal.getName()
                + "' is identified by the Hash string '"
                + id.b64
                + "' when accessing the VA.");
      }
    } else {
      LOG.error(
          "The DN '"
              + principal.getName()
              + "' has a non valid Hash identification string: "
              + id.b64);
    }
    return id;
  }
  /**
   * @param cert The subject DN of the certificate should be the identifier.
   * @return the ID
   */
  public static HashID getFromSubjectDN(final X509Certificate cert) {
    return getFromDN(cert.getSubjectX500Principal());
  }
  /**
   * @param cert The issuer DN of the certificate should be the identifier.
   * @return the ID
   */
  public static HashID getFromIssuerDN(final X509Certificate cert) {
    return getFromDN(cert.getIssuerX500Principal());
  }

  /**
   * @param certificateHolder The issuer DN of the certificate should be the
   *     identifier.
   * @return the ID
   * @throws CertificateException on failure
   */
  public static HashID getFromIssuerDN(
          final X509CertificateHolder certificateHolder)
      throws CertificateException {
    return getFromIssuerDN(
        new JcaX509CertificateConverter().getCertificate(certificateHolder));
  }
  /**
   * @param sDN A string representation of a DN to be as ID. The DN will not be
   *     transformed in any way.
   * @return the ID.
   */
  public static HashID getFromDNString(final String sDN) {
    // Note that the DN string has to be encoded to an ASN1 with the BC lib. BC
    // endcoding is EJBCA standard.
    try {
      return getFromDN(
          new X500Principal(
              new X500Name(
                      CertTools.isDNReversed(sDN)
                          ? CertTools.reverseDN(sDN)
                          : sDN)
                  .getEncoded()));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * @param s The hash base64 encoded. See RFC4387
   * @return the ID.
   */
  public static HashID getFromB64(final String s) {
    return new HashID(Base64.decode(s.length() == HASH_LENGTH ? s + '=' : s));
  }
  /**
   * @param cert The public key of the certificate will be used as ID.
   * @return the ID.
   */
  public static HashID getFromKeyID(final X509Certificate cert) {
    final HashID id =
        new HashID(
            KeyTools.createSubjectKeyId(cert.getPublicKey())
                .getKeyIdentifier());
    if (id.isOK) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The certificate with subject DN '"
                + cert.getSubjectX500Principal().getName()
                + "' can be fetched with 'search.cgi?sKIDHash="
                + id.b64
                + "' from the VA.");
      }
    } else {
      LOG.error(
          "The certificate with subject DN '"
              + cert.getSubjectX500Principal().getName()
              + "' gives a sKIDHash with a not valid format: "
              + id.b64);
    }
    return id;
  }

  /**
   * @param cert certificate
   * @return ID
   * @throws IOException on fail*/
  public static HashID getFromAuthorityKeyId(final X509Certificate cert)
      throws IOException {
    final byte[] hash = CertTools.getAuthorityKeyId(cert);
    if (hash == null) {
      return null;
    }
    final HashID id = new HashID(CertTools.getAuthorityKeyId(cert));
    if (!id.isOK) {
      LOG.error(
          "The certificate with subject DN '"
              + cert.getSubjectX500Principal().getName()
              + "' don't have a valid AuthorityKeyId: "
              + id.b64);
    }
    return id;
  }

  /** @return base64 encoded URI */
  public String getB64url() {
    return b64url;
  }

  /** @return key. */
  public Integer getKey() {
    return key;
  }

  /** @return base64 encoded. */
  public String getB64() {
    return b64;
  }
}
