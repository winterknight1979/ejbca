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
package org.ejbca.core.protocol.cmp;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Helper class to verify PBE of CMP messages, also extracts owf, mac Oids and
 * iteration count.
 *
 * @version $Id: CmpPbeVerifyer.java 25799 2017-05-04 21:04:53Z jeklund $
 */
public class CmpPbeVerifyer {
      /** Logger. */
  private static final Logger LOG = Logger.getLogger(CmpPbeVerifyer.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** Param. */
  private byte[] protectedBytes = null;
  /** Param. */
  private DERBitString protection = null;
  /** Param. */
  private AlgorithmIdentifier pAlg = null;
  /** Param. */
  private String errMsg = null;
  /** Param. */
  private String owfOid = null;
  /** Param. */
  private String macOid = null;
  /** Param. */
  private final int defaultIts = 1024;
  /** Param. */
  private int iterationCount = defaultIts;
  /** Param. */
  private byte[] salt = null;
  /** Param. */
  private String lastUsedRaSecret = null;

  /**
   * Constructor for CmpPbeVerifyer.
   *
   * @param amsg the PKIMessage payload from the CMP Message
   * @throws InvalidCmpProtectionException if this class is invoked on a message
   *     not signed with a password based MAC or the iterator count for this
   *     verifier was set higher than 10000.
   */
  public CmpPbeVerifyer(final PKIMessage amsg)
      throws InvalidCmpProtectionException {
    final int maxIts = 10000;
    final PKIHeader head = amsg.getHeader();
    protectedBytes = CmpMessageHelper.getProtectedBytes(amsg);
    protection = amsg.getProtection();
    pAlg = head.getProtectionAlg();
    final ASN1ObjectIdentifier algId = pAlg.getAlgorithm();
    if (!StringUtils.equals(
        algId.getId(), CMPObjectIdentifiers.passwordBasedMac.getId())) {
      final String theerrMsg =
          "Protection algorithm id expected '"
              + CMPObjectIdentifiers.passwordBasedMac.getId()
              + "' (passwordBasedMac) but was '"
              + algId.getId()
              + "'.";
      throw new InvalidCmpProtectionException(theerrMsg);
    }
    final PBMParameter pp = PBMParameter.getInstance(pAlg.getParameters());
    iterationCount = pp.getIterationCount().getPositiveValue().intValue();
    final AlgorithmIdentifier owfAlg = pp.getOwf();
    // Normal OWF alg is 1.3.14.3.2.26 - SHA1
    owfOid = owfAlg.getAlgorithm().getId();
    final AlgorithmIdentifier macAlg = pp.getMac();
    // Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
    macOid = macAlg.getAlgorithm().getId();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Protection type is: " + algId.getId());
      LOG.debug("Iteration count is: " + iterationCount);
      LOG.debug("Owf type is: " + owfOid);
      LOG.debug("Mac type is: " + macOid);
    }
    if (iterationCount > maxIts) {
      LOG.info(
          "Received message with too many iterations in PBE protection: "
              + iterationCount);
      throw new InvalidCmpProtectionException(
          "Iteration count can not exceed 10000");
    }
    salt = pp.getSalt().getOctets();
  }

  /**
   * @param raAuthenticationSecret the HMAC PBE password that should be used to
   *     verify the CMP message protection
   * @return true if the given password was correct
   * @throws InvalidKeyException if the key was not compatible with this MAC
   * @throws NoSuchAlgorithmException if the algorithm for the Owf or the MAC
   *     weren't found
   */
  public boolean verify(final String raAuthenticationSecret)
      throws InvalidKeyException, NoSuchAlgorithmException {
    if (raAuthenticationSecret == null) {
      throw new IllegalArgumentException("RA authentication secret is null.");
    }
    lastUsedRaSecret = raAuthenticationSecret;
    boolean ret = false;
    // Verify the PasswordBased protection of the message
    if (!pAlg.getAlgorithm().equals(CMPObjectIdentifiers.passwordBasedMac)) {
      errMsg =
          INTRES.getLocalizedMessage(
              "cmp.errorunknownprotalg", pAlg.getAlgorithm().getId());
      LOG.error(errMsg);
      return ret;
    } else {
      byte[] raSecret = raAuthenticationSecret.getBytes();
      byte[] basekey = new byte[raSecret.length + salt.length];
      System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
      System.arraycopy(salt, 0, basekey, raSecret.length, salt.length);
      // Construct the base key according to rfc4210, section 5.1.3.1
      try {
        MessageDigest dig =
            MessageDigest.getInstance(
                owfOid, BouncyCastleProvider.PROVIDER_NAME);
        for (int i = 0; i < iterationCount; i++) {
          basekey = dig.digest(basekey);
          dig.reset();
        }
        // HMAC/SHA1 is normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7
        Mac mac = Mac.getInstance(macOid, BouncyCastleProvider.PROVIDER_NAME);
        SecretKey key = new SecretKeySpec(basekey, macOid);
        mac.init(key);
        mac.reset();
        mac.update(protectedBytes, 0, protectedBytes.length);
        byte[] out = mac.doFinal();
        // My out should now be the same as the protection bits
        byte[] pb = protection.getBytes();
        ret = Arrays.equals(out, pb);
      } catch (NoSuchProviderException e) {
        throw new IllegalStateException("BouncyCastle provider not found.");
      }
    }
    return ret;
  }

  /**
   * @return ERR
   */
  public String getErrMsg() {
    return errMsg;
  }

  /**
   * @return OID
   */
  public String getMacOid() {
    return macOid;
  }

  /**
   * @return OID
   */
  public String getOwfOid() {
    return owfOid;
  }

  /**
   * @return count
   */
  public int getIterationCount() {
    return iterationCount;
  }

  /**
   * @return secret
   */
  public String getLastUsedRaSecret() {
    return lastUsedRaSecret;
  }
}
