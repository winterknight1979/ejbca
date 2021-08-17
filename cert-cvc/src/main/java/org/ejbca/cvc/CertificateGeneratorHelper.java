/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.util.BCECUtil;

/**
 * Generates CV-certificates and CVC-requests.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public final class CertificateGeneratorHelper {

  // Only static methods...
  private CertificateGeneratorHelper() { }

  /**
   * Generates a CVCertificate for testing with the following characteristics: -
   * expires 3 months from today - hash-algorithm is 'SHA1withRSA' -
   * AuthorizationRoleEnum = IS.
   *
   * <p>TODO: Move this method to the test cases!
   *
   * @param publicKey key
   * @param privateKey key
   * @param caRef CA
   * @param holderRef holder
   * @param algorithm SHA1WithRSA, SHA256WithECDSA etc
   * @param role role
   * @return cert
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
 * @throws ConstructionException fail
   */
  public static CVCertificate createTestCertificate(
      final PublicKey publicKey,
      final PrivateKey privateKey,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef,
      final String algorithm,
      final AuthorizationRoleEnum role)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    // Skapa default-datum
    Calendar cal1 = Calendar.getInstance();
    Date validFrom = cal1.getTime();
    final int offset = 3;
    Calendar cal2 = Calendar.getInstance();
    cal2.add(Calendar.MONTH, offset);
    Date validTo = cal2.getTime();
    return createCertificate(
        publicKey,
        privateKey,
        algorithm,
        caRef,
        holderRef,
        role,
        AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
        validFrom,
        validTo,
        "BC");
  }

  /**
   * Generates a CVCertificate.
   *
   * @param signerKey key
   * @param algorithmName algo
 * @param body body
   * @param provider prov
   * @return cert
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws ConstructionException fail
   */
  public static CVCertificate createCertificate(
      final PrivateKey signerKey,
      final String algorithmName,
      final CVCertificateBody body,
      final String provider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {

    CVCertificate cvc = new CVCertificate(body);

    // Perform signing
    Signature signature =
        Signature.getInstance(
            AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName), provider);
    signature.initSign(signerKey);
    signature.update(cvc.getTBS());
    byte[] signdata = signature.sign();

    // Now convert the X9.62 signature to a CVC signature
    byte[] sig = BCECUtil.convertX962SigToCVC(algorithmName, signdata);
    // Save the signature and return the certificate
    cvc.setSignature(sig);
    return cvc;
  }

  /**
   * Generates a CVCertificate.
   *
   * @param publicKey Key
   * @param signerKey Key
   * @param algorithmName Algo
   * @param caRef CA
   * @param holderRef holder
   * @param authRole role
 * @param rights rights
   * @param validFrom date
   * @param validTo date
   * @param extensions Certificate extensions, or null to not add a "Certificate
   *     Extensions" object to the certificate.
   * @param provider prov
   * @return cert
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws ConstructionException fail
   */
  public static CVCertificate createCertificate(// NOPMD: params
      final PublicKey publicKey,
      final PrivateKey signerKey,
      final String algorithmName,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef,
      final AuthorizationRole authRole,
      final AccessRights rights,
      final Date validFrom,
      final Date validTo,
      final Collection<CVCDiscretionaryDataTemplate> extensions,
      final String provider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {

    CVCPublicKey cvcPublicKey =
        KeyFactory.createInstance(publicKey, algorithmName, authRole);
    CVCertificateBody body =
        new CVCertificateBody(
            caRef,
            cvcPublicKey,
            holderRef,
            authRole,
            rights,
            validFrom,
            validTo,
            extensions);

    return createCertificate(signerKey, algorithmName, body, provider);
  }

  /** Generates a CVCertificate.
 * @param publicKey Key
 * @param signerKey Key
 * @param algorithmName Name
 * @param caRef CA
 * @param holderRef holder
 * @param authRole role
 * @param rights rights
 * @param validFrom date
 * @param validTo date
 * @param provider prov
 * @return cert
 * @throws IOException fail
 * @throws NoSuchAlgorithmException fail
 * @throws NoSuchProviderException fail
 * @throws InvalidKeyException fail
 * @throws SignatureException fail
 * @throws ConstructionException fail */
  public static CVCertificate createCertificate(// NOPMD: Params
      final PublicKey publicKey,
      final PrivateKey signerKey,
      final String algorithmName,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef,
      final AuthorizationRole authRole,
      final AccessRights rights,
      final Date validFrom,
      final Date validTo,
      final String provider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createCertificate(
        publicKey,
        signerKey,
        algorithmName,
        caRef,
        holderRef,
        authRole,
        rights,
        validFrom,
        validTo,
        null,
        provider);
  }

  /**
   * Generates a CVCertificate. This seemingly redundant overloaded method is
   * for binary (.class file) backwards compatibility. It is NOT deprecated to
   * use these argument types.
 * @param publicKey key
 * @param signerKey key
 * @param algorithmName name
 * @param caRef CA
 * @param holderRef holder
 * @param authRole role
 * @param rights rights
 * @param validFrom date
 * @param validTo  date
 * @param provider provider
 * @return  cert
 * @throws IOException fail
 * @throws NoSuchAlgorithmException fail
 * @throws NoSuchProviderException  fail
 * @throws InvalidKeyException  fail
 * @throws SignatureException fail
 * @throws ConstructionException fail
   */
  public static CVCertificate createCertificate(// NOPMD: Params
      final PublicKey publicKey,
      final PrivateKey signerKey,
      final String algorithmName,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef,
      final AuthorizationRoleEnum authRole,
      final AccessRightEnum rights,
      final Date validFrom,
      final Date validTo,
      final String provider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createCertificate(
        publicKey,
        signerKey,
        algorithmName,
        caRef,
        holderRef,
        (AuthorizationRole) authRole,
        (AccessRights) rights,
        validFrom,
        validTo,
        provider);
  }

  /**
   * Generates a CVC-request without an outer signature using BouncyCastle as
   * signature provider.
   *
   * @param keyPair key
   * @param algorithmName algo
   * @param holderRef holder
   * @return cert
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
 * @throws ConstructionException fail
   */
  public static CVCertificate createRequest(
      final KeyPair keyPair,
      final String algorithmName,
      final HolderReferenceField holderRef)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createRequest(keyPair, algorithmName, holderRef, "BC");
  }

  /**
   * Same as above except that signature provider is an argument fail.
   *
   * @param keyPair key
   * @param algorithmName name
   * @param holderRef holder
   * @param signProvicer prov
   * @return cert
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws ConstructionException fail
   */
  public static CVCertificate createRequest(
      final KeyPair keyPair,
      final String algorithmName,
      final HolderReferenceField holderRef,
      final String signProvicer)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createRequest(keyPair, algorithmName, null, holderRef, signProvicer);
  }

  /**
   * Generates a CVC-request without an outer signature using BouncyCastle as
   * signature provider, taking Certificate Authority Reference as argument.
   *
   * @param keyPair keys
   * @param algorithmName name
   * @param caRef CA
   * @param holderRef holder
   * @return cert
   *  @throws IOException fail
   *     @throws NoSuchAlgorithmException fail
   *     @throws NoSuchProviderException fail
   *     @throws ConstructionException fail
   *     @throws SignatureException fail
   *     @throws InvalidKeyException fail
   * @see CertificateGeneratorHelper#createRequest(KeyPair,
   * String, CAReferenceField,
   *     HolderReferenceField, Collection, String)
   */
  public static CVCertificate createRequest(
      final KeyPair keyPair,
      final String algorithmName,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createRequest(keyPair, algorithmName, caRef, holderRef, null, "BC");
  }

  /**
   * Generates a CVC-request without an outer signature using BouncyCastle as
   * signature provider, taking Certificate Authority Reference as argument.
   *
   * @see CertificateGeneratorHelper#createRequest(KeyPair, String,
   * CAReferenceField,
   *     HolderReferenceField, Collection, String)
   *     @param keyPair pair
   *     @param algorithmName name
   *     @param caRef ref
   *     @param holderRef hoder
   *     @param signProvider prov
   *     @return cert
   *     @throws IOException fail
   *     @throws NoSuchAlgorithmException fail
   *     @throws NoSuchProviderException fail
   *     @throws ConstructionException fail
   *     @throws SignatureException fail
   *     @throws InvalidKeyException fail
   */
  public static CVCertificate createRequest(
      final KeyPair keyPair,
      final String algorithmName,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef,
      final String signProvider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createRequest(
        keyPair, algorithmName, caRef, holderRef, null, signProvider);
  }

  /**
   * Generates a CVC-request without an outer signature using BouncyCastle as
   * signature provider, taking Certificate Authority Reference as argument.
   *
   * @param keyPair Key pair
   * @param algorithmName Algorithm
   * @param holderRef Holder Reference
   * @param caRef CA Reference
   * @param extensions List of certificate extensions, or null to exclude.
   * @param signProvider Crypto provider to use for proof of possession
   *     signature.
   * @return A certificate request
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
 * @throws ConstructionException fail
   */
  public static CVCertificate createRequest(
      final KeyPair keyPair,
      final String algorithmName,
      final CAReferenceField caRef,
      final HolderReferenceField holderRef,
      final Collection<CVCDiscretionaryDataTemplate> extensions,
      final String signProvider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    CVCPublicKey cvcPublicKey =
        KeyFactory.createInstance(keyPair.getPublic(), algorithmName, null);

    // Create the Request Body (which is a simplified CVCertificateBody)
    CVCertificateBody reqBody =
        new CVCertificateBody(caRef, cvcPublicKey, holderRef, extensions);

    CVCertificate cvc = new CVCertificate(reqBody);

    // Perform the signing
    Signature innerSign =
        Signature.getInstance(
            AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName),
            signProvider);
    innerSign.initSign(keyPair.getPrivate());
    innerSign.update(cvc.getTBS());
    byte[] signdata = innerSign.sign();

    // Now convert the X9.62 signature to a CVC signature
    byte[] sig = BCECUtil.convertX962SigToCVC(algorithmName, signdata);

    // Create and return the CVCRequest (which is an instance of CVCertificate)
    cvc.setSignature(sig);
    return cvc;
  }

  /**
   * Generates a CVCAuthenticatedRequest using BouncyCastle as signature
   * provider.
   *
   * @param cvcRequest req
   * @param keyPair key
   * @param algorithmName name
   * @param caRef Should be the same as caRef in the supplied cvcRequest but
   *     with an incremented sequence number
   * @return req
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
 * @throws ConstructionException fail
   */
  public static CVCAuthenticatedRequest createAuthenticatedRequest(
      final CVCertificate cvcRequest,
      final KeyPair keyPair,
      final String algorithmName,
      final CAReferenceField caRef)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {
    return createAuthenticatedRequest(
        cvcRequest, keyPair, algorithmName, caRef, "BC");
  }

  /**
   * Same as above except that signature provider is an argument.
   *
   * @param cvcRequest cvc
   * @param keyPair key
   * @param algorithmName algo
   * @param caRef ref
   * @param signProvider prov
   * @return req
   * @throws IOException fail
   * @throws NoSuchAlgorithmException fail
   * @throws NoSuchProviderException fail
   * @throws InvalidKeyException fail
   * @throws SignatureException fail
   * @throws ConstructionException fail
   */
  public static CVCAuthenticatedRequest createAuthenticatedRequest(
      final CVCertificate cvcRequest,
      final KeyPair keyPair,
      final String algorithmName,
      final CAReferenceField caRef,
      final String signProvider)
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException, SignatureException, ConstructionException {

    CVCAuthenticatedRequest authRequest =
        new CVCAuthenticatedRequest(cvcRequest, caRef);

    // Perform the signing
    Signature outerSign =
        Signature.getInstance(
            AlgorithmUtil.convertAlgorithmNameToCVC(algorithmName),
            signProvider);
    outerSign.initSign(keyPair.getPrivate());
    outerSign.update(authRequest.getTBS());
    byte[] signdata = outerSign.sign();

    // Now convert the X9.62 signature to a CVC signature
    byte[] sig = BCECUtil.convertX962SigToCVC(algorithmName, signdata);

    // Create and return the CVCAuthenticatedRequest
    authRequest.setSignature(sig);
    return authRequest;
  }
}
