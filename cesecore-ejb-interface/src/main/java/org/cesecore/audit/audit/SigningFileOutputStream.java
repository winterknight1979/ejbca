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
package org.cesecore.audit.audit;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64Util;

/**
 * Wrapper of a FileOutputStream that also produces a signature for the same
 * data that was written to disk. This way we know that we are not signing
 * manipulated data read back from the disk.
 *
 * <p>The signature is written as raw data to a separate file with the extension
 * ".sig".
 *
 * @version $Id: SigningFileOutputStream.java 27947 2018-01-15 14:20:08Z
 *     mikekushner $
 */
/* TODO: Rename/move to org.cesecore.audit.impl.BasicSigningFileOutputStream
 * TODO: Extract reasonable interface to allow different implementations.
 * TODO: Perhaps pass properties from config?
 */
public class SigningFileOutputStream extends FileOutputStream {

      /** Config. */
  public static final String EXPORT_SIGN_CERT = "cert";
  /** Config. */
  public static final String EXPORT_SIGN_ALG = "alg";
  /** Config. */
  public static final String EXPORT_SIGN_KEYALIAS = "key";

  /** Sig. */
  private final Signature signature;
  /** Validate. */
  private final Signature signValidate;
  /** Filename. */
  private final String signatureFilename;

  /**
   * Generates a signature file with the same name as the export file but with
   * .sig extension.
   *
   * @param file the exported file.
   * @param cryptoToken the crypto token that will be used to fetch the
   *     necessary keys.
   * @param signatureDetails Set properties containing signature details like
   *     keyAlias(EXPORT_SIGN_KEYALIAS), algorithm(EXPORT_SIGN_ALG) and
   *     certificate( EXPORT_SIGN_CERT ).
   * @throws FileNotFoundException If signature file not found
   * @throws CryptoTokenOfflineException If offline
   * @throws NoSuchAlgorithmException If algorithm not found
   * @throws NoSuchProviderException If provider not found
   * @throws InvalidKeyException If key is invalid
   */
  public SigningFileOutputStream(
      final File file,
      final CryptoToken cryptoToken,
      final Map<String, Object> signatureDetails)
      throws FileNotFoundException, CryptoTokenOfflineException,
          NoSuchAlgorithmException, NoSuchProviderException,
          InvalidKeyException {
    super(file);
    signatureFilename =
        String.format(
            "%s.sig", FilenameUtils.removeExtension(file.getAbsolutePath()));
    final String keyAlias =
        (String)
            signatureDetails.get(SigningFileOutputStream.EXPORT_SIGN_KEYALIAS);
    final PrivateKey privateKey = cryptoToken.getPrivateKey(keyAlias);
    final PublicKey publicKey = cryptoToken.getPublicKey(keyAlias);
    final String algorithm =
        (String) signatureDetails.get(SigningFileOutputStream.EXPORT_SIGN_ALG);
    signature =
        Signature.getInstance(algorithm, cryptoToken.getSignProviderName());
    signature.initSign(privateKey);
    signValidate =
        Signature.getInstance(algorithm, cryptoToken.getSignProviderName());
    final Certificate cert =
        (Certificate)
            signatureDetails.get(SigningFileOutputStream.EXPORT_SIGN_CERT);
    if (cert != null) {
      signValidate.initVerify(cert);
    } else {
      signValidate.initVerify(publicKey);
    }
  }

  @Override
  public void write(final byte[] b) throws IOException {
    super.write(b);
    try {
      signature.update(b);
      signValidate.update(b);
    } catch (SignatureException e) {
      throw new IOException(e);
    }
  }

  @Override
  public void write(final int b) throws IOException {
    super.write(b);
    try {
      signature.update((byte) b);
      signValidate.update((byte) b);
    } catch (SignatureException e) {
      throw new IOException(e);
    }
  }

  @Override
  public void write(final byte[] b, final int off, final int len)
      throws IOException {
    super.write(b, off, len);
    try {
      signature.update(b, off, len);
      signValidate.update(b, off, len);
    } catch (SignatureException e) {
      throw new IOException(e);
    }
  }

  /**
   * @return Sig
   * @throws SignatureException Fail
   * @throws AuditLogExporterException Fail
   * @throws IOException Fail
   */
  public String writeSignature()
      throws SignatureException, AuditLogExporterException, IOException {
    byte[] signedData = signature.sign();
    if (!signValidate.verify(signedData)) {
      throw new AuditLogExporterException("export file signature mismatch");
    }
    FileUtils.writeStringToFile(
        new File(signatureFilename),
        new String(Base64Util.encode(signedData)),
        Charset.defaultCharset());
    return signatureFilename;
  }
}
