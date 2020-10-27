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

package org.ejbca.util.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * JKStoPEM is used to export PEM files from a single jks file. The class
 * exports the user certificate, user private key in seperated files and the
 * chain of sub ca and ca certifikate in a third file. The PEM files will have
 * the names <i>common name</i>.pem, <i>common name</i>Key.pem and <i>common
 * name</i>CA.pem derived from the DN in user certificate.
 *
 * @version $Id: JKStoPEM.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class JKStoPEM {
      /** param. */
  private String exportpath = "./p12/pem/";
  /** param. */
  private String jksFile;
  /** param. */
  private String password;
  /** param. */
  private String keypass;
  /** param. */
  private KeyStore ks = null;
  /** param. */
  private boolean overwrite = false;
  /** Constant. */
  private final byte[] beginCertificate =
          "-----BEGIN CERTIFICATE-----".getBytes();
  /** Constant. */
  private final byte[] endCertificate =
          "-----END CERTIFICATE-----".getBytes();
  /** Constant. */
  private final byte[] beginPrivateKey =
          "-----BEGIN PRIVATE KEY-----".getBytes();
  /** Constant. */
  private final byte[] endPrivateKey =
          "-----END PRIVATE KEY-----".getBytes();
  /** Constant. */
  private static final byte[] NL = "\n".getBytes();

  /**
   * DOCUMENT ME!
   *
   * @param args DOCUMENT ME!
   */
  public static void main(final String[] args) {

    // Bouncy Castle security provider
    CryptoProviderTools.installBCProvider();

    JKStoPEM jks = null;
    final int maxArgs = 4;
    try {
      if (args.length > maxArgs) {
        boolean overwrite = false;

        if (args[maxArgs].equalsIgnoreCase("true")) {
          overwrite = true;
        }

        jks = new JKStoPEM(args[0], args[1], args[2], args[maxArgs - 1],
                overwrite);
      } else if (args.length > maxArgs - 1) {
        jks = new JKStoPEM(args[0], args[1], args[2], args[maxArgs - 1]);
      } else {
        System.out.println(
            "Usage: JKStoPEM <jksFile> <jkspassword> <keypassword> <outpath>"
                + " [overwrite (true/false)(default false)]");
        System.exit(0); // NOPMD this is a cli command
      }

      jks.createPEM();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * Basic construtor for the JKStoPEM class, set variables for the class.
   *
   * @param ajksFile jksFile The (path +) name of the input jks file.
   * @param apassword password The password for the jks file.
   * @param akeypass Key
   * @param anoutpath Out
   */
  public JKStoPEM(
      final String ajksFile,
      final String apassword,
      final String akeypass,
      final String anoutpath) {
    this.jksFile = ajksFile;
    this.password = apassword;
    this.keypass = akeypass;
    exportpath = anoutpath;
  }

  /**
   * Basic constructor using an in memory KeyStore instead for a file.
   *
   * @param akeystore the KeyStore to use.
   * @param apassword password The password for the jks file.
   * @param akeypass Key
   * @param anoutpath Out
   * @param dooverwrite overwrite If existing files should be overwritten.
   */
  public JKStoPEM(
      final KeyStore akeystore,
      final String apassword,
      final String akeypass,
      final String anoutpath,
      final boolean dooverwrite) {
    this.password = apassword;
    this.ks = akeystore;
    this.keypass = akeypass;
    exportpath = anoutpath;
    this.overwrite = dooverwrite;
  }

  /**
   * Sets the directory where PEM-files wil be stores.
   *
   * @param path path where PEM-files will be stores
   */
  public void setExportPath(final String path) {
    exportpath = path;
  }

  /**
   * Constructor for the JKStoPEM class.
   *
   * @param ajksFile jksFile The (path +) name of the input jks file.
   * @param apassword password The password for the jks file.
   * @param akeypass Key
   * @param anoutpath Out
   * @param dooverwrite overwrite If existing files should be overwritten.
   */
  public JKStoPEM(
      final String ajksFile,
      final String apassword,
      final String akeypass,
      final String anoutpath,
      final boolean dooverwrite) {
    this.jksFile = ajksFile;
    this.password = apassword;
    this.overwrite = dooverwrite;
    this.keypass = akeypass;
    exportpath = anoutpath;
  }

  /**
   * DOCUMENT ME!
   *
   * @throws KeyStoreException DOCUMENT ME!
   * @throws FileNotFoundException DOCUMENT ME!
   * @throws IOException DOCUMENT ME!
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws CertificateEncodingException DOCUMENT ME!
   * @throws CertificateException DOCUMENT ME!
   * @throws UnrecoverableKeyException DOCUMENT ME!
   */
  public void createPEM()
      throws KeyStoreException, FileNotFoundException, IOException,
          NoSuchAlgorithmException, CertificateEncodingException,
          CertificateException, UnrecoverableKeyException {

    if (this.ks == null) {
      ks = KeyStore.getInstance("JKS");
      InputStream in = new FileInputStream(jksFile);
      ks.load(in, password.toCharArray());
      in.close();
    }
    // Find the key private key entry in the keystore
    Enumeration<String> e = ks.aliases();
    Object o = null;
    PrivateKey serverPrivKey = null;

    while (e.hasMoreElements()) {
      o = e.nextElement();

      if (o instanceof String) {
          if ((ks.isKeyEntry((String) o))) {
              serverPrivKey =
                 (PrivateKey) ks.getKey((String) o, keypass.toCharArray());
              if (serverPrivKey != null) {
                  break;
              }
          }
      }
    }

    byte[] privKeyEncoded = "".getBytes();

    if (serverPrivKey != null) {
      privKeyEncoded = serverPrivKey.getEncoded();
    }

    // Certificate chain[] = ks.getCertificateChain((String) o);
    Certificate[] chain = KeyTools.getCertChain(ks, (String) o);

    X509Certificate userX509Certificate = (X509Certificate) chain[0];

    byte[] output = userX509Certificate.getEncoded();
    String sn = CertTools.getSubjectDN(userX509Certificate);
    String userFile = CertTools.getPartFromDN(sn, "CN");
    String filetype = ".pem";

    File path = new File(exportpath);
    path.mkdir();

    File tmpFile = new File(path, userFile + filetype);

    if (!overwrite) {
      if (tmpFile.exists()) {
        System.out.println(
            "File '" + tmpFile + "' already exists, don't overwrite.");

        return;
      }
    }

    OutputStream out = new FileOutputStream(tmpFile);
    out.write(beginCertificate);
    out.write(NL);

    byte[] userCertB64 = Base64.encode(output);
    out.write(userCertB64);
    out.write(NL);
    out.write(endCertificate);
    out.close();

    tmpFile = new File(path, userFile + "-Key" + filetype);

    if (!overwrite) {
      if (tmpFile.exists()) {
        System.out.println(
            "File '" + tmpFile + "' already exists, don't overwrite.");

        return;
      }
    }

    out = new FileOutputStream(tmpFile);
    out.write(beginPrivateKey);
    out.write(NL);

    byte[] privKey = Base64.encode(privKeyEncoded);
    out.write(privKey);
    out.write(NL);
    out.write(endPrivateKey);
    out.close();

    tmpFile = new File(path, userFile + "-CA" + filetype);

    if (!overwrite) {
      if (tmpFile.exists()) {
        System.out.println(
            "File '" + tmpFile + "' already exists, don't overwrite.");

        return;
      }
    }

    if (CertTools.isSelfSigned(userX509Certificate)) {
      System.out.println(
          "User certificate is selfsigned, this is a RootCA, no CA"
              + " certificates written.");
    } else {
      out = new FileOutputStream(tmpFile);

      for (int num = 1; num < chain.length; num++) {
        X509Certificate tmpX509Cert = (X509Certificate) chain[num];
        byte[] tmpOutput = tmpX509Cert.getEncoded();
        out.write(beginCertificate);
        out.write(NL);

        byte[] tmpCACertB64 = Base64.encode(tmpOutput);
        out.write(tmpCACertB64);
        out.write(NL);
        out.write(endCertificate);
        out.write(NL);
      }
      out.close();
    }
  } // createPEM
} // JKStoPEM
