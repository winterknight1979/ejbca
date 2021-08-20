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

package org.ejbca.ui.cli.ca;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;

/**
 * Base for CA commands, contains common functions for CA operations.
 *
 * @version $Id: BaseCaAdminCommand.java 27740 2018-01-05 07:24:53Z mikekushner
 *     $
 */
public abstract class BaseCaAdminCommand extends EjbcaCliUserCommandBase {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(BaseCaAdminCommand.class);
  /** Param. */
  protected static final String MAINCOMMAND = "ca";

  /** Param. */
  protected static final String DEF_SUPERADMIN_CN = "SuperAdmin";

  /** Private key alias in PKCS12 keystores. */
  protected String privKeyAlias = "privateKey";

  /**
   * PARAM.
   */
  protected char[] privateKeyPass = null;

  @Override
  public String[] getCommandPath() {
    return new String[] {MAINCOMMAND};
  }

  /**
   * Retrieves the complete certificate chain from the CA.
   *
   * @param authenticationToken token
   * @param caname human readable name of CA
   * @return a Collection of certificates
   */
  protected Collection<Certificate> getCertChain(
      final AuthenticationToken authenticationToken, final String caname) {
    LOG.trace(">getCertChain()");
    Collection<Certificate> returnval = new ArrayList<Certificate>();
    try {
      CAInfo cainfo =
          EjbRemoteHelper.INSTANCE
              .getRemoteSession(CaSessionRemote.class)
              .getCAInfo(authenticationToken, caname);
      if (cainfo != null) {
        returnval = cainfo.getCertificateChain();
      }
    } catch (Exception e) {
      LOG.error("Error while getting certfificate chain from CA.", e);
    }
    LOG.trace("<getCertChain()");
    return returnval;
  }

  /**
   * @param dn DN
   * @param rsaKeys Keys
   * @param reqfile Req
   * @throws NoSuchAlgorithmException FAil
   * @throws IOException FAil
   * @throws NoSuchProviderException Fail
   * @throws InvalidKeyException Fail
   * @throws SignatureException Fail
   * @throws OperatorCreationException Fail
   * @throws PKCSException Fail
   */
  protected void makeCertRequest(
      final String dn, final KeyPair rsaKeys, final String reqfile)
      throws NoSuchAlgorithmException, IOException, NoSuchProviderException,
          InvalidKeyException, SignatureException, OperatorCreationException,
          PKCSException {
    LOG.trace(">makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");

    PKCS10CertificationRequest req =
        CertTools.genPKCS10CertificationRequest(
            "SHA1WithRSA",
            CertTools.stringToBcX500Name(dn),
            rsaKeys.getPublic(),
            new DERSet(),
            rsaKeys.getPrivate(),
            null);

    /*
     * We don't use these unnecessary attributes DERConstructedSequence kName
     * = new DERConstructedSequence(); DERConstructedSet kSeq = new
     * DERConstructedSet();
     * kName.addObject(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
     * kSeq.addObject(new DERIA5String("foo@bar.se"));
     * kName.addObject(kSeq); req.setAttributes(kName);
     */
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    ASN1OutputStream dOut =
            ASN1OutputStream.create(bOut, ASN1Encoding.DER);
    dOut.writeObject(req.toASN1Structure());
    dOut.close();

    PKCS10CertificationRequest req2 =
        new PKCS10CertificationRequest(bOut.toByteArray());
    ContentVerifierProvider contentVerifier =
        CertTools.genContentVerifierProvider(rsaKeys.getPublic());
    boolean verify = req2.isSignatureValid(contentVerifier); // req2.verify();
    LOG.info("Verify returned " + verify);

    if (!verify) {
      LOG.info("Aborting!");
      return;
    }

    FileOutputStream os1 = new FileOutputStream(reqfile);
    os1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
    os1.write(Base64Util.encode(bOut.toByteArray()));
    os1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
    os1.close();
    LOG.info("CertificationRequest '" + reqfile + "' generated successfully.");
    LOG.trace("<makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");
  }

  /**
   * @param issuerdn DN
   * @param deltaCRL Bool
   */
  protected void createCRL(final String issuerdn, final boolean deltaCRL) {
    LOG.trace(">createCRL()");
    try {
      if (issuerdn != null) {
        CAInfo cainfo =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(CaSessionRemote.class)
                .getCAInfo(getAuthenticationToken(), issuerdn.hashCode());
        if (!deltaCRL) {
          EjbRemoteHelper.INSTANCE
              .getRemoteSession(PublishingCrlSessionRemote.class)
              .forceCRL(getAuthenticationToken(), cainfo.getCAId());
          int number =
              EjbRemoteHelper.INSTANCE
                  .getRemoteSession(CrlStoreSessionRemote.class)
                  .getLastCRLNumber(issuerdn, false);
          LOG.info("CRL with number " + number + " generated.");
        } else {
          EjbRemoteHelper.INSTANCE
              .getRemoteSession(PublishingCrlSessionRemote.class)
              .forceDeltaCRL(getAuthenticationToken(), cainfo.getCAId());
          int number =
              EjbRemoteHelper.INSTANCE
                  .getRemoteSession(CrlStoreSessionRemote.class)
                  .getLastCRLNumber(issuerdn, true);
          LOG.info("Delta CRL with number " + number + " generated.");
        }
      } else {
        int createdcrls =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(PublishingCrlSessionRemote.class)
                .createCRLs(getAuthenticationToken());
        LOG.info("  " + createdcrls + " CRLs have been created.");
        int createddeltacrls =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(PublishingCrlSessionRemote.class)
                .createDeltaCRLs(getAuthenticationToken());
        LOG.info("  " + createddeltacrls + " delta CRLs have been created.");
      }
    } catch (Exception e) {
      LOG.error("Error while creating CRL for CA: " + issuerdn, e);
    }
    LOG.trace(">createCRL()");
  }

  /**
   * @param authenticationToken Token
   * @param caname NAme
   * @return DN
   * @throws CADoesntExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  protected String getIssuerDN(
      final AuthenticationToken authenticationToken, final String caname)
      throws CADoesntExistsException, AuthorizationDeniedException {
    CAInfo cainfo =
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(CaSessionRemote.class)
            .getCAInfo(authenticationToken, caname);
    return cainfo != null ? cainfo.getSubjectDN() : null;
  }

  /**
   * @param authenticationToken Token
   * @param caname Name
   * @return Info
   */
  protected CAInfo getCAInfo(
      final AuthenticationToken authenticationToken, final String caname) {
    CAInfo result = null;
    try {
      result =
          EjbRemoteHelper.INSTANCE
              .getRemoteSession(CaSessionRemote.class)
              .getCAInfo(authenticationToken, caname);
    } catch (AuthorizationDeniedException e) {
      LOG.error("Authorization denied", e);
    }
    if (result == null) {
      LOG.debug("CA " + caname + " not found.");
    }
    return result;
  }

  /**   *
   * @param authenticationToken tOKEN
   * @param caid CA
   * @param superAdminCN CN
   * @throws AuthorizationDeniedException Fail
   */
  protected void initAuthorizationModule(
      final AuthenticationToken authenticationToken,
      final int caid,
      final String superAdminCN)
      throws AuthorizationDeniedException {
    if (superAdminCN == null) {
      LOG.info("Not initializing authorization module.");
    } else {
      LOG.info(
          "Initalizing authorization module with caid="
              + caid
              + " and superadmin CN '"
              + superAdminCN
              + "'.");
    }
    EjbRemoteHelper.INSTANCE
        .getRemoteSession(AuthorizationSystemSessionRemote.class)
        .initializeAuthorizationModuleWithSuperAdmin(
            authenticationToken, caid, superAdminCN);
  }

  /**
   * @return CAS string
   */
  protected String getAvailableCasString() {
    // List available CAs by name
    final StringBuilder existingCas = new StringBuilder();
    try {
      for (final Integer nextId
          : EjbRemoteHelper.INSTANCE
              .getRemoteSession(CaSessionRemote.class)
              .getAuthorizedCaIds(getAuthenticationToken())) {
        final String caName =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(CaSessionRemote.class)
                .getCAInfo(getAuthenticationToken(), nextId.intValue())
                .getName();
        if (existingCas.length() > 0) {
          existingCas.append(", ");
        }
        existingCas.append("\"").append(caName).append("\"");
      }
    } catch (Exception e) {
      existingCas.append("<unable to fetch available CA(s)>");
    }
    return existingCas.toString();
  }

  /**   *
   * @param endentityAccessRule Rule
   * @return Eeps String
   */
  protected String getAvailableEepsString(final String endentityAccessRule) {
    // List available EndEntityProfiles by name
    final StringBuilder availableEEPs = new StringBuilder();
    try {
      for (final Integer nextId
          : EjbRemoteHelper.INSTANCE
              .getRemoteSession(EndEntityProfileSessionRemote.class)
              .getAuthorizedEndEntityProfileIds(
                  getAuthenticationToken(), endentityAccessRule)) {
        final String eepName =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityProfileSessionRemote.class)
                .getEndEntityProfileName(nextId.intValue());
        if (availableEEPs.length() > 0) {
          availableEEPs.append(", ");
        }
        availableEEPs.append("\"").append(eepName).append("\"");
      }
    } catch (Exception e) {
      availableEEPs.append("<unable to fetch available End Entity Profile(s)>");
    }
    return availableEEPs.toString();
  }

  /**
   * @return CPS String
   */
  protected String getAvailableEndUserCpsString() {
    // List available CertificateProfiles by name
    final StringBuilder availableCPs = new StringBuilder();
    try {
      for (final Integer nextId
          : EjbRemoteHelper.INSTANCE
              .getRemoteSession(CertificateProfileSessionRemote.class)
              .getAuthorizedCertificateProfileIds(
                  getAuthenticationToken(),
                  CertificateConstants.CERTTYPE_ENDENTITY)) {
        final String cpName =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(CertificateProfileSessionRemote.class)
                .getCertificateProfileName(nextId.intValue());
        if (availableCPs.length() > 0) {
          availableCPs.append(", ");
        }
        availableCPs.append("\"").append(cpName).append("\"");
      }
    } catch (Exception e) {
      availableCPs.append("<unable to fetch available Certificate Profile(s)>");
    }
    return availableCPs.toString();
  }

  /**
   * @return CA List
   */
  protected String getCaList() {
    final String tab = "    ";
    Collection<Integer> cas =
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(CaSessionRemote.class)
            .getAuthorizedCaIds(getAuthenticationToken());
    String casList = "Available CAs:\n";
    for (Integer caid : cas) {
      CAInfo info;
      try {
        info =
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(CaSessionRemote.class)
                .getCAInfo(getAuthenticationToken(), caid);
        if (info.getStatus() == CAConstants.CA_EXTERNAL) {
          casList += tab + info.getName() + ": External CA\n";
        } else {
          int cryptoTokenId = info.getCAToken().getCryptoTokenId();
          String cryptoTokenName =
              "Current CLI user does not have authorization to Crypto"
                  + " Tokens.\n";
          try {
            CryptoTokenInfo ctInfo =
                EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class)
                    .getCryptoTokenInfo(
                        getAuthenticationToken(), cryptoTokenId);
            if (ctInfo != null) {
              cryptoTokenName = ctInfo.getName();
            } else {
              cryptoTokenName = "ID " + cryptoTokenId;
            }
          } catch (AuthorizationDeniedException e) {
            // NOPMD: ignore, use string above
          }
          casList +=
              tab
                  + info.getName()
                  + ":"
                  + cryptoTokenName
                  + ":"
                  + info.getCAToken().getSignatureAlgorithm()
                  + "\n";
        }
      } catch (AuthorizationDeniedException e) {
        casList = "Current CLI user does not have authorization to any CAs.\n";
        break;
      }
    }
    return casList;
  }
}
