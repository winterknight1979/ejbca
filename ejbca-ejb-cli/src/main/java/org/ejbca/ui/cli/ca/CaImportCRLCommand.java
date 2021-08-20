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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.EJBUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Imports a CRL file to the database.
 *
 * @version $Id: CaImportCRLCommand.java 29401 2018-06-28 12:09:06Z andresjakobs
 *     $
 */
public class CaImportCRLCommand extends BaseCaAdminCommand {
/** Logger. */
  private static final Logger LOG = Logger.getLogger(CaImportCRLCommand.class);

  /** Param. */
  public static final String MISSING_USERNAME_PREFIX =
      "*** Missing During CRL Import to: ";

  /** Param. */
  private static final String STRICT_OP = "STRICT";
  /** Param. */
  private static final String LENIENT_OP = "LENIENT";
  /** Param. */
  private static final String ADAPTIVE_OP = "ADAPTIVE";

  /** Param. */
  private static final String CA_NAME_KEY = "--caname";
  /** Param. */
  private static final String CRL_FILE_KEY = "-f";
  /** Param. */
  private static final String OPERATION_KEY = "-o";

  {
    registerParameter(
        new Parameter(
            CA_NAME_KEY,
            "CA Name",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "Name of the issuing CA."));
    registerParameter(
        new Parameter(
            CRL_FILE_KEY,
            "Filename",
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "The file containing the CRL."));
    registerParameter(
        new Parameter(
            OPERATION_KEY,
            STRICT_OP + "|" + LENIENT_OP + "|" + ADAPTIVE_OP,
            MandatoryMode.MANDATORY,
            StandaloneMode.ALLOW,
            ParameterMode.ARGUMENT,
            "Operations mode. Must be one of "
                + STRICT_OP
                + ", "
                + LENIENT_OP
                + " or "
                + ADAPTIVE_OP
                + "."));
  }

  @Override
  public String getMainCommand() {
    return "importcrl";
  }

  @Override
  public CommandResult execute(final ParameterContainer parameters) {
    LOG.trace(">execute()");
    CryptoProviderUtil.installBCProvider();

    try {
      // Parse arguments
      final String caname = parameters.get(CA_NAME_KEY);
      final String crlFile = parameters.get(CRL_FILE_KEY);
      final String operationsMode = parameters.get(OPERATION_KEY);
      final boolean strict = operationsMode.equalsIgnoreCase(STRICT_OP);
      final boolean adaptive = operationsMode.equalsIgnoreCase(ADAPTIVE_OP);
      if (!strict
          && !adaptive
          && !operationsMode.equalsIgnoreCase(LENIENT_OP)) {
        // None of the above.
        LOG.error(
            "Operations mode must be one of "
                + STRICT_OP
                + ", "
                + LENIENT_OP
                + " or "
                + ADAPTIVE_OP
                + ".");
        return CommandResult.CLI_FAILURE;
      }
      // Fetch CA and related info
      final CAInfo cainfo = getCAInfo(getAuthenticationToken(), caname);
      if (cainfo == null) {
        LOG.error("CA by name of " + caname + " could not be found.");
        return CommandResult.FUNCTIONAL_FAILURE;
      }
      final X509Certificate cacert =
          (X509Certificate) cainfo.getCertificateChain().iterator().next();
      final String issuer =
          CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
      LOG.info("CA: " + issuer);
      // Read the supplied CRL and verify that it is issued by the specified CA
      final X509CRL x509crl =
          (X509CRL)
              CertTools.getCertificateFactory()
                  .generateCRL(new FileInputStream(crlFile));
      if (!x509crl
          .getIssuerX500Principal()
          .equals(cacert.getSubjectX500Principal())) {
        throw new IOException("CRL wasn't issued by this CA");
      }
      x509crl.verify(cacert.getPublicKey());
      int crlNo = CrlExtensions.getCrlNumber(x509crl).intValue();
      LOG.info("Processing CRL #" + crlNo);
      int missCount = 0; // Number of certs not already in database
      int revoked = 0; // Number of certs activly revoked by this algorithm
      int alreadyRevoked =
          0; // Number of certs already revoked in database and ignored in
             // non-strict mode
      final String missingUserName = MISSING_USERNAME_PREFIX + caname;
      @SuppressWarnings("unchecked")
      Set<X509CRLEntry> entries =
          (Set<X509CRLEntry>) x509crl.getRevokedCertificates();
      if (entries != null) {
        for (final X509CRLEntry entry : entries) {
          final BigInteger serialNr = entry.getSerialNumber();
          final String serialHex = serialNr.toString(16).toUpperCase();
          final String username =
              EjbRemoteHelper.INSTANCE
                  .getRemoteSession(CertificateStoreSessionRemote.class)
                  .findUsernameByCertSerno(serialNr, issuer);
          // If this certificate exists and has an assigned username, we keep
          // using that. Otherwise we create this coupling to a user.
          if (username == null) {
            LOG.info("Certificate '" + serialHex + "' missing in the database");
            if (strict) {
              throw new IOException(
                  "Aborted! Running in strict mode and is missing certificate"
                      + " in database.");
            }
            missCount++;
            if (!adaptive) {
              continue;
            }
            final Date time =
                new Date(); // time from which certificate is valid
            final KeyPair keyPair =
                KeyUtil.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);

            final SubjectPublicKeyInfo pkinfo =
                SubjectPublicKeyInfo.getInstance(
                    keyPair.getPublic().getEncoded());
            final X500Name dnName =
                new X500Name(
                    "CN=Dummy Missing in Imported CRL, serialNumber="
                        + serialHex);
            final Date notAfter =
                new Date(
                    time.getTime()
                        + 1000L * 60 * 60 * 24 * 365 * 10); // 10 years of life
            final X509v3CertificateBuilder certbuilder =
                new X509v3CertificateBuilder(
                    X500Name.getInstance(
                        cacert.getSubjectX500Principal().getEncoded()),
                    serialNr,
                    time,
                    notAfter,
                    dnName,
                    pkinfo);
            final ContentSigner signer =
                new BufferingContentSigner(
                    new JcaContentSignerBuilder("SHA1withRSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()),
                    20480);
            final X509CertificateHolder certHolder = certbuilder.build(signer);
            final X509Certificate certificate =
                CertTools.getCertfromByteArray(
                    certHolder.getEncoded(), X509Certificate.class);

            final String fingerprint =
                CertTools.getFingerprintAsString(certificate);
            // We add all certificates that does not have a user already to
            // "missing_user_name"
            final EndEntityInformation missingUserEndEntityInformation =
                EjbRemoteHelper.INSTANCE
                    .getRemoteSession(EndEntityAccessSessionRemote.class)
                    .findUser(getAuthenticationToken(), missingUserName);
            if (missingUserEndEntityInformation == null) {
              // Add the user and change status to REVOKED
              LOG.debug("Loading/updating user " + missingUserName);
              final EndEntityInformation userdataNew =
                  new EndEntityInformation(
                      missingUserName,
                      CertTools.getSubjectDN(certificate),
                      cainfo.getCAId(),
                      null,
                      null,
                      EndEntityConstants.STATUS_NEW,
                      new EndEntityType(EndEntityTypes.ENDUSER),
                      EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                      CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                      null,
                      null,
                      SecConst.TOKEN_SOFT_BROWSERGEN,
                      SecConst.NO_HARDTOKENISSUER,
                      null);
              userdataNew.setPassword("foo123");
              EjbRemoteHelper.INSTANCE
                  .getRemoteSession(EndEntityManagementSessionRemote.class)
                  .addUser(getAuthenticationToken(), userdataNew, false);
              LOG.info("User '" + missingUserName + "' has been added.");
              EjbRemoteHelper.INSTANCE
                  .getRemoteSession(EndEntityManagementSessionRemote.class)
                  .setUserStatus(
                      getAuthenticationToken(),
                      missingUserName,
                      EndEntityConstants.STATUS_REVOKED);
              LOG.info("User '" + missingUserName + "' has been updated.");
            }
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(CertificateStoreSessionRemote.class)
                .storeCertificateRemote(
                    getAuthenticationToken(),
                    EJBUtil.wrap(certificate),
                    missingUserName,
                    fingerprint,
                    CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    EndEntityConstants.NO_END_ENTITY_PROFILE,
                    null,
                    new Date().getTime());
            LOG.info("Dummy certificate  '" + serialHex + "' has been stored.");
          }
          // This check will not catch a certificate with status
          // CertificateConstants.CERT_ARCHIVED
          if (!strict
              && EjbRemoteHelper.INSTANCE
                  .getRemoteSession(CertificateStoreSessionRemote.class)
                  .isRevoked(issuer, serialNr)) {
            LOG.info("Certificate '" + serialHex + "' is already revoked");
            alreadyRevoked++;
            continue;
          }
          LOG.info(
              "Revoking '"
                  + serialHex
                  + "' "
                  + "("
                  + serialNr.toString()
                  + ")");
          try {
            int reason = getCRLReasonValue(entry);
            LOG.info("Reason code: " + reason);
            EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityManagementSessionRemote.class)
                .revokeCert(
                    getAuthenticationToken(),
                    serialNr,
                    entry.getRevocationDate(),
                    issuer,
                    reason,
                    false);
            revoked++;
          } catch (AlreadyRevokedException e) {
            alreadyRevoked++;
            LOG.warn(
                "Failed to revoke '"
                    + serialHex
                    + "'. (Status might be 'Archived'.) Error message was: "
                    + e.getMessage());
          }
        }
      } // if (entries != null)
      if (EjbRemoteHelper.INSTANCE
              .getRemoteSession(CrlStoreSessionRemote.class)
              .getLastCRLNumber(issuer, false)
          < crlNo) {
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(CrlStoreSessionRemote.class)
            .storeCRL(
                getAuthenticationToken(),
                x509crl.getEncoded(),
                CertTools.getFingerprintAsString(cacert),
                crlNo,
                issuer,
                x509crl.getThisUpdate(),
                x509crl.getNextUpdate(),
                -1);
      } else {
        if (strict) {
          throw new IOException(
              "CRL #" + crlNo + " or higher is already in the database");
        }
      }
      LOG.info("\nSummary:\nRevoked " + revoked + " certificates");
      if (alreadyRevoked > 0) {
        LOG.info(alreadyRevoked + " certificates were already revoked");
      }
      if (missCount > 0) {
        LOG.info(
            "There were "
                + missCount
                + (adaptive
                    ? " dummy certificates added to"
                    : " certificates missing in")
                + " the database");
      }
      LOG.info("CRL #" + crlNo + " stored in the database");
    } catch (Exception e) {
      // FIXME: This is all kinds of suboptimal.
      LOG.info("Error: " + e.getMessage());
      return CommandResult.FUNCTIONAL_FAILURE;
    }
    LOG.trace("<execute()");
    return CommandResult.SUCCESS;
  }

  /**
   * Return a CRL reason code from a CRL entry, or
   * RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED if a reson code extension
   * does not exist.
   *
   * @param entry Entry
   * @return Value
   * @throws IOException Fail
   */
  private int getCRLReasonValue(final X509CRLEntry entry) throws IOException {
    int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
    if ((entry != null) && entry.hasExtensions()) {
      final byte[] bytes =
          entry.getExtensionValue(Extension.reasonCode.getId());
      if (bytes != null) {
        ASN1InputStream aIn =
            new ASN1InputStream(new ByteArrayInputStream(bytes));
        final ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        final ASN1Primitive obj = aIn.readObject();
        if (obj != null) {
          try {
            final ASN1Enumerated ext = (ASN1Enumerated) obj;
            reason = ext.getValue().intValue();
          } catch (ClassCastException e) {
            // this was not a reason code, very strange
            LOG.info(
                "Reason code extension did not contain DEREnumerated, is this"
                    + " CRL corrupt?. "
                    + obj.getClass().getName());
          }
        }
      }
    }
    return reason;
  } // getCRLReasonValue

  @Override
  public String getCommandDescription() {
    return "Imports a CRL file (and updates certificates) to the database";
  }

  @Override
  public String getFullHelpText() {
    StringBuilder sb = new StringBuilder();
    sb.append(getCommandDescription() + "\n");
    sb.append("Operation modes: \n");
    sb.append(
        "    "
            + STRICT_OP
            + " means that all certificates must be in the database and that"
            + " the CRL must not already be in the database.\n");
    sb.append(
        "    "
            + LENIENT_OP
            + " means not strict and not adaptive, i.e. all certificates must"
            + " not be in the database, but no dummy certificates will be"
            + " created.\n");
    sb.append(
        "    "
            + ADAPTIVE_OP
            + " means that missing certficates will be replaced by dummy"
            + " certificates to cater for proper CRLs for missing"
            + " certificates.\n");
    sb.append(" Existing CAs: " + getAvailableCasString());
    return sb.toString();
  }

  @Override
  protected Logger getLogger() {
    return LOG;
  }
}
