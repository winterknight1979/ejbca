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

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.Callable;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.cesecore.util.StringUtil;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Class implementing logic for importing a certificate from file.
 *
 * @version $Id$
 */
class CertificateImporter implements Callable<CertificateImporter.Result> {
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(CertificateImporter.class);
  // Map Username -> Certificate containing the usernames of end entities
  // currently being
  // processed. If two certificates, belonging to the same end entity, are being
  // imported at the
  // same time, one of these imports will fail with IMPORT_IN_PROGRESS to avoid
  // transaction rollback.
  // TODO Implement this to allow CN or DN to be used as end entity username
  // private static final ConcurrentHashMap<String, File>
  // usernamesBeingProcessed = new ConcurrentHashMap<>();

  /** Param. */
  private File file;
  /** Param. */
  private boolean resumeOnError;
  /** Param. */
  private int status;
  /** Param. */
  private int endEntityProfileId;
  /** Param. */
  private int certificateProfileId;
  /** Param. */
  private Date revocationTime;
  /** Param. */
  private RevocationReasons revocationReason;
  /** Param. */
  private String issuer;
  /** Param. */
  private String usernameFilter;
  /** Param. */
  private X509Certificate caCertificate;
  /** Param. */
  private AuthenticationToken authenticationToken;
  /** Param. */
  private CAInfo caInfo;

  public enum Result {
        /** Result. */
    REDUNDANT,
    /** Result. */
    CA_MISMATCH,
    /** Result. */
    READ_ERROR,
    /** Result. */
    CONSTRAINT_VIOLATION,
    /** Result. */
    GENERAL_IMPORT_ERROR,
    /** Result. */
    IMPORT_OK,
  }

  public CertificateImporter setFileToImport(final File afile) {
    this.file = afile;
    return this;
  }

  public CertificateImporter setResumeOnError(final boolean aresumeOnError) {
    this.resumeOnError = aresumeOnError;
    return this;
  }

  public CertificateImporter setStatus(final int astatus) {
    this.status = astatus;
    return this;
  }

  public CertificateImporter setCertificateProfileId(
      final int acertificateProfileId) {
    this.certificateProfileId = acertificateProfileId;
    return this;
  }

  public CertificateImporter setEndEntityProfileId(
      final int anendEntityProfileId) {
    this.endEntityProfileId = anendEntityProfileId;
    return this;
  }

  public CertificateImporter setRevocationTime(final Date arevocationTime) {
    this.revocationTime = arevocationTime;
    return this;
  }

  public CertificateImporter setRevocationReason(
      final RevocationReasons arevocationReason) {
    this.revocationReason = arevocationReason;
    return this;
  }

  public CertificateImporter setIssuer(final String anissuer) {
    this.issuer = anissuer;
    return this;
  }

  public CertificateImporter setUsernameFilter(final String ausernameFilter) {
    this.usernameFilter = ausernameFilter;
    return this;
  }

  public CertificateImporter setCaCertificate(
      final X509Certificate acaCertificate) {
    this.caCertificate = acaCertificate;
    return this;
  }

  public CertificateImporter setAuthenticationToken(
      final AuthenticationToken anauthenticationToken) {
    this.authenticationToken = anauthenticationToken;
    return this;
  }

  public CertificateImporter setCaInfo(final CAInfo acaInfo) {
    this.caInfo = acaInfo;
    return this;
  }

  private Certificate loadCertificateFromFile(final String filename)
      throws IOException, CertificateParsingException {
    final byte[] bytes =
        FileTools.getBytesFromPEM(
            FileTools.readFiletoBuffer(filename),
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----");
    return CertTools.getCertfromByteArray(bytes, Certificate.class);
  }

  private String getEndEntityUsername(
      final String filename,
      final Certificate certificate,
      final String ausernameFilter) {
    if (StringUtils.equalsIgnoreCase(ausernameFilter, "DN")) {
      // Use the DN if requested, but fall-back to filename if DN is empty.
      final String dn = CertTools.getSubjectDN(certificate);
      if (dn == null || dn.length() == 0) {
        LOG.warn(
            "WARN: Certificate with serial '"
                + CertTools.getSerialNumberAsString(certificate)
                + "' lacks DN, filename used instead, file: "
                + filename);
        return filename;
      } else {
        return dn;
      }
    } else if (StringUtils.equalsIgnoreCase(ausernameFilter, "CN")) {
      // Use CN if requested, but fallback to DN if it's empty, or if DN is
      // empty as well, fall back to filename.
      final String dn = CertTools.getSubjectDN(certificate);
      final String cn = CertTools.getPartFromDN(dn, "CN");
      if (cn == null || cn.length() == 0) {
        if (dn == null || dn.length() == 0) {
          LOG.warn(
              "WARN: Certificate with serial '"
                  + CertTools.getSerialNumberAsString(certificate)
                  + "' lacks both CN and DN, filename used instead, file: "
                  + filename);
          return filename;
        } else {
          LOG.warn(
              "WARN: Certificate with serial '"
                  + CertTools.getSerialNumberAsString(certificate)
                  + "' lacks CN, DN used instead, file: "
                  + filename);
          return dn;
        }
      } else {
        return cn;
      }
    } else {
      // Use the filename as username by default since it's something that's
      // always present.
      return filename;
    }
  }

  private boolean certificateAlreadyExists(final String fingerprint) {
    final CertificateStoreSessionRemote certificateStoreSession =
        EjbRemoteHelper.INSTANCE.getRemoteSession(
            CertificateStoreSessionRemote.class);
    return certificateStoreSession.findCertificateByFingerprintRemote(
            fingerprint)
        != null;
  }

  private boolean certificateIsSignedByCa(
      final X509Certificate certificate, final X509Certificate acaCertificate) {
    try {
      certificate.verify(acaCertificate.getPublicKey());
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private EndEntityInformation getOrCreateUserdata(
      final EndEntityManagementSessionRemote endEntityManagementSession,
      final Certificate certificate,
      final String username)
      throws Exception {
    EndEntityInformation userdata =
        EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityAccessSessionRemote.class)
            .findUser(authenticationToken, username);
    if (userdata != null) {
      // Return the existing user
      return userdata;
    } else {
      // Add a "user" to map this certificate to
      final String subjectAltName =
          CertTools.getSubjectAlternativeName(certificate);
      final String email = CertTools.getEMailAddress(certificate);
      userdata =
          new EndEntityInformation(
              username,
              CertTools.getSubjectDN(certificate),
              caInfo.getCAId(),
              subjectAltName,
              email,
              EndEntityConstants.STATUS_GENERATED,
              new EndEntityType(EndEntityTypes.ENDUSER),
              endEntityProfileId,
              certificateProfileId,
              null,
              null,
              SecConst.TOKEN_SOFT_BROWSERGEN,
              SecConst.NO_HARDTOKENISSUER,
              null);
      userdata.setPassword("foo123");
      endEntityManagementSession.addUser(authenticationToken, userdata, false);
      LOG.info("User '" + username + "' has been added.");
      return userdata;
    }
  }

  @Override
  public CertificateImporter.Result call() throws Exception {
    try {
      // TODO Support for CVC certificates?
      final X509Certificate certificate =
          (X509Certificate) loadCertificateFromFile(file.getCanonicalPath());
      final String fingerprint = CertTools.getFingerprintAsString(certificate);

      if (certificateAlreadyExists(fingerprint)) {
        LOG.info(
            "SKIP: Certificate with serial '"
                + CertTools.getSerialNumberAsString(certificate)
                + "' is already present, file: "
                + file.getName());
        return Result.REDUNDANT;
      }

      // Strip the username of dangerous characters before using it.
      final String username =
          StringUtil.stripUsername(
              getEndEntityUsername(
                  file.getName(), certificate, usernameFilter));
      final Date now = new Date();

      if (CertTools.getNotAfter(certificate).compareTo(now) < 0) {
        // Certificate has expired, but we are obviously keeping it for archival
        // purposes
        status = CertificateConstants.CERT_ARCHIVED;
      }

      if (!caCertificate
          .getSubjectX500Principal()
          .equals(certificate.getIssuerX500Principal())) {
        LOG.error(
            "ERROR: The certificates issuer subject DN does not match with the"
                + " specified CA's subject DN, file: "
                + file.getName());
        return Result.CA_MISMATCH;
      }

      if (!certificateIsSignedByCa(certificate, caCertificate)) {
        LOG.error(
            "ERROR: The certificate's signature does not validate against the"
                + " specified CA, file: "
                + file.getName());
        return Result.CA_MISMATCH;
      }

      LOG.debug("Loading/updating user " + username);
      final EndEntityManagementSessionRemote endEntityManagementSession =
          EjbRemoteHelper.INSTANCE.getRemoteSession(
              EndEntityManagementSessionRemote.class);
      final EndEntityInformation userdata =
          getOrCreateUserdata(
              endEntityManagementSession, certificate, username);

      // addUser always adds the user with STATUS_NEW (even if we specified
      // otherwise)
      // We always override the userdata with the info from the certificate even
      // if the user existed.
      userdata.setStatus(EndEntityConstants.STATUS_GENERATED);
      endEntityManagementSession.changeUser(
          authenticationToken, userdata, false);
      LOG.info("User '" + username + "' has been updated.");

      // Finally import the certificate and revoke it if necessary
      CertificateStoreSessionRemote certificateStoreSession =
          EjbRemoteHelper.INSTANCE.getRemoteSession(
              CertificateStoreSessionRemote.class);
      certificateStoreSession.storeCertificateRemote(
          authenticationToken,
          EJBUtil.wrap(certificate),
          username,
          CertTools.getFingerprintAsString(caCertificate),
          CertificateConstants.CERT_ACTIVE,
          CertificateConstants.CERTTYPE_ENDENTITY,
          certificateProfileId,
          endEntityProfileId,
          null,
          now.getTime());

      if (status == CertificateConstants.CERT_REVOKED) {
        endEntityManagementSession.revokeCert(
            authenticationToken,
            certificate.getSerialNumber(),
            revocationTime,
            issuer,
            revocationReason.getDatabaseValue(),
            false);
        LOG.info(
            "Certificate with serial '"
                + CertTools.getSerialNumberAsString(certificate)
                + "' has been revoked.");
      }

      LOG.info(
          "Certificate with serial '"
              + CertTools.getSerialNumberAsString(certificate)
              + "' has been added.");

      return Result.IMPORT_OK;
    } catch (IOException | CertificateParsingException e) {
      LOG.error(
          "ERROR: A problem was encountered while reading the certificate,"
              + " file: "
              + file.getName());
      if (!resumeOnError) {
        throw e;
      } else {
        LOG.error(e.getMessage());
        return Result.READ_ERROR;
      }
    } catch (EndEntityProfileValidationException e) {
      LOG.error(
          "ERROR: End entity profile constraints were violated by the"
              + " certificate, file: "
              + file.getName());
      if (!resumeOnError) {
        throw e;
      } else {
        LOG.error(e.getMessage());
        return Result.CONSTRAINT_VIOLATION;
      }
    } catch (Exception e) {
      LOG.error(
          "ERROR: Unclassified general import error has occurred, file: "
              + file.getName()
              + System.lineSeparator()
              + "  "
              + e.getMessage());
      if (!resumeOnError) {
        throw e;
      } else {
        return Result.GENERAL_IMPORT_ERROR;
      }
    }
  }
}
