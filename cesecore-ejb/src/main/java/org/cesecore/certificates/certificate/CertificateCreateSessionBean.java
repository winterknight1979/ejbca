/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.internal.RequestAndPublicKeySelector;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTAuditLogCallback;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.ValidationException;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderUtil;

/**
 * Session bean for creating certificates.
 *
 * @version $Id: CertificateCreateSessionBean.java 29808 2018-09-05 07:52:38Z
 *     henriks $
 */
@Stateless(
    mappedName =
        JndiConstants.APP_JNDI_PREFIX + "CertificateCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateCreateSessionBean // NOPMD
    implements CertificateCreateSessionLocal, CertificateCreateSessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CertificateCreateSessionBean.class);

  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** CA. */
  @EJB private CaSessionLocal caSession;
  /** Store. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** Profile. */
  @EJB private CertificateProfileSessionLocal certificateProfileSession;
  /** Validator. */
  @EJB private KeyValidatorSessionLocal keyValidatorSession;
  /** Auth. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** Logger. */
  @EJB private SecurityEventsLoggerSessionLocal logSession;
  /** Management. */
  @EJB private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
  /** Confoig. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;

  /** Default create for SessionBean without any creation Arguments. */
  @PostConstruct
  public void postConstruct() {
    // Install BouncyCastle provider
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }

  @Override
  public CertificateResponseMessage createCertificate(
      final AuthenticationToken admin,
      final EndEntityInformation endEntityInformation,
      final CA ca,
      final RequestMessage requestMessage,
      final Class<? extends ResponseMessage> responseClass,
      final CertificateGenerationParams certGenParams,
      final long updateTime)
      throws CryptoTokenOfflineException, SignRequestSignatureException,
          IllegalKeyException, IllegalNameException,
          CustomCertificateSerialNumberException, CertificateCreateException,
          CertificateRevokeException, CertificateSerialNumberException,
          AuthorizationDeniedException, IllegalValidityException,
          CAOfflineException, InvalidAlgorithmException,
          CertificateExtensionException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">createCertificate(IRequestMessage, CA)");
    }
    CertificateResponseMessage ret = null;
    try {
      final CAToken catoken = ca.getCAToken();
      final CryptoToken cryptoToken =
          cryptoTokenManagementSession.getCryptoToken(
              catoken.getCryptoTokenId());
      final String alias;
      final Collection<Certificate> cachain;
      final Certificate cacert;
      if (ca.getUseNextCACert(requestMessage)) {
        alias = catoken.getAliasFromPurpose(
                CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
        cachain = ca.getRolloverCertificateChain();
        cacert = cachain.iterator().next();
      } else {
        alias =
            catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        cachain = ca.getCertificateChain();
        cacert = ca.getCACertificate();
      }
      // See if we need some key material to decrypt request
      if (requestMessage.requireKeyInfo()) {
        // You go figure...scep encrypts message with the public CA-cert
        requestMessage.setKeyInfo(
            cacert,
            cryptoToken.getPrivateKey(alias),
            cryptoToken.getEncProviderName());
      }
      // Verify the request
      final PublicKey reqpk = getReqPK(requestMessage);
      final Date notBefore =
          requestMessage
              .getRequestValidityNotBefore(); // Optionally requested validity
      final Date notAfter =
          requestMessage
              .getRequestValidityNotAfter(); // Optionally requested validity
      final Extensions exts =
          requestMessage
              .getRequestExtensions(); // Optionally requested extensions
      int keyusage = -1;
      keyusage = handleNullKey(exts, keyusage);
      String sequence = getSequence(requestMessage);
      CertificateDataWrapper certWrapper = createCertificate(
              admin,
              endEntityInformation,
              ca,
              requestMessage,
              reqpk,
              keyusage,
              notBefore,
              notAfter,
              exts,
              sequence,
              certGenParams,
              updateTime);
      // Create the response message with all nonces and checks etc
      ret = ResponseMessageUtils.createResponseMessage(
              responseClass,
              requestMessage,
              cachain,
              cryptoToken.getPrivateKey(alias),
              cryptoToken.getEncProviderName());
      setReturnValues(requestMessage, ret, cacert, certWrapper);
      ret.create();
    } catch (InvalidKeyException e) {
      throw new CertificateCreateException(ErrorCode.INVALID_KEY, e);
    } catch (NoSuchAlgorithmException e) {
      throw new CertificateCreateException(ErrorCode.BAD_REQUEST_SIGNATURE, e);
    } catch (NoSuchProviderException e) {
      throw new CertificateCreateException(ErrorCode.INTERNAL_ERROR, e);
    } catch (CertificateEncodingException e) {
      throw new CertificateCreateException(
          ErrorCode.CERT_COULD_NOT_BE_PARSED, e);
    } catch (CRLException e) {
      throw new CertificateCreateException(
          ErrorCode.CERT_COULD_NOT_BE_PARSED, e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<createCertificate(IRequestMessage, CA)");
    }
    return ret;
  }

/**
 * @param requestMessage Message
 * @param ret Cert
 * @param cacert CA
 * @param certWrapper Wrapper
 */
private void setReturnValues(final RequestMessage requestMessage,
        final CertificateResponseMessage ret,
        final Certificate cacert, final CertificateDataWrapper certWrapper) {
    ResponseStatus status = ResponseStatus.SUCCESS;
      FailInfo failInfo = null;
      String failText = null;
      if (certWrapper == null && status == ResponseStatus.SUCCESS) {
        status = ResponseStatus.FAILURE;
        failInfo = FailInfo.BAD_REQUEST;
      } else {
        ret.setCertificate(certWrapper.getCertificate());
        ret.setCACert(cacert);
        // Add in case of success after CMP message -> CmpResponseMessage.
        ret.addAdditionalCaCertificates(
            requestMessage.getAdditionalCaCertificates());
        ret.setBase64CertData(certWrapper.getBase64CertData());
        ret.setCertificateData(certWrapper.getCertificateData());
      }
      // Add in all cases -> PKI message.
      ret.addAdditionalResponseExtraCertsCertificates(
          requestMessage.getAdditionalExtraCertsCertificates());
      ret.setStatus(status);
      if (failInfo != null) {
        ret.setFailInfo(failInfo);
        ret.setFailText(failText);
      }
}

/**
 * @param requestMessage Message
 * @return Seq
 */
private String getSequence(final RequestMessage requestMessage) {
    String sequence = null;
      byte[] ki = requestMessage.getRequestKeyInfo();
      // CVC sequence is only 5 characters, don't fill with a lot of garbage
      // here, it must be a readable string
      if (ki != null && ki.length > 0 && ki.length < 10) {
        final String str = new String(ki);
        // A cvc sequence must be ascii printable, otherwise it's some binary
        // data
        if (StringUtils.isAsciiPrintable(str)) {
          sequence = new String(ki);
        }
      }
    return sequence;
}

/**
 * @param exts Extensions
 * @param k Usage
 * @return Usage
 */
private int handleNullKey(final Extensions exts, final int k) {
    int keyusage = k;
    if (exts != null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "we have extensions, see if we can override KeyUsage by looking"
                  + " for a KeyUsage extension in request");
        }
        final KeyUsage keyUsage = KeyUsage.fromExtensions(exts);
        if (keyUsage != null) {
          final DERBitString bitString =
              (DERBitString) keyUsage.toASN1Primitive();
          keyusage = bitString.intValue();
          if (LOG.isDebugEnabled()) {
            LOG.debug("We have a key usage request extension: " + keyusage);
          }
        }
      }
    return keyusage;
}

/**
 * @param requestMessage Message
 * @return PK
 * @throws NoSuchAlgorithmException Fail
 * @throws NoSuchProviderException Fail
 * @throws SignRequestSignatureException Fail
 * @throws IllegalKeyException Fail
 */
private PublicKey getReqPK(final RequestMessage requestMessage)
        throws NoSuchAlgorithmException, NoSuchProviderException,
        SignRequestSignatureException, IllegalKeyException {
    final PublicKey reqpk;
      try {
        if (!requestMessage.verify()) {
          throw new SignRequestSignatureException(
              INTRES.getLocalizedMessage("createcert.popverificationfailed"));
        }
        reqpk = requestMessage.getRequestPublicKey();
        if (reqpk == null) {
          final String msg =
              INTRES.getLocalizedMessage("createcert.nokeyinrequest");
          throw new InvalidKeyException(msg);
        }
      } catch (InvalidKeyException e) {
        // If we get an invalid key exception here, we should throw an
        // IllegalKeyException to the caller
        // The catch of InvalidKeyException in the end of this method, catches
        // error from the CA crypto token
        throw new IllegalKeyException(e);
      }
    return reqpk;
}

  @Override
  public CertificateResponseMessage createCertificate(
      final AuthenticationToken admin,
      final EndEntityInformation userData,
      final RequestMessage req,
      final Class<? extends ResponseMessage> responseClass,
      final CertificateGenerationParams certGenParams)
      throws CADoesntExistsException, AuthorizationDeniedException,
          CryptoTokenOfflineException, SignRequestSignatureException,
          IllegalKeyException, IllegalNameException,
          CustomCertificateSerialNumberException, CertificateCreateException,
          CertificateRevokeException, CertificateSerialNumberException,
          IllegalValidityException, CAOfflineException,
          InvalidAlgorithmException, CertificateExtensionException {
    final long updateTime = System.currentTimeMillis();
    return createCertificate(
        admin, userData, req, responseClass, certGenParams, updateTime);
  }

  @Override
  public CertificateResponseMessage createCertificate(
      final AuthenticationToken admin,
      final EndEntityInformation userData,
      final RequestMessage req,
      final Class<? extends ResponseMessage> responseClass,
      final CertificateGenerationParams certGenParams,
      final long updateTime)
      throws CADoesntExistsException, AuthorizationDeniedException,
          CryptoTokenOfflineException, SignRequestSignatureException,
          IllegalKeyException, IllegalNameException,
          CustomCertificateSerialNumberException, CertificateCreateException,
          CertificateRevokeException, CertificateSerialNumberException,
          IllegalValidityException, CAOfflineException,
          InvalidAlgorithmException, CertificateExtensionException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">createCertificate(IRequestMessage)");
    }
    final CA ca;
    // First find the CA, this checks authorization and that the CA exists
    if (userData == null || userData.getCAId() == 0) {
      // If no CAid in the supplied userdata
      ca = getCAFromRequest(admin, req);
    } else {
      ca = caSession.getCA(admin, userData.getCAId());
    }

    if (LOG.isTraceEnabled()) {
      LOG.trace("<createCertificate(IRequestMessage)");
    }
    return createCertificate(
        admin, userData, ca, req, responseClass, certGenParams, updateTime);
  }

  /**
   * Help Method that extracts the CA specified in the request.
   *
   * @param admin Auth token
   * @param req Request
   * @return CA
   * @throws AuthorizationDeniedException If access denied
   * @throws CADoesntExistsException On fail
   */
  private CA getCAFromRequest(
      final AuthenticationToken admin, final RequestMessage req)
      throws CADoesntExistsException, AuthorizationDeniedException {
    CA ca = null;
    // See if we can get issuerDN directly from request
    if (req.getIssuerDN() != null) {
      String dn = certificateStoreSession.getCADnFromRequest(req);
      ca = caSession.getCA(admin, dn.hashCode());
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Using CA (from issuerDN) with id: "
                + ca.getCAId()
                + " and DN: "
                + ca.getSubjectDN());
      }
    } else {
      throw new CADoesntExistsException(
          INTRES.getLocalizedMessage(
              "createcert.canotfoundissuerusername",
              req.getIssuerDN(),
              req.getUsername()));
    }

    if (ca.getStatus() != CAConstants.CA_ACTIVE) {
      final String msg =
          INTRES.getLocalizedMessage(
              "createcert.canotactive", ca.getSubjectDN());
      throw new EJBException(msg);
    }
    return ca;
  }

  @Override
  public CertificateDataWrapper createCertificate(// NOPMD: can't be reduced
      final AuthenticationToken admin,
      final EndEntityInformation endEntityInformation,
      final CA ca,
      final RequestMessage request,
      final PublicKey pk,
      final int keyusage,
      final Date notBefore,
      final Date notAfter,
      final Extensions extensions,
      final String sequence,
      final CertificateGenerationParams certGenParams,
      final long updateTime)
      throws AuthorizationDeniedException, IllegalNameException,
          CustomCertificateSerialNumberException, CertificateCreateException,
          CertificateRevokeException, CertificateSerialNumberException,
          CryptoTokenOfflineException, IllegalKeyException,
          CertificateExtensionException, IllegalValidityException,
          CAOfflineException, InvalidAlgorithmException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
              + " notBefore, notAfter, extesions, sequence)");
    }

    // Even though CA is passed as an argument to this method, we do check
    // authorization on that.
    // To make sure we properly log authorization checks needed to issue a cert.
    // We need to check that admin have rights to create certificates, and have
    // access to the CA
    failIfUnauthorized(admin, ca);

    // Audit log that we received the request
    populateDetails(admin, endEntityInformation, ca, request,
            pk, keyusage, notBefore, notAfter, sequence);

    // Retrieve the certificate profile this user should have, checking for
    // authorization to the profile
    final int certProfileId = endEntityInformation.getCertificateProfileId();
    final CertificateProfile certProfile =
        getCertificateProfile(certProfileId, ca.getCAId());

    // Validate ValidatorPhase.DATA_VALIDATION
    validatePK(admin, endEntityInformation, ca, request, pk,
            notBefore, notAfter, certProfile);
    validateDnsNames(admin, endEntityInformation, ca, request);

    // Set up audit logging of CT pre-certificate
    addCTLoggingCallback(certGenParams, admin.toString());

    try {
      CertificateDataWrapper result = null;
      // If the user is of type USER_INVALID, it cannot have any other type (in
      // the mask)
      assertValidEEI(endEntityInformation);

      assertSubjectEnforcements(ca.getCAInfo(), endEntityInformation);
      assertSubjectKeyIdEnforcements(ca.getCAInfo(), endEntityInformation, pk);

      // certProfile.verifyKey(pk); Verifying the public key against certificate
      // profile is going to be executed in *CA.generateCertificate

      // Below we have a small loop if it would happen that we generate the same
      // serial number twice
      // If using only 4 byte serial numbers this do happen once in a while
      Certificate cert = null;
      String cafingerprint = null;
      final boolean useCustomSN;

       ExtendedInformation ei =
            endEntityInformation.getExtendedInformation();
        useCustomSN = ei != null && ei.certificateSerialNumber() != null;

      final int maxRetrys = getMaxRetrys(ca, certProfileId, certProfile,
              useCustomSN);

      // Before storing the new certificate, check if single active certificate
      // constraint is active, and if so let's revoke all active and unexpired
      // certificates
      handleSingleConstraint(admin, endEntityInformation, certProfile);

      CertificateSerialNumberException storeEx =
          null; // this will not be null if stored == false after the below
                // passage
      String serialNo = "unknown";
      for (int retrycounter = 0; retrycounter < maxRetrys; retrycounter++) {
        final CryptoToken cryptoToken = getCryptoToken(admin,
                endEntityInformation, ca);
        final AvailableCustomCertificateExtensionsConfiguration cceConfig =
            (AvailableCustomCertificateExtensionsConfiguration)
                globalConfigurationSession.getCachedConfiguration(
                    AvailableCustomCertificateExtensionsConfiguration
                        .CONFIGURATION_ID);
        certGenParams.setAuthenticationToken(admin);
        certGenParams.setCertificateValidationDomainService(
            keyValidatorSession);

        // Validate ValidatorPhase.PRE_CERTIFICATE_VALIDATION (X.509 CA only)
        cert =
            ca.generateCertificate(
                cryptoToken, endEntityInformation, request,
                pk, keyusage,
                new CA.CaCertValidity(notBefore, notAfter),
                new CA.CaCertConfig(certProfile, extensions,
                        sequence, certGenParams, cceConfig));
        // Set null required here?
        certGenParams.setCertificateValidationDomainService(null);

        // Validate ValidatorPhase.CERTIFICATE_VALIDATION (X.509 CA only)
        validateCaType(admin, endEntityInformation, ca, cert);

        cafingerprint = CertTools.getFingerprintAsString(ca.getCACertificate());
        serialNo = CertTools.getSerialNumberAsString(cert);
        // Store certificate in the database, if this CA is configured to do so.
        if (!ca.isUseCertificateStorage()
            || !certProfile.getUseCertificateStorage()) {
          // We still need to return a CertificateData object for publishers
          final CertificateData throwAwayCertData =
              new CertificateData(
                  cert, cert.getPublicKey(),
                  endEntityInformation.getUsername(),
                  cafingerprint,
                  CertificateConstants.CERT_ACTIVE,
                  certProfile.getType(), certProfileId,
                  endEntityInformation.getEndEntityProfileId(),
                  null, updateTime, false,
                  certProfile.getStoreSubjectAlternativeName());
          result = new CertificateDataWrapper(cert, throwAwayCertData, null);
          // Always Store full certificate for OCSP signing certificates.
          boolean isOcspSigner =
              certProfile
                  .getExtendedKeyUsageOids()
                  .contains("1.3.6.1.5.5.7.3.9");
          if (!isOcspSigner) {
            break; // We have our cert and we don't need to store it.. Move on..
          }
          LOG.debug(
              "Storing certificate even though storage is disabled since OCSP"
                  + " signer EKU is used.");
        }
        try {
          // Remember for CVC serialNo can be alphanumeric, so we can't just try
          // to decode that using normal Java means (BigInteger.valueOf)...
          assertSerialNumberForIssuerOk(ca, CertTools.getSerialNumber(cert));
          // Tag is reserved for future use, currently only null
          final String tag = null;
          // Authorization was already checked by since this is a private
          // method, the CA parameter should
          // not be possible to get without authorization
          result =
              certificateStoreSession.storeCertificateNoAuth(
                  admin,
                  cert,
                  endEntityInformation.getUsername(),
                  cafingerprint,
                  CertificateConstants.CERT_ACTIVE,
                  certProfile.getType(),
                  certProfileId,
                  endEntityInformation.getEndEntityProfileId(),
                  tag,
                  updateTime);
          storeEx = null;
          break;
        } catch (CertificateSerialNumberException e) {
          // If we have created a unique index on (issuerDN,serialNumber) on
          // table CertificateData we can
          // get a CreateException here if we would happen to generate a
          // certificate with the same serialNumber
          // as one already existing certificate.
          if (retrycounter + 1 < maxRetrys) {
            LOG.info(
                "Can not store certificate with serNo ("
                    + serialNo
                    + "), will retry (retrycounter="
                    + retrycounter
                    + ") with a new certificate with new serialNo: "
                    + e.getMessage());
          }
          storeEx = e;
        }
      }
      checkException(useCustomSN, storeEx, serialNo);

      // Finally we check if this certificate should not be issued as active,
      // but revoked directly upon issuance
      doAuditLog(admin, endEntityInformation, ca, certProfile,
              result, cert, serialNo);
      return result;
      // We need to catch and re-throw all of these exception just because we
      // need to audit log all failures
    } catch (CustomCertificateSerialNumberException
            | AuthorizationDeniedException | CertificateCreateException e) {
      LOG.info(e.getMessage());
      auditFailure(
          admin,
          e,
          null,
          "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
              + " notBefore, notAfter, extesions, sequence)",
          ca.getCAId(),
          endEntityInformation.getUsername());
      throw e;
    } catch (CryptoTokenOfflineException e) {
      final String msg =
          INTRES.getLocalizedMessage("error.catokenoffline", ca.getCAId());
      LOG.info(msg);
      auditFailure(
          admin,
          e,
          e.getMessage(),
          "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
              + " notBefore, notAfter, extesions, sequence)",
          ca.getCAId(),
          endEntityInformation.getUsername());
      throw e;
    } catch (CAOfflineException | InvalidAlgorithmException
            | IllegalValidityException | CertificateExtensionException e) {
      LOG.error("Error creating certificate", e);
      auditFailure(
          admin,
          e,
          null,
          "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
              + " notBefore, notAfter, extesions, sequence)",
          ca.getCAId(),
          endEntityInformation.getUsername());
      throw e;
    } catch (OperatorCreationException
            | SignatureException e) {
      LOG.error("Error creating certificate", e);
      auditFailure(
          admin,
          e,
          null,
          "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
              + " notBefore, notAfter, extesions, sequence)",
          ca.getCAId(),
          endEntityInformation.getUsername());
      // Rollback
      throw new CertificateCreateException(e);
    }
  }

/**
 * @param admin Token
 * @param endEntityInformation EEI
 * @param ca CA
 * @param request Req
 * @param pk PK
 * @param notBefore Date
 * @param notAfter Date
 * @param certProfile Profile
 * @throws IllegalValidityException Fail
 * @throws CertificateCreateException Fail
 */
private void validatePK(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation, final CA ca,
        final RequestMessage request, final PublicKey pk,
        final Date notBefore, final Date notAfter,
        final CertificateProfile certProfile)
                throws IllegalValidityException, CertificateCreateException {
    try {
      // Which public key to validate follows the criteria established in
      // RequestAndPublicKeySelector, which is the same as used in the CA.
      final ExtendedInformation ei =
          endEntityInformation.getExtendedInformation();
      final RequestAndPublicKeySelector pkSelector =
          new RequestAndPublicKeySelector(request, pk, ei);
      keyValidatorSession.validatePublicKey(
          admin,
          ca,
          endEntityInformation,
          certProfile,
          notBefore,
          notAfter,
          pkSelector.getPublicKey());
    } catch (ValidationException e) {
      throw new CertificateCreateException(ErrorCode.ILLEGAL_KEY, e);
    }
}

/**
 * @param admin Admin
 * @param endEntityInformation EEI
 * @param ca CA
 * @param request Req
 * @throws CertificateCreateException Fail
 */
private void validateDnsNames(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CA ca, final RequestMessage request)
                throws CertificateCreateException {
    try {
      keyValidatorSession.validateDnsNames(
          admin, ca, endEntityInformation, request);
    } catch (ValidationException e) {
      // Re-factor: ErrorCode could be specified more precisely.
      throw new CertificateCreateException(
          ErrorCode.NOT_AUTHORIZED, e.getLocalizedMessage());
    }
}

/**
 * @param admin token
 * @param endEntityInformation EEI
 * @param ca CA
 * @param request Req
 * @param pk PK
 * @param keyusage Usage
 * @param notBefore Date
 * @param notAfter Date
 * @param sequence Seq
 * @throws AuditRecordStorageException fail
 */
private void populateDetails(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CA ca, final RequestMessage request, final PublicKey pk,
        final int keyusage, final Date notBefore,
        final Date notAfter, final String sequence)
                throws AuditRecordStorageException {
    final Map<String, Object> details = new LinkedHashMap<String, Object>();
    details.put("subjectdn", endEntityInformation.getDN());
    details.put(
        "requestX500name",
        request == null || request.getRequestX500Name() == null
            ? "null"
            : request.getRequestX500Name().toString());
    details.put("subjectaltname", endEntityInformation.getSubjectAltName());
    if (null != request) {
      details.put("requestaltname", request.getRequestAltNames());
    }
    details.put("certprofile", endEntityInformation.getCertificateProfileId());
    details.put("keyusage", keyusage);
    details.put("notbefore", notBefore);
    details.put("notafter", notAfter);
    details.put("sequence", sequence);
    details.put("publickey", new String(
            Base64Util.encode(pk.getEncoded(), false)));
    logSession.log(
        EventTypes.CERT_REQUEST,
        EventStatus.SUCCESS,
        ModuleTypes.CERTIFICATE,
        ServiceTypes.CORE,
        admin.toString(),
        String.valueOf(ca.getCAId()),
        null,
        endEntityInformation.getUsername(),
        details);
}

/**
 * @param endEntityInformation EEI
 * @throws CertificateCreateException Fail
 */
private void assertValidEEI(final EndEntityInformation endEntityInformation)
        throws CertificateCreateException {
    if (endEntityInformation.getType().isType(EndEntityTypes.INVALID)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.usertypeinvalid",
                endEntityInformation.getUsername());
        throw new CertificateCreateException(ErrorCode.INTERNAL_ERROR, msg);
      }
}

/**
 * @param admin token
 * @param endEntityInformation EEI
 * @param ca CA
 * @param certProfile Profile
 * @param result Result
 * @param cert Cert
 * @param serialNo SN
 * @throws CertificateRevokeException Fail
 * @throws AuthorizationDeniedException Fail
 * @throws IllegalStateException Fail
 * @throws AuditRecordStorageException Fail
 */
private void doAuditLog(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CA ca,
        final CertificateProfile certProfile,
        final CertificateDataWrapper result,
        final Certificate cert, final String serialNo)
        throws CertificateRevokeException,
        AuthorizationDeniedException, IllegalStateException,
        AuditRecordStorageException {
    int revreason = checkRevocation(admin, endEntityInformation, ca,
              certProfile, result, cert, serialNo);

      // Audit log that we issued the certificate
      final Map<String, Object> issuedetails =
          new LinkedHashMap<String, Object>();
      issuedetails.put("subjectdn", endEntityInformation.getDN());
      issuedetails.put(
          "certprofile", endEntityInformation.getCertificateProfileId());
      issuedetails.put("issuancerevocationreason", revreason);
      try {
        issuedetails.put(
            "cert", new String(Base64Util.encode(cert.getEncoded(), false)));
      } catch (CertificateEncodingException e) {
        // Should not be able to happen at this point
        throw new IllegalStateException();
      }
      logSession.log(
          EventTypes.CERT_CREATION,
          EventStatus.SUCCESS,
          ModuleTypes.CERTIFICATE,
          ServiceTypes.CORE,
          admin.toString(),
          String.valueOf(ca.getCAId()),
          serialNo,
          endEntityInformation.getUsername(),
          issuedetails);

      if (LOG.isTraceEnabled()) {
        LOG.trace(
            "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
                + " notBefore, notAfter, extesions, sequence)");
      }
}

/**
 * @param admin Token
 * @param endEntityInformation EEI
 * @param ca CA
 * @return Token
 * @throws CryptoTokenOfflineException Fail
 */
private CryptoToken getCryptoToken(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CA ca) throws CryptoTokenOfflineException {
    final CryptoToken cryptoToken =
        cryptoTokenManagementSession.getCryptoToken(
            ca.getCAToken().getCryptoTokenId());
    if (cryptoToken == null) {
      final String msg =
          INTRES.getLocalizedMessage("error.catokenoffline", ca.getCAId());
      LOG.info(msg);
      CryptoTokenOfflineException exception =
          new CryptoTokenOfflineException("CA's CryptoToken not found.");
      auditFailure(
          admin,
          exception,
          exception.getMessage(),
          "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku,"
              + " notBefore, notAfter, extesions, sequence)",
          ca.getCAId(),
          endEntityInformation.getUsername());
      throw exception;
    }
    return cryptoToken;
}

/**
 * @param admin Token
 * @param endEntityInformation EEI
 * @param certProfile Profile
 * @throws CertificateRevokeException Fail
 */
private void handleSingleConstraint(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CertificateProfile certProfile)
                throws CertificateRevokeException {
    if (certProfile.isSingleActiveCertificateConstraint()) {
        // Only get not yet expired certificates with status CERT_ACTIVE,
        // CERT_NOTIFIEDABOUTEXPIRATION, CERT_REVOKED
        final List<CertificateDataWrapper> cdws =
            certificateStoreSession.getCertificateDataByUsername(
                endEntityInformation.getUsername(),
                true,
                Arrays.asList(
                    CertificateConstants.CERT_ARCHIVED,
                    CertificateConstants.CERT_INACTIVE,
                    CertificateConstants.CERT_ROLLOVERPENDING,
                    CertificateConstants.CERT_UNASSIGNED));
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "SingleActiveCertificateConstraint, found "
                  + cdws.size()
                  + " old (non expired, active) certificates.");
        }
        for (final CertificateDataWrapper cdw : cdws) {
          final CertificateData certificateData = cdw.getCertificateData();
          if (certificateData.getStatus() == CertificateConstants.CERT_REVOKED
              && certificateData.getRevocationReason()
                  != RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
            // It's possible that revocation may have been already called from a
            // higher level bean (such as SignSession) which had to
            // perform operations (such as publishing) which are out of scope of
            // this method. This check is performed twice in order
            // to ensure that operations entirely contained within CESeCore
            // follow this constraint as well.
            continue;
          }
          // Authorization to the CA was already checked at the head of this
          // method, so no need to do so now
          certificateStoreSession.setRevokeStatusNoAuth(
              admin,
              certificateData,
              new Date(),
              RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
        }
      }
}

/**
 * @param ca CA
 * @param certProfileId IF
 * @param certProfile Progile
 * @param useCustomSN bool
 * @return retrys
 * @throws CustomCertificateSerialNumberException fail
 */
private int getMaxRetrys(final CA ca, final int certProfileId,
        final CertificateProfile certProfile,
        final boolean useCustomSN)
                throws CustomCertificateSerialNumberException {
    final int maxRetrys;
      if (useCustomSN) {
        if (ca.isUseCertificateStorage()
            && !isUniqueCertificateSerialNumberIndex()) {
          final String msg =
              INTRES.getLocalizedMessage(
                  "createcert.not_unique_certserialnumberindex");
          LOG.error(msg);
          throw new CustomCertificateSerialNumberException(msg);
        }
        if (!certProfile.getAllowCertSerialNumberOverride()) {
          final String msg =
              INTRES.getLocalizedMessage(
                  "createcert.certprof_not_allowing_cert_sn_override",
                  Integer.valueOf(certProfileId));
          LOG.info(msg);
          throw new CustomCertificateSerialNumberException(msg);
        }
        maxRetrys = 1;
      } else {
        maxRetrys = 5;
      }
    return maxRetrys;
}

/**
 * @param admin Admin
 * @param endEntityInformation EEI
 * @param ca CA
 * @param certProfile Profile
 * @param result Result
 * @param cert Cert
 * @param serialNo SN
 * @return Reason
 * @throws CertificateRevokeException fail
 * @throws AuthorizationDeniedException fail
 */
private int checkRevocation(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CA ca, final CertificateProfile certProfile,
        final CertificateDataWrapper result, final Certificate cert,
        final String serialNo)
                throws CertificateRevokeException,
                AuthorizationDeniedException {
    ExtendedInformation ei;
    int revreason = RevokedCertInfo.NOT_REVOKED;
      ei = endEntityInformation.getExtendedInformation();
      if (ei != null) {
        revreason = ei.getIssuanceRevocationReason();
        if (revreason != RevokedCertInfo.NOT_REVOKED) {
          // If we don't store the certificate in the database, we wont support
          // revocation/reactivation so issuing revoked certificates would be
          // really strange.
          if (ca.isUseCertificateStorage()
              && certProfile.getUseCertificateStorage()) {
            certificateStoreSession.setRevokeStatus(
                admin, result, new Date(), revreason);
          } else {
            LOG.warn(
                "CA configured to revoke issued certificates directly, but not"
                    + " to store issued the certificates. Revocation will be"
                    + " ignored. Please verify your configuration.");
          }
        }
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Generated certificate with SerialNumber '"
                + serialNo
                + "' for user '"
                + endEntityInformation.getUsername()
                + "', with revocation reason="
                + revreason);
        LOG.debug(cert.toString());
      }
    return revreason;
}

/**
 * @param useCustomSN bool
 * @param storeEx exception
 * @param serialNo SN
 * @throws CustomCertificateSerialNumberException Fail
 * @throws CertificateSerialNumberException Fail
 */
private void checkException(final boolean useCustomSN,
        final CertificateSerialNumberException storeEx,
        final String serialNo)
        throws CustomCertificateSerialNumberException,
        CertificateSerialNumberException {
    if (storeEx != null) {
        if (useCustomSN) {
          final String msg =
              INTRES.getLocalizedMessage(
                  "createcert.cert_serial_number_already_in_database",
                  serialNo);
          LOG.info(msg);
          throw new CustomCertificateSerialNumberException(msg);
        }
        LOG.error(
            "Can not store certificate in database in 5 tries, aborting: ",
            storeEx);
        throw storeEx;
      }
}

/**
 * @param admin Admin
 * @param endEntityInformation EEI
 * @param ca CA
 * @param cert Cert
 * @throws CertificateCreateException Fail
 */
private void validateCaType(final AuthenticationToken admin,
        final EndEntityInformation endEntityInformation,
        final CA ca, final Certificate cert) throws CertificateCreateException {
    if (CAInfo.CATYPE_X509 == ca.getCAType()) {
      try {
        keyValidatorSession.validateCertificate(
            admin,
            IssuancePhase.CERTIFICATE_VALIDATION,
            ca,
            endEntityInformation,
            (X509Certificate) cert);
      } catch (ValidationException e) {
        throw new CertificateCreateException(
            ErrorCode.INVALID_CERTIFICATE, e);
      }
    }
}

/**
 * @param admin Admin
 * @param ca CA
 * @throws AuthorizationDeniedException Fail
 */
private void failIfUnauthorized(final AuthenticationToken admin, final CA ca)
        throws AuthorizationDeniedException {
    if (!authorizationSession.isAuthorized(
        admin,
        StandardRules.CREATECERT.resource(),
        StandardRules.CAACCESS.resource() + ca.getCAId())) {
      final String msg =
          INTRES.getLocalizedMessage(
              "createcert.notauthorized", admin.toString(), ca.getCAId());
      throw new AuthorizationDeniedException(msg);
    }
}

  private void addCTLoggingCallback(
      final CertificateGenerationParams certGenParams,
      final String authTokenName) {
    if (certGenParams != null) {
      certGenParams.setCTAuditLogCallback(
          new CTAuditLogCallback() {
            @Override
            public void logPreCertSubmission(
                final X509CA issuer,
                final EndEntityInformation subject,
                final X509Certificate precert,
                final boolean success) {
              // Mostly the same info is logged as in
              // CertificateCreateSessionBean.createCertificate
              final Map<String, Object> issuedetails =
                  new LinkedHashMap<String, Object>();
              issuedetails.put("ctprecert", true);
              issuedetails.put(
                  "msg",
                  INTRES.getLocalizedMessage(
                      success
                          ? "createcert.ctlogsubmissionsuccessful"
                          : "createcert.ctlogsubmissionfailed"));
              issuedetails.put("subjectdn", CertTools.getSubjectDN(precert));
              issuedetails.put(
                  "certprofile", subject.getCertificateProfileId());
              try {
                issuedetails.put(
                    "cert",
                    new String(Base64Util.encode(precert.getEncoded(), false)));
              } catch (CertificateEncodingException e) {
                LOG.warn("Could not encode cert", e);
              }
              logSession.log(
                  EventTypes.CERT_CTPRECERT_SUBMISSION,
                  success ? EventStatus.SUCCESS : EventStatus.FAILURE,
                  ModuleTypes.CERTIFICATE,
                  ServiceTypes.CORE,
                  authTokenName,
                  String.valueOf(issuer.getCAId()),
                  CertTools.getSerialNumberAsString(precert),
                  subject.getUsername(),
                  issuedetails);
            }
          });
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public void assertSubjectEnforcements(
      final CAInfo ca, final EndEntityInformation endEntityInformation)
      throws CertificateCreateException {
    boolean enforceUniqueDistinguishedName = false;
    if (ca.isDoEnforceUniqueDistinguishedName()) {
      if (ca.isUseCertificateStorage()) {
        enforceUniqueDistinguishedName = true;
      } else {
        LOG.warn(
            "CA configured to enforce unique SubjectDN, but not to store"
                + " issued certificates. Check will be ignored. Please verify"
                + " your configuration.");
      }
    }
    final String username = endEntityInformation.getUsername();
    String subjectDN = null;
    if (enforceUniqueDistinguishedName) {
      subjectDN = endEntityInformation.getCertificateDN();
    }
    // boolean multipleCheckOk = false;

    // The below combined query is commented out because there is a bug in MySQL
    // 5.5 that causes it to
    // select bad indexes making the query slow. In MariaDB 5.5 and MySQL 5.6 it
    // works well, so it is MySQL 5.5 specific.
    // See ECA-3309
    //
    // Some time in the future, when we want to use multiple checks on the
    // database, a separate method should be added to execute this commented out
    // code.
    //        if (enforceUniqueDistinguishedName && enforceUniquePublicKeys) {
    //            multipleCheckOk =
    // certificateStoreSession.isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN
    //        (issuerDN, subjectKeyId, subjectDN, username);
    //        }

    // If one of the checks failed, we need to investigate further what went
    // wrong
    if (
    /*!multipleCheckOk && */ enforceUniqueDistinguishedName) {
      final Set<String> users =
          certificateStoreSession.findUsernamesByIssuerDNAndSubjectDN(
              ca.getSubjectDN(), subjectDN);
      if (users.size() > 0 && !users.contains(username)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.subjectdn_exists_for_another_user",
                username,
                listUsers(users));
        throw new CertificateCreateException(
            ErrorCode
              .CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER,
            msg);
      }
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public void assertSubjectKeyIdEnforcements(
      final CAInfo ca,
      final EndEntityInformation endEntityInformation,
      final PublicKey publicKey)
      throws CertificateCreateException {
    boolean enforceUniquePublicKeys = false;
    if (ca.isDoEnforceUniquePublicKeys()) {
      if (ca.isUseCertificateStorage()) {
        enforceUniquePublicKeys = true;
      } else {
        LOG.warn(
            "CA configured to enforce unique entity keys, but not to store"
                + " issued certificates. Check will be ignored. Please verify"
                + " your configuration.");
      }
    }
    final String username = endEntityInformation.getUsername();
    byte[] subjectKeyId = null;
    if (enforceUniquePublicKeys) {
      subjectKeyId = KeyUtil.createSubjectKeyId(publicKey).getKeyIdentifier();
    }
    // boolean multipleCheckOk = false;

    // The below combined query is commented out because there is a bug in MySQL
    // 5.5 that causes it to
    // select bad indexes making the query slow. In MariaDB 5.5 and MySQL 5.6 it
    // works well, so it is MySQL 5.5 specific.
    // See ECA-3309
    //        if (enforceUniqueDistinguishedName && enforceUniquePublicKeys) {
    //            multipleCheckOk =
    // certificateStoreSession.isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN
    //        (issuerDN, subjectKeyId, subjectDN, username);
    //        }

    if (
    /*!multipleCheckOk && */ enforceUniquePublicKeys) {
      final Set<String> users =
          certificateStoreSession.findUsernamesByIssuerDNAndSubjectKeyId(
              ca.getSubjectDN(), subjectKeyId);
      if (users.size() > 0 && !users.contains(username)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.key_exists_for_another_user", username);
        LOG.info(msg + listUsers(users));
        throw new CertificateCreateException(
            ErrorCode.CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER,
            msg);
      }
    }
  }

  /**
   * When no unique index is present in the database, we still try to enforce
   * X.509 serial number per CA uniqueness.
   *
   * @param ca CA
   * @param serialNumber SN
   * @throws CertificateSerialNumberException if serial number already exists in
   *     database
   */
  private void assertSerialNumberForIssuerOk(
      final CA ca, final BigInteger serialNumber)
      throws CertificateSerialNumberException {
    if (ca.getCAType() == CAInfo.CATYPE_X509
        && !isUniqueCertificateSerialNumberIndex()) {
      final String caSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
      if (certificateStoreSession.existsByIssuerAndSerno(
          caSubjectDN, serialNumber)) {
        final String msg =
            INTRES.getLocalizedMessage(
                "createcert.cert_serial_number_already_in_database",
                serialNumber.toString());
        LOG.info(msg);
        throw new CertificateSerialNumberException(msg);
      }
    }
  }

  private CertificateProfile getCertificateProfile(
      final int certProfileId, final int caid)
      throws AuthorizationDeniedException {
    final CertificateProfile certProfile =
        certificateProfileSession.getCertificateProfile(certProfileId);
    // What if certProfile == null?
    if (certProfile == null) {
      final String msg =
          INTRES.getLocalizedMessage(
              "createcert.errorcertprofilenotfound",
              Integer.valueOf(certProfileId));
      throw new AuthorizationDeniedException(msg);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Using certificate profile with id " + certProfileId);
    }

    // Check that CAid is among available CAs
    boolean caauthorized = false;
    for (final Integer nextInt : certProfile.getAvailableCAs()) {
      final int next = nextInt.intValue();
      if (next == caid || next == CertificateProfile.ANYCA) {
        caauthorized = true;
        break;
      }
    }
    if (!caauthorized) {
      final String msg =
          INTRES.getLocalizedMessage(
              "createcert.errorcertprofilenotauthorized",
              Integer.valueOf(caid),
              Integer.valueOf(certProfileId));
      throw new AuthorizationDeniedException(msg);
    }
    return certProfile;
  }

  /**
   * FIXME: Documentation.
   *
   * @param admin Auth token
   * @param e Excption
   * @param extraDetails Detaild
   * @param tracelog Log
   * @param caid CA
   * @param username User
   */
  private void auditFailure(
      final AuthenticationToken admin,
      final Exception e,
      final String extraDetails,
      final String tracelog,
      final int caid,
      final String username) {
    final Map<String, Object> details = new LinkedHashMap<String, Object>();
    details.put("msg", e.getMessage());
    if (extraDetails != null) {
      details.put("details", extraDetails);
    }
    logSession.log(
        EventTypes.CERT_CREATION,
        EventStatus.FAILURE,
        ModuleTypes.CERTIFICATE,
        ServiceTypes.CORE,
        admin.toString(),
        String.valueOf(caid),
        null,
        username,
        details);
    if (LOG.isTraceEnabled()
      && tracelog != null) {
        LOG.trace(tracelog);
      }

  }

  /**
   * Small function that makes a list of users, space separated. Used for
   * logging. Only actually displays the first 10 records, then a notice how
   * many records were not displayed
   *
   * @param users a set of usernames to create a string of
   * @return space separated list of usernames, i.e. "'user1' 'user2' 'user3'",
   *     max 10 users
   */
  private String listUsers(final Set<String> users) {
    final StringBuilder sb = new StringBuilder();
    int bar = 0; // limit number of displayed users
    final int max = 9;
    for (final String user : users) {
      if (sb.length() > 0) {
        sb.append(' ');
      }
      if (bar++ > max) {
        sb.append("and ")
            .append(users.size() - bar + 1)
            .append(" users not displayed");
        break;
      }
      sb.append('\'');
      sb.append(user);
      sb.append('\'');
    }
    return sb.toString();
  }

  @Override
  public boolean isUniqueCertificateSerialNumberIndex() {
    return certificateStoreSession.isUniqueCertificateSerialNumberIndex();
  }
}
