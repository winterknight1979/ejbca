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
package org.cesecore.certificates.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreError;
import org.cesecore.CesecoreException;
import org.cesecore.CesecoreRuntimeException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStatusHolder;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.certificates.ocsp.cache.OcspExtensionsCache;
import org.cesecore.certificates.ocsp.cache.OcspRequestSignerStatusCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.certificates.ocsp.exception.CryptoProviderException;
import org.cesecore.certificates.ocsp.exception.IllegalNonceException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.certificates.ocsp.extension.OCSPExtensionType;
import org.cesecore.certificates.ocsp.keys.CardKeys;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.PatternLogger;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.ConfigurationHolderUtil;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.log.ProbableErrorHandler;
import org.cesecore.util.log.SaferAppenderListener;
import org.cesecore.util.provider.EkuPKIXCertPathChecker;

/**
 * This SSB generates OCSP responses.
 *
 * @version $Id: OcspResponseGeneratorSessionBean.java 30346 2018-11-01
 *     13:14:39Z samuellb $
 */
@Stateless(
    mappedName =
        JndiConstants.APP_JNDI_PREFIX + "OcspResponseGeneratorSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class OcspResponseGeneratorSessionBean
    implements OcspResponseGeneratorSessionRemote,
        OcspResponseGeneratorSessionLocal,
        SaferAppenderListener {

  /** Max size of a request is 100000 bytes. */
  private static final int MAX_REQUEST_SIZE = 100000;
  /** Timer identifiers. */
  private static final int TIMERID_OCSPSIGNINGCACHE = 1;

  /** Name. */
  private static final String HARD_TOKEN_CLASS_NAME =
      OcspConfiguration.getHardTokenClassName();

  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(OcspResponseGeneratorSessionBean.class);

  /** Resource. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** Service. */
  private static volatile ExecutorService service =
      Executors.newCachedThreadPool();

  /** Context. */
  @Resource private SessionContext sessionContext;
  /** When the sessionContext is injected,
   * the timerService should be looked up.
   * This is due to the Glassfish EJB verifier complaining.
   */
  private TimerService timerService;

  /** CA. */
  @EJB private CaSessionLocal caSession;
  /** Store. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** Crypto. */
  @EJB private CryptoTokenSessionLocal cryptoTokenSession;
  /** Crypto. */
  @EJB private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
  /** Binding. */
  @EJB private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
  /** Binding. */
  @EJB private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
  /** Config. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;

  /** Converter. */
  private final JcaX509CertificateConverter certificateConverter =
      new JcaX509CertificateConverter();

  /** Setup. */
  @PostConstruct
  public void init() {

    timerService = sessionContext.getTimerService();
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void initTimers() {
    // Reload OCSP signing cache, and cancel/create timers if there are no
    // timers or if the cache is empty (probably a fresh startup)
    if (getTimerCount(TIMERID_OCSPSIGNINGCACHE) == 0
        || OcspSigningCache.INSTANCE.getEntries().isEmpty()) {
      reloadOcspSigningCache();
    } else {
      LOG.info("Not initing OCSP reload timers, there are already some.");
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void reloadOcspExtensionsCache() {
    OcspExtensionsCache.INSTANCE.reloadCache();
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void clearCTFailFastCache() {
    final CertificateTransparency ct =
        CertificateTransparencyFactory.getInstance();
    if (ct != null) {
      ct.clearCaches();
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void clearOcspRequestSignerRevocationStatusCache() {
    OcspRequestSignerStatusCache.INSTANCE.flush();
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void reloadOcspSigningCache() {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">reloadOcspSigningCache");
    }
    // Cancel any waiting timers of this type
    cancelTimers(TIMERID_OCSPSIGNINGCACHE);
    try {
      // Verify card key holder
      if (LOG.isDebugEnabled()
          && CardKeyHolder.getInstance().getCardKeys() == null) {
        LOG.debug(
            INTRES.getLocalizedMessage(
                "ocsp.classnotfound", HARD_TOKEN_CLASS_NAME));
      }
      GlobalOcspConfiguration ocspConfiguration =
          (GlobalOcspConfiguration)
              globalConfigurationSession.getCachedConfiguration(
                  GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
      OcspSigningCache.INSTANCE.stagingStart();
      try {
        // Populate OcspSigningCache
        // Add all potential CA's as OCSP responders to the staging area
        populateCache(ocspConfiguration);
        // Add all potential InternalKeyBindings as OCSP responders to the
        // staging area, overwriting CA entries from before
        handleCachedKeyBindings();
        OcspSigningCache.INSTANCE.stagingCommit(
            ocspConfiguration.getOcspDefaultResponderReference());
      } finally {
        OcspSigningCache.INSTANCE.stagingRelease();
      }
    } finally {
      // Schedule a new timer of this type
      addTimer(
          OcspConfiguration.getSigningCertsValidTimeInMilliseconds(),
          TIMERID_OCSPSIGNINGCACHE);
    }
  }

/**
 * @param ocspConfiguration config
 */
private void populateCache(final GlobalOcspConfiguration ocspConfiguration) {
    for (final Integer caId : caSession.getAllCaIds()) {
      final List<X509Certificate> caCertificateChain =
          new ArrayList<X509Certificate>();

      final CAInfo caInfo = caSession.getCAInfoInternal(caId.intValue());
      if (caInfo == null || caInfo.getCAType() == CAInfo.CATYPE_CVC) {
        // Bravely ignore OCSP for CVC CAs
        continue;
      }
      if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
        // Cache active CAs as signers
        logActiveCA(caInfo);
        final CAToken caToken = caInfo.getCAToken();
        final CryptoToken cryptoToken =
            cryptoTokenSession.getCryptoToken(caToken.getCryptoTokenId());
        if (cryptoToken == null) {
          LOG.info(
              "Excluding CA with id "
                  + caId
                  + " for OCSP signing consideration due to missing"
                  + " CryptoToken.");
          continue;
        }
        loadCerts(caCertificateChain, caInfo);
        final String keyPairAlias;
        try {
          keyPairAlias =
              caToken.getAliasFromPurpose(
                  CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        } catch (CryptoTokenOfflineException e) {
          LOG.warn(
              "Referenced private key with purpose "
                  + CATokenConstants.CAKEYPURPOSE_CERTSIGN
                  + " could not be used. CryptoToken is off-line for CA"
                  + " with id "
                  + caId
                  + ": "
                  + e.getMessage());
          continue;
        }
        final PrivateKey privateKey;
        try {
          privateKey = cryptoToken.getPrivateKey(keyPairAlias);
        } catch (CryptoTokenOfflineException e) {
          LOG.warn(
              "Referenced private key with alias "
                  + keyPairAlias
                  + " could not be used. CryptoToken is off-line for CA"
                  + " with id "
                  + caId
                  + ": "
                  + e.getMessage());
          continue;
        }
        if (privateKey == null) {
          LOG.warn(
              "Referenced private key with alias "
                  + keyPairAlias
                  + " does not exist. Ignoring CA with id "
                  + caId);
          continue;
        }
        final String signatureProviderName =
            cryptoToken.getSignProviderName();
        if (caCertificateChain.size() > 0) {
          stageCert(ocspConfiguration, caCertificateChain,
                  privateKey, signatureProviderName);
        } else {
          LOG.warn(
              "CA with ID "
                  + caId
                  + " appears to lack a certificate in the database. This"
                  + " may be a serious error if not in a test"
                  + " environment.");
        }
      } else if (caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
        final CertificateStatus caCertificateStatus
            = handleExternalCA(caCertificateChain, caInfo);
        // Add an entry with just a chain and nothing else
        OcspSigningCache.INSTANCE.stagingAdd(
            new OcspSigningCacheEntry(
                caCertificateChain.get(0),
                caCertificateStatus,
                null,
                null,
                null,
                null,
                null,
                ocspConfiguration.getOcspResponderIdType()));
      }
    }
}

/**
 * @param ocspConfiguration config
 * @param caCertificateChain chain
 * @param privateKey key
 * @param signatureProviderName Name
 */
private void stageCert(final GlobalOcspConfiguration ocspConfiguration,
        final List<X509Certificate> caCertificateChain,
        final PrivateKey privateKey, final String signatureProviderName) {
    X509Certificate caCertificate = caCertificateChain.get(0);
      final CertificateStatus caCertificateStatus =
          getRevocationStatusWhenCasPrivateKeyIsCompromised(
              caCertificate, false);
      OcspSigningCache.INSTANCE.stagingAdd(
          new OcspSigningCacheEntry(
              caCertificate,
              caCertificateStatus,
              caCertificateChain,
              null,
              privateKey,
              signatureProviderName,
              null,
              ocspConfiguration.getOcspResponderIdType()));
      // Check if CA cert has been revoked (only key compromise as
      // returned above). Always make this check, even if this CA has an
      // OCSP signing certificate, because
      // signing will still fail even if the signing cert is valid.
      // Shouldn't happen, but log it just in case.
      logRevokedOrExpired(caCertificate, caCertificateStatus);
}

/**
 * @param caInfo Info
 */
private void logActiveCA(final CAInfo caInfo) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Processing X509 CA "
              + caInfo.getName()
              + " ("
              + caInfo.getCAId()
              + ").");
    }
}

/**
 * @param caCertificateChain chain
 * @param caInfo info
 */
private void loadCerts(final List<X509Certificate> caCertificateChain,
        final CAInfo caInfo) {
    for (final Certificate certificate : caInfo.getCertificateChain()) {
      caCertificateChain.add((X509Certificate) certificate);
    }
}

/**
 * @param caCertificate cert
 * @param caCertificateStatus status
 */
private void logRevokedOrExpired(final X509Certificate caCertificate,
        final CertificateStatus caCertificateStatus) {
    if (caCertificateStatus.equals(CertificateStatus.REVOKED)) {
        LOG.warn(
            "Active CA with subject DN '"
                + CertTools.getSubjectDN(caCertificate)
                + "' and serial number "
                + CertTools.getSerialNumber(caCertificate)
                + " has a revoked certificate with reason "
                + caCertificateStatus.getRevocationReason()
                + ".");
      }
      // Check if CA cert is expired
      if (!CertTools.isCertificateValid(caCertificate, true)) {
        LOG.warn(
            "Active CA with subject DN '"
                + CertTools.getSubjectDN(caCertificate)
                + "' and serial number "
                + CertTools.getSerialNumber(caCertificate)
                + " has an expired certificate with expiration date "
                + CertTools.getNotAfter(caCertificate)
                + ".");
      }
}

/**
 * @param caCertificateChain Chain
 * @param caInfo Info
 * @return Status
 */
private CertificateStatus handleExternalCA(
        final List<X509Certificate> caCertificateChain, final CAInfo caInfo) {
    loadCerts(caCertificateChain, caInfo);
    final CertificateStatus caCertificateStatus =
        getRevocationStatusWhenCasPrivateKeyIsCompromised(
            caCertificateChain.get(0), false);
    // Check if CA cert has been revoked (only key compromise as
    // returned above). Always make this check, even if this CA has an
    // OCSP signing certificate, because
    // signing will still fail even if the signing cert is valid.
    if (caCertificateStatus.equals(CertificateStatus.REVOKED)) {
      LOG.info(
          "External CA with subject DN '"
              + CertTools.getSubjectDN(caCertificateChain.get(0))
              + "' and serial number "
              + CertTools.getSerialNumber(caCertificateChain.get(0))
              + " has a revoked certificate with reason "
              + caCertificateStatus.getRevocationReason()
              + ".");
    }
    // Check if CA cert is expired
    if (!CertTools.isCertificateValid(
        caCertificateChain.get(0), false)) {
      LOG.info(
          "External CA with subject DN '"
              + CertTools.getSubjectDN(caCertificateChain.get(0))
              + "' and serial number "
              + CertTools.getSerialNumber(caCertificateChain.get(0))
              + " has an expired certificate with expiration date "
              + CertTools.getNotAfter(caCertificateChain.get(0))
              + ".");
    }
    return caCertificateStatus;
}

/**
 *
 */
private void handleCachedKeyBindings() {
    for (final int internalKeyBindingId
        : internalKeyBindingDataSession.getIds(
            OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
      final OcspKeyBinding ocspKeyBinding =
          (OcspKeyBinding)
              internalKeyBindingDataSession.getInternalKeyBinding(
                  internalKeyBindingId);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Processing "
                + ocspKeyBinding.getName()
                + " ("
                + ocspKeyBinding.getId()
                + ")");
      }
      if (!ocspKeyBinding
          .getStatus()
          .equals(InternalKeyBindingStatus.ACTIVE)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Ignoring OcspKeyBinding since it is not active.");
        }
        continue;
      }
      final X509Certificate ocspSigningCertificate =
          (X509Certificate)
              certificateStoreSession.findCertificateByFingerprint(
                  ocspKeyBinding.getCertificateId());
      if (ocspSigningCertificate == null) {
        LOG.warn(
            "OCSP signing certificate with referenced fingerprint "
                + ocspKeyBinding.getCertificateId()
                + " does not exist. Ignoring internalKeyBinding with id "
                + ocspKeyBinding.getId());
        continue;
      }
      // Make the same check as above
      if (certificateStoreSession
          .getStatus(
              CertTools.getIssuerDN(ocspSigningCertificate),
              CertTools.getSerialNumber(ocspSigningCertificate))
          .equals(CertificateStatus.REVOKED)) {
        LOG.warn(
            "OCSP Responder certificate with subject DN '"
                + CertTools.getSubjectDN(ocspSigningCertificate)
                + "' and serial number "
                + CertTools.getSerialNumber(ocspSigningCertificate)
                + " is revoked.");
      }
      // Check if signing cert is expired
      if (!CertTools.isCertificateValid(ocspSigningCertificate, true)) {
        LOG.warn(
            "OCSP Responder certificate with subject DN '"
                + CertTools.getSubjectDN(ocspSigningCertificate)
                + "' and serial number "
                + CertTools.getSerialNumber(ocspSigningCertificate)
                + " is expired.");
      }

      OcspSigningCacheEntry ocspSigningCacheEntry =
          makeOcspSigningCacheEntry(ocspSigningCertificate, ocspKeyBinding);
      if (ocspSigningCacheEntry == null) {
        continue;
      } else {
        OcspSigningCache.INSTANCE.stagingAdd(ocspSigningCacheEntry);
      }
    }
}

  /**
   * Constructs an OcspSigningCacheEntry from the given parameters.
   *
   * @param ocspSigningCertificate The signing certificate associated with the
   *     key binding. May be found separately, so given as a separate parameter
   * @param ocspKeyBinding the Key Binding to base the cache entry off of.
   * @return an OcspSigningCacheEntry, or null if any error was encountered.
   */
  private OcspSigningCacheEntry makeOcspSigningCacheEntry(
      final X509Certificate ocspSigningCertificate,
      final OcspKeyBinding ocspKeyBinding) {
    final List<X509Certificate> caCertificateChain =
        getCaCertificateChain(ocspSigningCertificate);
    if (caCertificateChain == null) {
      LOG.warn(
          "OcspKeyBinding "
              + ocspKeyBinding.getName()
              + " ( "
              + ocspKeyBinding.getId()
              + ") has a signing certificate, but no chain and will be"
              + " ignored.");
      return null;
    }
    final CryptoToken cryptoToken =
        cryptoTokenSession.getCryptoToken(ocspKeyBinding.getCryptoTokenId());
    if (cryptoToken == null) {
      LOG.warn(
          "Referenced CryptoToken with id "
              + ocspKeyBinding.getCryptoTokenId()
              + " does not exist. Ignoring OcspKeyBinding with id "
              + ocspKeyBinding.getId());
      return null;
    }
    final PrivateKey privateKey;
    try {
      privateKey = cryptoToken.getPrivateKey(ocspKeyBinding.getKeyPairAlias());
    } catch (CryptoTokenOfflineException e) {
      LOG.warn(
          "Referenced private key with alias "
              + ocspKeyBinding.getKeyPairAlias()
              + " could not be used. CryptoToken is off-line for"
              + " OcspKeyBinding with id "
              + ocspKeyBinding.getId()
              + ": "
              + e.getMessage());
      return null;
    }
    if (privateKey == null) {
      LOG.warn(
          "Referenced private key with alias "
              + ocspKeyBinding.getKeyPairAlias()
              + " does not exist. Ignoring OcspKeyBinding with id "
              + ocspKeyBinding.getId());
      return null;
    }
    final String signatureProviderName = cryptoToken.getSignProviderName();
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Adding OcspKeyBinding "
              + ocspKeyBinding.getId()
              + ", "
              + ocspKeyBinding.getName());
    }
    final CertificateStatus certificateStatus =
        getRevocationStatusWhenCasPrivateKeyIsCompromised(
            caCertificateChain.get(0), true);
    OcspKeyBinding.ResponderIdType respIdType;
    if (ResponderIdType.NAME.equals(ocspKeyBinding.getResponderIdType())) {
      respIdType = OcspKeyBinding.ResponderIdType.NAME;
    } else {
      respIdType = OcspKeyBinding.ResponderIdType.KEYHASH;
    }
    return new OcspSigningCacheEntry(
        caCertificateChain.get(0),
        certificateStatus,
        caCertificateChain,
        ocspSigningCertificate,
        privateKey,
        signatureProviderName,
        ocspKeyBinding,
        respIdType);
  }

  /**
   * RFC 6960 Section 2.7 states that if it is known CA's private key has been
   * compromised, it MAY return the "revoked" state for all certificates issued
   * by that CA.
   *
   * <p>We interpret this as if the revocation reasons is one of
   * "keyCompromise", "cACompromise" or "aACompromise" we know this.
   * Additionally, if the "unspecified" reason is used we will consider this as
   * a known private key compromise. (Safety first!)
   *
   * @param caCertificate the X.509 CA certificate to check
   * @param suppressInfo set to true to only do debug logging instead of info
   *     logging
   * @return OK or the revocation status that we will use if the CA is revoked
   *     (same revocation date, but with reasonCode "cACompromise")
   */
  private CertificateStatus getRevocationStatusWhenCasPrivateKeyIsCompromised(
      final X509Certificate caCertificate, final boolean suppressInfo) {
    final String issuerDn = CertTools.getIssuerDN(caCertificate);
    final BigInteger serialNumber = CertTools.getSerialNumber(caCertificate);
    final CertificateStatus certificateStatus =
        certificateStoreSession.getStatus(issuerDn, serialNumber);
    if (certificateStatus.isRevoked()) {
      final String subjectDn = CertTools.getSubjectDN(caCertificate);
      if (certificateStatus.getRevocationReason()
              == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED
          || certificateStatus.getRevocationReason()
              == RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE
          || certificateStatus.getRevocationReason()
              == RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE
          || certificateStatus.getRevocationReason()
              == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE) {
        final String msg =
            "CA certificate Subject DN '"
                + subjectDn
                + "', Issuer DN '"
                + issuerDn
                + "' and serial number "
                + serialNumber.toString()
                + " (0x"
                + serialNumber.toString(16)
                + ") is revoked with reason code "
                + certificateStatus.getRevocationReason()
                + ". The cACompromise revocation reason will be used for all"
                + " certs issued by this CA.";
        if (suppressInfo) {
          LOG.debug(msg);
        } else {
          LOG.info(msg);
        }
        return new CertificateStatus(
            certificateStatus.toString(),
            certificateStatus.getRevocationDate().getTime(),
            RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE,
            certificateStatus.getCertificateProfileId());
      }
      final String msg =
          "CA certificate Subject DN '"
              + subjectDn
              + "', Issuer DN '"
              + issuerDn
              + "' and serial number "
              + serialNumber.toString()
              + " (0x"
              + serialNumber.toString(16)
              + ") is revoked with reason code "
              + certificateStatus.getRevocationReason()
              + ". "
              + "Status of individual leaf certificate will still be checked.";
      if (suppressInfo) {
        LOG.debug(msg);
      } else {
        LOG.info(msg);
      }
    }
    return CertificateStatus.OK;
  }

  private List<X509Certificate> getCaCertificateChain(
      final X509Certificate leafCertificate) {
    final List<X509Certificate> caCertificateChain =
        new ArrayList<X509Certificate>();
    X509Certificate currentLevelCertificate = leafCertificate;
    while (!CertTools.getIssuerDN(currentLevelCertificate)
        .equals(CertTools.getSubjectDN(currentLevelCertificate))) {
      final String issuerDn = CertTools.getIssuerDN(currentLevelCertificate);
      currentLevelCertificate =
          certificateStoreSession.findLatestX509CertificateBySubject(issuerDn);
      if (currentLevelCertificate == null) {
        LOG.warn(
            "Unable to build certificate chain for OCSP signing certificate"
                + " with Subject DN '"
                + CertTools.getSubjectDN(leafCertificate)
                + "'. CA with Subject DN '"
                + issuerDn
                + "' is missing in the database.");
        return null;
      }
      caCertificateChain.add(currentLevelCertificate);
    }
    try {
      CertTools.verify(
          leafCertificate,
          caCertificateChain,
          new Date(),
          new EkuPKIXCertPathChecker(KeyPurposeId.id_kp_OCSPSigning.getId()));
    } catch (CertPathValidatorException e) {
      // Apparently the built chain could not be used to validate the leaf
      // certificate
      // this could happen if the CA keys were renewed, but the subject DN did
      // not change
      final CertificateInfo certificateInfo = getLeafCert(leafCertificate, e);
      if (certificateInfo == null) {
        return null;
      }
      final List<Certificate> chainByFingerPrints =
          certificateStoreSession.getCertificateChain(certificateInfo);
      if (chainByFingerPrints.size() > 0) {
        // Remove the leaf certificate itself
        chainByFingerPrints.remove(0);
      }
      caCertificateChain.clear();
      for (final Certificate current : chainByFingerPrints) {
        if (current instanceof X509Certificate) {
          caCertificateChain.add((X509Certificate) current);
        } else {
          LOG.warn(
              "Unable to build certificate chain for OCSP signing certificate"
                  + " with Subject DN '"
                  + CertTools.getSubjectDN(leafCertificate)
                  + "' and Issuer DN '"
                  + CertTools.getIssuerDN(leafCertificate)
                  + "'. CA certificate chain contains non-X509 certificates.");
          return null;
        }
      }
      if (caCertificateChain.isEmpty()) {
        LOG.warn(
            "Unable to build certificate chain for OCSP signing certificate"
                + " with Subject DN '"
                + CertTools.getSubjectDN(leafCertificate)
                + "' and Issuer DN '"
                + CertTools.getIssuerDN(leafCertificate)
                + "''. CA certificate(s) are missing in the database.");
        return null;
      }
      try {
        CertTools.verify(
            leafCertificate,
            caCertificateChain,
            new Date(),
            new EkuPKIXCertPathChecker(KeyPurposeId.id_kp_OCSPSigning.getId()));
      } catch (Exception e2) {
        LOG.warn(
            "Unable to build certificate chain for OCSP signing certificate"
                + " with Subject DN '"
                + CertTools.getSubjectDN(leafCertificate)
                + "' and Issuer DN '"
                + CertTools.getIssuerDN(leafCertificate)
                + "''. Found CA certificate(s) cannot be used for validation: "
                + e2.getMessage());
        return null;
      }
      LOG.info(
          "Recovered and managed to build a valid certificate chain for OCSP"
              + " signing certificate with Subject DN '"
              + CertTools.getSubjectDN(leafCertificate)
              + "' and Issuer DN '"
              + CertTools.getIssuerDN(leafCertificate)
              + "'.");
    }
    return caCertificateChain;
  }

/**
 * @param leafCertificate Leaf
 * @param e ex
 * @return cert
 */
private CertificateInfo getLeafCert(final X509Certificate leafCertificate,
        final CertPathValidatorException e) {
    LOG.info(
          "Unable to build a valid certificate chain for OCSP signing"
              + " certificate with Subject DN '"
              + CertTools.getSubjectDN(leafCertificate)
              + "' and Issuer DN "
              + CertTools.getIssuerDN(leafCertificate)
              + "' using the latest CA certificate(s) in the database. Trying"
              + " to recover from exception: "
              + e.getMessage());
      final CertificateInfo certificateInfo =
          certificateStoreSession.getCertificateInfo(
              CertTools.getFingerprintAsString(leafCertificate));
    return certificateInfo;
}

  @Override
  public void setCanlog(final boolean canLog) {
    CanLogCache.INSTANCE.setCanLog(canLog);
  }

  /**
   * This method exists solely to avoid code duplication when error handling in
   * getOcspResponse.
   *
   * @param responseGenerator A OCSPRespBuilder for generating a response with
   *     state INTERNAL_ERROR.
   * @param transactionLogger The TransactionLogger for this call.
   * @param auditLogger The AuditLogger for this call.
   * @param e The thrown exception.
   * @return a response with state INTERNAL_ERROR.
   * @throws OCSPException if generation of the response failed.
   */
  private OCSPResp processDefaultError(
      final OCSPRespBuilder responseGenerator,
      final TransactionLogger transactionLogger,
      final AuditLogger auditLogger,
      final Throwable e)
      throws OCSPException {
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
    }
    if (auditLogger.isEnabled()) {
      auditLogger.paramPut(
          PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
    }
    String errMsg =
        INTRES.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
    LOG.error(errMsg, e);
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          TransactionLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
      transactionLogger.writeln();
    }
    if (auditLogger.isEnabled()) {
      auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
    }
    return responseGenerator.build(
        OCSPRespBuilder.INTERNAL_ERROR,
        null); // RFC 2560: responseBytes are not set on error.
  }

  /**
   * Select the preferred OCSP response sigAlg according to RFC6960 Section
   * 4.4.7 in the following order:
   *
   * <p>1. Select an algorithm specified as a preferred signature algorithm in
   * the client request if it is an acceptable algorithm by EJBCA. 2. Select the
   * signature algorithm used to sign a certificate revocation list (CRL) issued
   * by the certificate issuer providing status information for the certificate
   * specified by CertID. (NOT APPLIED) 3. Select the signature algorithm used
   * to sign the OCSPRequest if it is an acceptable algorithm in EJBCA. 4.
   * Select a signature algorithm that has been advertised as being the default
   * signature algorithm for the signing service using an out-of-band mechanism.
   * 5. Select a mandatory or recommended signature algorithm specified for the
   * version of OCSP in use, aka. specified in the properties file.
   *
   * <p>The acceptable algorithm by EJBCA are the algorithms specified in
   * ocsp.properties file in 'ocsp.signaturealgorithm'
   *
   * @param req request
   * @param ocspSigningCacheEntry Signing cache
   * @param signerCert Certificate
   * @return Algorithm
   */
  private String getSigAlg(
      final OCSPReq req,
      final OcspSigningCacheEntry ocspSigningCacheEntry,
      final X509Certificate signerCert) {
    String sigAlg = null;
    PublicKey pk = signerCert.getPublicKey();
    // Start with the preferred signature algorithm in the OCSP request
    final Extension preferredSigAlgExtension =
        req.getExtension(
            new ASN1ObjectIdentifier(
                OCSPObjectIdentifiers.id_pkix_ocsp + ".8"));
    if (preferredSigAlgExtension != null) {
      final ASN1Sequence preferredSignatureAlgorithms =
          ASN1Sequence.getInstance(preferredSigAlgExtension.getParsedValue());
      for (int i = 0; i < preferredSignatureAlgorithms.size(); i++) {
        final ASN1Encodable asn1Encodable =
            preferredSignatureAlgorithms.getObjectAt(i);
        final ASN1ObjectIdentifier algorithmOid;
        if (asn1Encodable instanceof ASN1ObjectIdentifier) {
          // Handle client requests that were adapted to EJBCA 6.1.0's
          // implementation
          LOG.info(
              "OCSP request's PreferredSignatureAlgorithms did not contain an"
                  + " PreferredSignatureAlgorithm, but instead an algorithm"
                  + " OID. This will not be supported in a future versions of"
                  + " EJBCA.");
          algorithmOid = (ASN1ObjectIdentifier) asn1Encodable;
        } else {
          // Handle client requests that provide a proper AlgorithmIdentifier as
          // specified in RFC 6960 + RFC 5280
          final ASN1Sequence preferredSignatureAlgorithm =
              ASN1Sequence.getInstance(asn1Encodable);
          final AlgorithmIdentifier algorithmIdentifier =
              AlgorithmIdentifier.getInstance(
                  preferredSignatureAlgorithm.getObjectAt(0));
          algorithmOid = algorithmIdentifier.getAlgorithm();
        }
        if (algorithmOid != null) {
          sigAlg = AlgorithmTools.getAlgorithmNameFromOID(algorithmOid);
          if (sigAlg != null
              && OcspConfiguration.isAcceptedSignatureAlgorithm(sigAlg)
              && AlgorithmTools.isCompatibleSigAlg(pk, sigAlg)) {
            logExtracted(algorithmOid);
            return sigAlg;
          }
        }
      }
    }
    // the signature algorithm used to sign the OCSPRequest
    if (req.getSignatureAlgOID() != null) {
      sigAlg = AlgorithmTools.getAlgorithmNameFromOID(req.getSignatureAlgOID());
      if (OcspConfiguration.isAcceptedSignatureAlgorithm(sigAlg)
          && AlgorithmTools.isCompatibleSigAlg(pk, sigAlg)) {
        logAlgo(sigAlg);
        return sigAlg;
      }
    }
    // The signature algorithm that has been advertised as being the default
    // signature algorithm for the signing service using an
    // out-of-band mechanism.
    if (ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
      // If we have an OcspKeyBinding we use this configuration to override the
      // default
      sigAlg =
          ocspSigningCacheEntry.getOcspKeyBinding().getSignatureAlgorithm();
      logOutOfBand(sigAlg);
      return sigAlg;
    }
    // The signature algorithm specified for the version of OCSP in use.
    String sigAlgs = OcspConfiguration.getSignatureAlgorithm();
    sigAlg = getSigningAlgFromAlgSelection(sigAlgs, pk);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Using configured signature algorithm to sign OCSP response. "
              + sigAlg);
    }
    return sigAlg;
  }

/**
 * @param sigAlg Alg
 */
private void logOutOfBand(final String sigAlg) {
    if (LOG.isDebugEnabled()) {
        LOG.debug(
            "OCSP response signature algorithm: the signature algorithm that"
                + " has been advertised as being the default signature"
                + " algorithm for the signing service using an out-of-band"
                + " mechanism. "
                + sigAlg);
      }
}

/**
 * @param sigAlg Alf
 */
private void logAlgo(final String sigAlg) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "OCSP response signature algorithm: the signature algorithm used"
              + " to sign the OCSPRequest. "
              + sigAlg);
    }
}

/**
 * @param algorithmOid OID
 */
private void logExtracted(final ASN1ObjectIdentifier algorithmOid) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Using OCSP response signature algorithm extracted from OCSP"
              + " request extension. "
              + algorithmOid);
    }
}

  /**
   * This method takes byte array and translates it onto a OCSPReq class.
   *
   * @param request the byte array in question.
   * @param remoteAddress The remote address of the HttpRequest associated with
   *     this array.
   * @param transactionLogger A transaction logger.
   * @return OCSP Request
   * @throws MalformedRequestException if malformed
   * @throws SignRequestException thrown if an unsigned request was processed
   *     when system configuration requires that all requests be signed.
   * @throws CertificateException if cert is invalid
   * @throws NoSuchAlgorithmException if algo not found
   * @throws SignRequestSignatureException if sigs fails
   */
  private OCSPReq translateRequestFromByteArray(
      final byte[] request,
      final String remoteAddress,
      final TransactionLogger transactionLogger)
      throws MalformedRequestException, SignRequestException,
          SignRequestSignatureException, CertificateException,
          NoSuchAlgorithmException {
    final OCSPReq ocspRequest;
    try {
      ocspRequest = new OCSPReq(request);
    } catch (IOException e) {
      throw new MalformedRequestException("Could not form OCSP request", e);
    }
    logSetup(transactionLogger, ocspRequest);
    /*
     * check the signature if contained in request. if the request does not
     * contain a signature and the servlet is configured in the way the a
     * signature is required we send back 'sigRequired' response.
     */
    if (LOG.isDebugEnabled()) {
      LOG.debug("Incoming OCSP request is signed : " + ocspRequest.isSigned());
    }
    if (ocspRequest.isSigned()) {
      final X509Certificate signercert =
          checkRequestSignature(remoteAddress, ocspRequest);
      final String signercertIssuerName = CertTools.getIssuerDN(signercert);
      final BigInteger signercertSerNo = CertTools.getSerialNumber(signercert);
      final String signercertSubjectName = CertTools.getSubjectDN(signercert);
      logParams(transactionLogger, signercert, signercertIssuerName,
              signercertSubjectName);
      // Check if we have configured request verification using the old property
      // file way..
      boolean enforceRequestSigning =
          OcspConfiguration.getEnforceRequestSigning();
      // Next, check if there is an OcspKeyBinding where signing is required and
      // configured for this request
      // In the case where multiple requests are bundled together they all must
      // be trusting the signer
      for (final Req req : ocspRequest.getRequestList()) {
        OcspSigningCacheEntry ocspSigningCacheEntry =
            OcspSigningCache.INSTANCE.getEntry(req.getCertID());
        if (ocspSigningCacheEntry == null) {
          if (LOG.isTraceEnabled()) {
            LOG.trace("Using default responder to check signature.");
          }
          ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getDefaultEntry();
        }
        if (ocspSigningCacheEntry != null
            && ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
          final OcspKeyBinding ocspKeyBinding
              = getKeyBinding(ocspSigningCacheEntry);
          if (ocspKeyBinding.getRequireTrustedSignature()) {
            enforceRequestSigning = true;
            boolean isTrusted = false;
            final List<InternalKeyBindingTrustEntry>
                trustedCertificateReferences =
                    ocspKeyBinding.getTrustedCertificateReferences();
            if (trustedCertificateReferences.isEmpty()) {
              // We trust ANY cert from a known CA
              isTrusted = true;
            } else {
              isTrusted = handleTrust(signercertIssuerName, signercertSerNo,
                      isTrusted, trustedCertificateReferences);
            }
            assertTrusted(signercertIssuerName, signercertSerNo,
                    signercertSubjectName, isTrusted);
          }
        }
      }
      handleEnforceSigning(signercertIssuerName, signercertSerNo,
              signercertSubjectName, enforceRequestSigning);
    } else {
      if (OcspConfiguration.getEnforceRequestSigning()) {
        // Signature required
        throw new SignRequestException("Signature required");
      }
      // Next, check if there is an OcspKeyBinding where signing is required and
      // configured for this request
      // In the case where multiple requests are bundled together they all must
      // be trusting the signer
      assertSigningValid(ocspRequest);
    }
    return ocspRequest;
  }

/**
 * @param signercertIssuerName name
 * @param signercertSerNo SN
 * @param t bool
 * @param trustedCertificateReferences certs
 * @return bool
 */
private boolean handleTrust(final String signercertIssuerName,
        final BigInteger signercertSerNo, final boolean t,
        final List<InternalKeyBindingTrustEntry> trustedCertificateReferences) {
    boolean isTrusted = t;
    for (final InternalKeyBindingTrustEntry trustEntry
         : trustedCertificateReferences) {
        final int trustedCaId = trustEntry.getCaId();
        final BigInteger trustedSerialNumber =
            trustEntry.fetchCertificateSerialNumber();
        if (LOG.isTraceEnabled()) {
          LOG.trace(
              "Processing trustedCaId="
                  + trustedCaId
                  + " trustedSerialNumber="
                  + trustedSerialNumber
                  + " signercertIssuerName.hashCode()="
                  + signercertIssuerName.hashCode()
                  + " signercertSerNo="
                  + signercertSerNo);
        }
        if (trustedCaId == signercertIssuerName.hashCode()) {
          if (trustedSerialNumber == null) {
            // We trust any certificate from this CA
            isTrusted = true;
            if (LOG.isTraceEnabled()) {
              LOG.trace(
                  "Trusting request signature since ANY certificate"
                      + " from issuer "
                      + trustedCaId
                      + " is trusted.");
            }
            break;
          } else if (signercertSerNo.equals(trustedSerialNumber)) {
            // We trust this particular certificate from this CA
            isTrusted = true;
            if (LOG.isTraceEnabled()) {
              LOG.trace(
                  "Trusting request signature since certificate with"
                      + " serialnumber "
                      + trustedSerialNumber
                      + " from issuer "
                      + trustedCaId
                      + " is trusted.");
            }
            break;
          }
        }
      }
    return isTrusted;
}

/**
 * @param signercertIssuerName Issuer
 * @param signercertSerNo SN
 * @param signercertSubjectName Name
 * @param isTrusted Trusted
 * @throws SignRequestSignatureException Ex
 */
private void assertTrusted(final String signercertIssuerName,
        final BigInteger signercertSerNo,
        final String signercertSubjectName,
        final boolean isTrusted) throws SignRequestSignatureException {
    if (!isTrusted) {
      final String infoMsg =
          INTRES.getLocalizedMessage(
              "ocsp.infosigner.notallowed",
              signercertSubjectName,
              signercertIssuerName,
              signercertSerNo.toString(16));
      LOG.info(infoMsg);
      throw new SignRequestSignatureException(infoMsg);
    }
}

/**
 * @param ocspSigningCacheEntry Cache
 * @return Binding
 */
private OcspKeyBinding getKeyBinding(
        final OcspSigningCacheEntry ocspSigningCacheEntry) {
    if (LOG.isTraceEnabled()) {
        LOG.trace(
            "ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate: "
                + ocspSigningCacheEntry
                    .isUsingSeparateOcspSigningCertificate());
      }
      final OcspKeyBinding ocspKeyBinding =
          ocspSigningCacheEntry.getOcspKeyBinding();
      if (LOG.isTraceEnabled()) {
        LOG.trace(
            "OcspKeyBinding "
                + ocspKeyBinding.getId()
                + ", RequireTrustedSignature: "
                + ocspKeyBinding.getRequireTrustedSignature());
      }
    return ocspKeyBinding;
}

/**
 * @param transactionLogger Logger
 * @param signercert Cert
 * @param signercertIssuerName Issuer
 * @param signercertSubjectName Name
 */
private void logParams(final TransactionLogger transactionLogger,
        final X509Certificate signercert,
        final String signercertIssuerName, final String signercertSubjectName) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.SIGN_ISSUER_NAME_DN, signercertIssuerName);
        transactionLogger.paramPut(
            TransactionLogger.SIGN_SERIAL_NO,
            signercert.getSerialNumber().toByteArray());
        transactionLogger.paramPut(
            TransactionLogger.SIGN_SUBJECT_NAME, signercertSubjectName);
        transactionLogger.paramPut(
            PatternLogger.REPLY_TIME, TransactionLogger.REPLY_TIME);
      }
}

/**
 * @param signercertIssuerName name
 * @param signercertSerNo SN
 * @param signercertSubjectName  Name
 * @param enforceRequestSigning bool
 * @throws SignRequestSignatureException fail
 */
private void handleEnforceSigning(final String signercertIssuerName,
        final BigInteger signercertSerNo,
        final String signercertSubjectName,
        final boolean enforceRequestSigning)
                throws SignRequestSignatureException {
    if (enforceRequestSigning) {
        // If it verifies OK, check if it is revoked
        final String cacheLookupKey =
            OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey(
                signercertIssuerName, signercertSerNo);
        CertificateStatus status =
            OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(
                cacheLookupKey);
        if (status == null) {
          status =
              certificateStoreSession.getStatus(
                  signercertIssuerName, signercertSerNo);
          OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(
              cacheLookupKey, status);
        }
        /*
         * CertificateStatus.NOT_AVAILABLE means that the certificate does not
         * exist in database. We treat this as ok, because it may be
         *  so that only revoked
         * certificates is in the (external) OCSP database.
         */
        if (status.equals(CertificateStatus.REVOKED)) {
          String serno = signercertSerNo.toString(16);
          String infoMsg =
              INTRES.getLocalizedMessage(
                  "ocsp.infosigner.revoked",
                  signercertSubjectName,
                  signercertIssuerName,
                  serno);
          LOG.info(infoMsg);
          throw new SignRequestSignatureException(infoMsg);
        }
      }
}

/**
 * @param ocspRequest req
 * @throws SignRequestException fail
 */
private void assertSigningValid(final OCSPReq ocspRequest)
        throws SignRequestException {
    for (final Req req : ocspRequest.getRequestList()) {
        OcspSigningCacheEntry ocspSigningCacheEntry =
            OcspSigningCache.INSTANCE.getEntry(req.getCertID());
        if (ocspSigningCacheEntry == null) {
          ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getDefaultEntry();
        }
        if (ocspSigningCacheEntry != null
            && ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
          final OcspKeyBinding ocspKeyBinding =
              ocspSigningCacheEntry.getOcspKeyBinding();
          if (ocspKeyBinding.getRequireTrustedSignature()) {
            throw new SignRequestException("Signature required");
          }
        }
      }
}

/**
 * @param transactionLogger log
 * @param ocspRequest req
 */
private void logSetup(final TransactionLogger transactionLogger,
        final OCSPReq ocspRequest) {
    if (ocspRequest.getRequestorName() == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Requestor name is null");
      }
    } else {
      if (transactionLogger.isEnabled() || LOG.isDebugEnabled()) {
        final X500Name requestorDirectoryName =
            (X500Name) ocspRequest.getRequestorName().getName();
        final String requestor =
            CertTools.stringToBCDNString(requestorDirectoryName.toString());
        final String requestorRaw =
            GeneralName.directoryName
                + ": "
                + X500Name.getInstance(
                        CeSecoreNameStyle.INSTANCE, requestorDirectoryName)
                    .toString();
        if (transactionLogger.isEnabled()) {
          transactionLogger.paramPut(TransactionLogger.REQ_NAME, requestor);
          transactionLogger.paramPut(
              TransactionLogger.REQ_NAME_RAW, requestorRaw);
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Requestor name is: '"
                  + requestor
                  + "' Raw: '"
                  + requestorRaw
                  + "'");
        }
      }
    }
}

  /**
   * Checks the signature on an OCSP request. Does not check for revocation of
   * the signer certificate
   *
   * @param clientRemoteAddr The IP address or host name of the remote client
   *     that sent the request, can be null.
   * @param req The signed OCSPReq
   * @return X509Certificate which is the certificate that signed the OCSP
   *     request
   * @throws SignRequestSignatureException if signature verification fail, or if
   *     the signing certificate is not authorized
   * @throws SignRequestException if there is no signature on the OCSPReq
   * @throws CertificateException if the certificate can not be parsed
   * @throws NoSuchAlgorithmException if the certificate contains an unsupported
   *     algorithm
   */
  private X509Certificate checkRequestSignature(
      final String clientRemoteAddr, // NOPMD: compat
      final OCSPReq req)
      throws SignRequestException, SignRequestSignatureException,
          CertificateException, NoSuchAlgorithmException {
    X509Certificate signercert = null;
    // Get all certificates embedded in the request (probably a certificate
    // chain)
    try {
      final X509CertificateHolder[] certs = req.getCerts();
      String signerSubjectDn = null;
      // We must find a certificate to verify the signature with...
      boolean verifyOK = false;
      for (int i = 0; i < certs.length; i++) {
        final X509Certificate certificate =
            certificateConverter.getCertificate(certs[i]);
        try {
          if (req.isSignatureValid(
              CertTools.genContentVerifierProvider(
                  certificate.getPublicKey()))) {
            signercert =
                certificate; // if the request signature verifies by this
                             // certificate, this is the signer cert
            signerSubjectDn = CertTools.getSubjectDN(signercert);
            LOG.info(
                INTRES.getLocalizedMessage("ocsp.infosigner", signerSubjectDn));
            verifyOK = true;
            // Check that the signer certificate can be verified by one of the
            // CA-certificates that we answer for
            final X509Certificate signerca =
                CaCertificateCache.INSTANCE.findLatestBySubjectDN(
                    HashID.getFromIssuerDN(signercert));
            if (signerca != null) {
              try {
                signercert.verify(signerca.getPublicKey());
                final Date now = new Date();
                if (LOG.isDebugEnabled()) {
                  LOG.debug(
                      "Checking validity. Now: "
                          + now
                          + ", signerNotAfter: "
                          + signercert.getNotAfter());
                }
                try {
                  // Check validity of the request signing certificate
                  CertTools.checkValidity(signercert, now);
                } catch (CertificateNotYetValidException e) {
                  verifyOK = handleCertNotValidEx(signercert,
                          signerSubjectDn, e);
                } catch (CertificateExpiredException e) {
                  verifyOK = handleCertExpiredEx(signercert,
                          signerSubjectDn, e);
                }
                try {
                  // Check validity of the CA certificate
                  CertTools.checkValidity(signerca, now);
                } catch (CertificateNotYetValidException e) {
                  verifyOK = handleNotYetValidEx(signerca, e);
                } catch (CertificateExpiredException e) {
                  verifyOK = handleCertExpiredEx(signerca, e);
                }
              } catch (SignatureException e) {
                verifyOK = handleSigEx(signercert, signerSubjectDn, e);
              } catch (InvalidKeyException e) {
                verifyOK = handleKeyEx(signercert, signerSubjectDn, e);
              }
            } else {
              LOG.info(
                  INTRES.getLocalizedMessage(
                      "ocsp.infosigner.nocacert",
                      signerSubjectDn,
                      CertTools.getIssuerDN(signercert)));
              verifyOK = false;
            }
            break;
          }
        } catch (OperatorCreationException e) {
          // Very fatal error
          throw new EJBException("Can not create Jca content signer: ", e);
        }
      }
      assertVerifyOk(certs, signerSubjectDn, verifyOK);
    } catch (OCSPException e) {
      throw new CryptoProviderException(
          "BouncyCastle was not initialized properly.", e);
    } catch (NoSuchProviderException e) {
      throw new CryptoProviderException(
          "BouncyCastle was not found as a provider.", e);
    }
    return signercert;
  }

/**
 * @param certs Certs
 * @param dn DN
 * @param verifyOK VOK
 * @throws CertificateException fail
 * @throws SignRequestSignatureException fail
 */
private void assertVerifyOk(final X509CertificateHolder[] certs,
        final String dn, final boolean verifyOK)
        throws CertificateException, SignRequestSignatureException {
    String signerSubjectDn = dn;
    if (!verifyOK) {
        if (signerSubjectDn == null && certs.length > 0) {
          signerSubjectDn =
              CertTools.getSubjectDN(
                  certificateConverter.getCertificate(certs[0]));
        }
        String errMsg =
            INTRES.getLocalizedMessage(
                "ocsp.errorinvalidsignature", signerSubjectDn);
        LOG.info(errMsg);
        throw new SignRequestSignatureException(errMsg);
      }
}

/**
 * @param signercert cert
 * @param signerSubjectDn DN
 * @param e Ex
 * @return bool
 */
private boolean handleKeyEx(final X509Certificate signercert,
        final String signerSubjectDn, final InvalidKeyException e) {

    LOG.info(
        INTRES.getLocalizedMessage(
            "ocsp.infosigner.invalidcertsignature",
            signerSubjectDn,
            CertTools.getIssuerDN(signercert),
            e.getMessage()));
    return false;
}

/**
 * @param signercert cert
 * @param signerSubjectDn DN
 * @param e Ex
 * @return bool
 */
private boolean handleSigEx(final X509Certificate signercert,
        final String signerSubjectDn, final SignatureException e) {
    LOG.info(
        INTRES.getLocalizedMessage(
            "ocsp.infosigner.invalidcertsignature",
            signerSubjectDn,
            CertTools.getIssuerDN(signercert),
            e.getMessage()));
    return false;
}

/**
 * @param signerca CA
 * @param e ex
 * @return bool
 */
private boolean handleCertExpiredEx(final X509Certificate signerca,
        final CertificateExpiredException e) {
    LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.infosigner.certexpired",
              CertTools.getSubjectDN(signerca),
              CertTools.getIssuerDN(signerca),
              e.getMessage()));
    return false;
}

/**
 * @param signerca CA
 * @param e ex
 * @return bool
 */
private boolean handleNotYetValidEx(final X509Certificate signerca,
        final CertificateNotYetValidException e) {
    LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.infosigner.certnotyetvalid",
              CertTools.getSubjectDN(signerca),
              CertTools.getIssuerDN(signerca),
              e.getMessage()));
    return false;
}

/**
 * @param signercert cert
 * @param signerSubjectDn DN
 * @param e Ex
 * @return bool
 */
private boolean handleCertExpiredEx(
        final X509Certificate signercert,
        final String signerSubjectDn, final CertificateExpiredException e) {
    LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.infosigner.certexpired",
              signerSubjectDn,
              CertTools.getIssuerDN(signercert),
              e.getMessage()));
    return false;
}
/**
 * @param signercert cert
 * @param signerSubjectDn DN
 * @param e Ex
 * @return bool
 */
private boolean handleCertNotValidEx(final X509Certificate signercert,
        final String signerSubjectDn,
        final CertificateNotYetValidException e) {
    LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.infosigner.certnotyetvalid",
              signerSubjectDn,
              CertTools.getIssuerDN(signercert),
              e.getMessage()));
    return false;
}

  private void assertAcceptableResponseExtension(final OCSPReq req)
      throws OcspFailureException {
    if (null == req) {
      throw new IllegalArgumentException();
    }
    if (req.hasExtensions()) {
      final Extension acceptableResponsesExtension =
          req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response);
      if (acceptableResponsesExtension != null) {
        // RFC 6960 4.4.3 AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
        final ASN1Sequence sequence =
            ASN1Sequence.getInstance(
                acceptableResponsesExtension.getExtnValue().getOctets());
        @SuppressWarnings("unchecked")
        final Enumeration<ASN1ObjectIdentifier> oids = sequence.getObjects();
        boolean supportsResponseType = false;
        while (oids.hasMoreElements()) {
          final ASN1ObjectIdentifier oid = oids.nextElement();
          if (oid.equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
            // This is the response type we support, so we are happy! Break the
            // loop.
            supportsResponseType = true;
            if (LOG.isDebugEnabled()) {
              LOG.debug("Response type supported: " + oid.getId());
            }
            break;
          }
        }
        if (!supportsResponseType) {
          final String msg =
              "Required response type not supported, this responder only"
                  + " supports id-pkix-ocsp-basic.";
          LOG.info("OCSP Request type not supported: " + msg);
          throw new OcspFailureException(msg);
        }
      }
    }
  }

  /**
   * When a timer expires, this method will update
   *
   * <p>According to JSR 220 FR (18.2.2), this method may not throw any
   * exceptions.
   *
   * @param timer The timer whose expiration caused this notification.
   */
  @Timeout
  /* Glassfish 2.1.1:
   * "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX
   * attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
   * JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA
   * DataSource transactions.
   */
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void timeoutHandler(final Timer timer) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">timeoutHandler: " + timer.getInfo().toString());
    }
    // reloadTokenAndChainCache cancels old timers and adds a new timer
    reloadOcspSigningCache();
    if (LOG.isTraceEnabled()) {
      LOG.trace("<timeoutHandler");
    }
  }

  /**
   * This method cancels all timers associated with this bean.
   *
   * @param id ID
   */
  // We don't want the appserver to persist/update the timer in the same
  // transaction if they are stored in different non XA DataSources. This method
  // should not be run from within a transaction.
  private void cancelTimers(final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">cancelTimers");
    }
    final Collection<Timer> timers = timerService.getTimers();
    for (final Timer timer : timers) {
      final int currentTimerId = ((Integer) timer.getInfo()).intValue();
      if (currentTimerId == id) {
        timer.cancel();
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<cancelTimers, timers canceled: " + timers.size());
    }
  }

  private int getTimerCount(final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getTimerCount");
    }
    int count = 0;
    final Collection<Timer> timers = timerService.getTimers();
    for (final Timer timer : timers) {
      final int currentTimerId = ((Integer) timer.getInfo()).intValue();
      if (currentTimerId == id) {
        count++;
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getTimerCount, timers: " + count);
    }
    return count;
  }

  /**
   * Adds a timer to the bean.
   *
   * @param interval Interval
   * @param id the id of the timer
   * @return Timer
   */
  // We don't want the appserver to persist/update the timer in the same
  // transaction if they are stored in different non XA DataSources. This method
  // should not be run from within a transaction.
  private Timer addTimer(final long interval, final Integer id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addTimer: " + id + ", interval: " + interval);
    }
    Timer ret = null;
    if (interval > 0) {
      // Create non-persistent timer that fires once
      ret =
          timerService.createSingleActionTimer(
              interval, new TimerConfig(id, false));
      if (LOG.isTraceEnabled()) {
        LOG.trace(
            "<addTimer: "
                + id
                + ", interval: "
                + interval
                + ", "
                + ret.getNextTimeout().toString());
      }
    }
    return ret;
  }

  @Override
  public OcspResponseInformation getOcspResponse(// NOPMD: can't be further red.
      final byte[] request,
      final X509Certificate[] requestCertificates,
      final String remoteAddress,
      final String xForwardedFor,
      final StringBuffer requestUrl,
      final AuditLogger auditLogger,
      final TransactionLogger transactionLogger)
      throws MalformedRequestException, OCSPException {
    // Check parameters
    checkOcspParams(request, auditLogger, transactionLogger);
    final Date startTime = new Date();
    OCSPResp ocspResponse = null;
    // Start logging process time after we have received the request
    startOcspLog(request, auditLogger, transactionLogger);
    OCSPReq req;
    long maxAge =
        OcspConfiguration.getMaxAge(
            CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    OCSPRespBuilder responseGenerator = new OCSPRespBuilder();
    X509Certificate signerCert = null;
    try {
      req =
          translateRequestFromByteArray(
              request, remoteAddress, transactionLogger);
      // Get the certificate status requests that are inside this OCSP req
      Req[] ocspRequests = getOcspRequestArray(auditLogger,
              transactionLogger, req);
      OcspSigningCacheEntry ocspSigningCacheEntry = null;
      long nextUpdate =
          OcspConfiguration.getUntilNextUpdate(
              CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
      Map<ASN1ObjectIdentifier, Extension> responseExtensions = new HashMap<>();

      // Look over the status requests
      List<OCSPResponseItem> responseList = new ArrayList<OCSPResponseItem>();
      boolean addExtendedRevokedExtension = false;
      Date producedAt = null;
      for (Req ocspRequest : ocspRequests) {
        CertificateID certId = getCertId(auditLogger,
                transactionLogger, ocspRequest);
        String hash = getCertHash(certId);
        logInfoRecieved(remoteAddress, xForwardedFor, certId, hash);
        // Locate the CA which gave out the certificate
        ocspSigningCacheEntry = getCacheEntry(certId);
        if (ocspSigningCacheEntry != null) {
          logIssuerDN(transactionLogger, ocspSigningCacheEntry);
        } else {
          /*
           * if the certId was issued by an unknown CA
           *
           * The algorithm here:
           * We will sign the response with the CA that issued the last
           * certificate(certId) in the request. If the issuing CA is not
           * available on
           * this server, we sign the response with the default responderId
           * (from params in web.xml). We have to look up the ca-certificate for
           * each certId in the request though, as we will check for revocation
           * on the ca-cert as well when checking for revocation on the certId.
           */
          // We could not find certificate for this request so get certificate
          // for default responder
          ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getDefaultEntry();
          if (ocspSigningCacheEntry != null) {
            handleDefaultCache(transactionLogger, nextUpdate,
                    responseList, certId);
            continue;
          } else {
            handleNullCache(nextUpdate, responseList, certId);
            continue;
          }
        }

        Collection<String> extensionOids =
                getExtensionOids(ocspSigningCacheEntry);

        // Intended for debugging. Will usually be null
        String alwaysUseOid = getUseOid(extensionOids);

        final org.bouncycastle.cert.ocsp.CertificateStatus certStatus;
        // Check if the cacert (or the default responderid) is revoked
        X509Certificate caCertificate =
            ocspSigningCacheEntry.getIssuerCaCertificate();
        final CertificateStatus signerIssuerCertStatus =
            ocspSigningCacheEntry.getIssuerCaCertificateStatus();
        final String caCertificateSubjectDn =
            CertTools.getSubjectDN(caCertificate);
        CertificateStatusHolder certificateStatusHolder = null;
        OCSPResponseItem respItem;
        if (signerIssuerCertStatus.equals(CertificateStatus.REVOKED)) {
          /*
           * According to chapter 2.7 in RFC2560:
           *
           * 2.7 CA Key Compromise If an OCSP responder knows that a particular
           *  CA's private key has been compromised, it MAY return the revoked
           * state for all certificates issued by that CA.
           */
          // If we've ended up here it's because the signer issuer certificate
          // was revoked.
          certStatus =
              new RevokedStatus(
                  new RevokedInfo(
                      new ASN1GeneralizedTime(
                          signerIssuerCertStatus.getRevocationDate()),
                      CRLReason.lookup(
                          signerIssuerCertStatus.getRevocationReason())));
          LOG.info(
              INTRES.getLocalizedMessage(
                  "ocsp.signcertissuerrevoked",
                  CertTools.getSerialNumberAsString(caCertificate),
                  CertTools.getSubjectDN(caCertificate)));
          respItem = new OCSPResponseItem(certId, certStatus, nextUpdate);
          logOcspRevoked(transactionLogger, signerIssuerCertStatus);
        } else {
          /*
           * Here is the actual check for the status of the sought certificate
           * (easy to miss). Here we grab just the status if there aren't any
           * OIDs defined (default case), but if there are we'll probably need
           * the certificate as well. If that's the case, we'll grab the
           * certificate in the same transaction.
           */
          final CertificateStatus status;
          final long k = 1000L;
          if (extensionOids.isEmpty()) {
            status =
                certificateStoreSession.getStatus(
                    caCertificateSubjectDn, certId.getSerialNumber());
          } else {
            certificateStatusHolder =
                certificateStoreSession.getCertificateAndStatus(
                    caCertificateSubjectDn, certId.getSerialNumber());
            status = certificateStatusHolder.getCertificateStatus();
          }
          logProfileID(transactionLogger, status);
          // If we have an OcspKeyBinding configured for this request, we
          // override the default value
          nextUpdate = setNextUpdate(ocspSigningCacheEntry, nextUpdate,
                  status, k);
          // If we have an OcspKeyBinding configured for this request, we
          // override the default value
          maxAge = setMaxAge(maxAge, ocspSigningCacheEntry, status, k);

          final String sStatus;
          boolean addArchiveCutoff = false;
          if (status.equals(CertificateStatus.NOT_AVAILABLE)) {
            // No revocation info available for this cert, handle it
            logDebugRevFail(certId, caCertificateSubjectDn);
            /*
             * If we do not treat non existing certificates as good or revoked
             * OR
             * we don't actually handle requests for the CA issuing
             * the certificate asked about
             * then we return unknown
             * */
            if (OcspConfigurationCache.INSTANCE.isNonExistingGood(
                    requestUrl, ocspSigningCacheEntry.getOcspKeyBinding())
                && OcspSigningCache.INSTANCE.getEntry(certId) != null) {
              sStatus = "good";
              certStatus = null; // null means "good" in OCSP
              logOcspGood(transactionLogger);
            } else if (OcspConfigurationCache.INSTANCE.isNonExistingRevoked(
                    requestUrl, ocspSigningCacheEntry.getOcspKeyBinding())
                && OcspSigningCache.INSTANCE.getEntry(certId) != null) {
              sStatus = "revoked";
              certStatus =
                  new RevokedStatus(
                      new RevokedInfo(
                          new ASN1GeneralizedTime(new Date(0)),
                          CRLReason.lookup(CRLReason.certificateHold)));
              logHold(transactionLogger);
              addExtendedRevokedExtension = true;
            } else if (OcspConfigurationCache.INSTANCE
                    .isNonExistingUnauthorized(
                        ocspSigningCacheEntry.getOcspKeyBinding())
                && OcspSigningCache.INSTANCE.getEntry(certId) != null) {
              // In order to save on cycles and mitigate the chances of a DOS
              // attack, we'll return a unsigned unauthorized reply.
              ocspResponse =
                  responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
              logUnAuth(auditLogger, transactionLogger);
              LOG.info(
                  INTRES.getLocalizedMessage(
                      "ocsp.errorfindcert",
                      certId.getSerialNumber().toString(16),
                      caCertificateSubjectDn));
              // Return early here
              return new OcspResponseInformation(ocspResponse, maxAge, null);
            } else {
              sStatus = "unknown";
              certStatus = new UnknownStatus();
              logRevocation(transactionLogger);
            }
          } else if (status.equals(CertificateStatus.REVOKED)) {
            // Revocation info available for this cert, handle it
            sStatus = "revoked";
            certStatus =
                new RevokedStatus(
                    new RevokedInfo(
                        new ASN1GeneralizedTime(status.getRevocationDate()),
                        CRLReason.lookup(status.getRevocationReason())));
            logRevoked(transactionLogger, status);
            // If we have an explicit value configured for this certificate
            // profile, we override the the current value with this value
            nextUpdate = updateNextUpdate(nextUpdate, status);
            // If we have an explicit value configured for this certificate
            // profile, we override the the current value with this value
            maxAge = updateMaxAge(maxAge, status);
          } else {
            sStatus = "good";
            certStatus = null;
            logGood(transactionLogger);
            addArchiveCutoff =
                checkAddArchiveCuttoff(caCertificateSubjectDn, certId);
          }
          logDebugMaxAge(maxAge, nextUpdate, certId, caCertificateSubjectDn,
                  status, sStatus);
          respItem = new OCSPResponseItem(certId, certStatus, nextUpdate);
          producedAt = handleArchCutOff(producedAt, respItem, addArchiveCutoff);
          flushTransLog(transactionLogger);
        }

        handleOcspExtensions(requestCertificates, remoteAddress,
                req, ocspSigningCacheEntry, responseExtensions,
                extensionOids, alwaysUseOid, certStatus,
                certificateStatusHolder, respItem);
        responseList.add(respItem);
      }
      handleRevokedExtension(responseExtensions, addExtendedRevokedExtension);
      if (ocspSigningCacheEntry != null) {
        // Add standard response extensions
        responseExtensions.putAll(
            getStandardResponseExtensions(req, ocspSigningCacheEntry));

        signerCert = ocspSigningCacheEntry.getSigningCertificate();
        ocspResponse = buildBasicResp(auditLogger, transactionLogger,
                req, responseGenerator, ocspSigningCacheEntry,
                responseExtensions, responseList, producedAt);
      } else {
        // Only unknown CAs in requests and no default responder's cert, return
        // an unsigned response
        ocspResponse = buildUnsignedResp(auditLogger,
                transactionLogger, responseGenerator);
      }
    } catch (SignRequestException e) {
      ocspResponse = handleSignReqException(auditLogger,
              transactionLogger, responseGenerator, e);
    } catch (SignRequestSignatureException | IllegalNonceException e) {
      ocspResponse = handleSigException(auditLogger,
              transactionLogger, responseGenerator, e);
    } catch (InvalidAlgorithmException e) {
      ocspResponse = handleAlgException(auditLogger,
              transactionLogger, responseGenerator, e);
    } catch (NoSuchAlgorithmException e) {
      ocspResponse =
          processDefaultError(
              responseGenerator, transactionLogger, auditLogger, e);
    } catch (CertificateException e) {
      ocspResponse =
          processDefaultError(
              responseGenerator, transactionLogger, auditLogger, e);
    } catch (CryptoTokenOfflineException e) {
      ocspResponse =
          processDefaultError(
              responseGenerator, transactionLogger, auditLogger, e);
    }
    ocspResponse = buildResponse(auditLogger, transactionLogger, startTime,
            ocspResponse, responseGenerator);
    return new OcspResponseInformation(ocspResponse, maxAge, signerCert);
  }

/**
 * @param p datr
 * @param respItem item
 * @param addArchiveCutoff bool
 * @return date
 */
private Date handleArchCutOff(final Date p,
        final OCSPResponseItem respItem, final boolean addArchiveCutoff) {
    Date producedAt = p;
    if (addArchiveCutoff) {
        addArchiveCutoff(respItem);
        producedAt = new Date();
      }
    return producedAt;
}

/**
 * @param transactionLogger log
 */
private void flushTransLog(final TransactionLogger transactionLogger) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.writeln();
      }
}

/**
 * @param maxAge Age
 * @param nextUpdate Update
 * @param certId ID
 * @param caCertificateSubjectDn DN
 * @param status Status
 * @param sStatus Sign
 */
private void logDebugMaxAge(final long maxAge, final long nextUpdate,
        final CertificateID certId,
        final String caCertificateSubjectDn,
        final CertificateStatus status, final String sStatus) {
    if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Set nextUpdate="
                + nextUpdate
                + ", and maxAge="
                + maxAge
                + " for certificateProfileId="
                + status.getCertificateProfileId());
      }
      LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.infoaddedstatusinfo",
              sStatus,
              certId.getSerialNumber().toString(16),
              caCertificateSubjectDn));
}

/**
 * @param certId ID
 * @param caCertificateSubjectDn DN
 */
private void logDebugRevFail(final CertificateID certId,
        final String caCertificateSubjectDn) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Unable to find revocation information for certificate with"
              + " serial '"
              + certId.getSerialNumber().toString(16)
              + "'"
              + " from issuer '"
              + caCertificateSubjectDn
              + "'");
    }
}

/**
 * @param transactionLogger Logger
 */
private void logOcspGood(final TransactionLogger transactionLogger) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_GOOD);
        transactionLogger.paramPut(
            TransactionLogger.REV_REASON, CRLReason.certificateHold);
      }
}

/**
 * @param transactionLogger Logger
 * @param status Status
 */
private void logProfileID(final TransactionLogger transactionLogger,
        final CertificateStatus status) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.CERT_PROFILE_ID,
            String.valueOf(status.getCertificateProfileId()));
      }
}

/**
 * @param transactionLogger Logger
 * @param signerIssuerCertStatus Status
 */
private void logOcspRevoked(final TransactionLogger transactionLogger,
        final CertificateStatus signerIssuerCertStatus) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_REVOKED);
        transactionLogger.paramPut(
            TransactionLogger.REV_REASON,
            signerIssuerCertStatus.getRevocationReason());
        transactionLogger.writeln();
      }
}

/**
 * @param transactionLogger log
 */
private void logGood(final TransactionLogger transactionLogger) {
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_GOOD);
    }
}

/**
 * @param transactionLogger log
 */
private void logHold(final TransactionLogger transactionLogger) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.CERT_STATUS,
            OCSPResponseItem.OCSP_REVOKED);
        transactionLogger.paramPut(
            TransactionLogger.REV_REASON, CRLReason.certificateHold);
      }
}

/**
 * @param transactionLogger log
 * @param status status
 */
private void logRevoked(final TransactionLogger transactionLogger,
        final CertificateStatus status) {
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_REVOKED);
      transactionLogger.paramPut(
          TransactionLogger.REV_REASON, status.getRevocationReason());
    }
}

/**
 * @param transactionLogger log
 */
private void logRevocation(final TransactionLogger transactionLogger) {
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.CERT_STATUS,
            OCSPResponseItem.OCSP_UNKNOWN);
        transactionLogger.paramPut(
            TransactionLogger.REV_REASON, CRLReason.certificateHold);
      }
}

/**
 * @param auditLogger log
 * @param transactionLogger log
 */
private void logUnAuth(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger) {
    if (auditLogger.isEnabled()) {
        auditLogger.paramPut(
            AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
      }
      if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
      }
}

/**
 * @param auditLogger log
 * @param transactionLogger log
 * @param startTime start
 * @param o resp
 * @param responseGenerator gen
 * @return resp
 * @throws OCSPException fail
 */
private OCSPResp buildResponse(
        final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final Date startTime,
        final OCSPResp o,
        final OCSPRespBuilder responseGenerator) throws OCSPException {
    byte[] respBytes;
    OCSPResp ocspResponse = o;
    try {
      respBytes = ocspResponse.getEncoded();
      ocspResponse = buildRespFromBytes(auditLogger, transactionLogger,
              respBytes, startTime, ocspResponse,
            responseGenerator);
    } catch (IOException e) {
      flushLoggers(auditLogger, transactionLogger, e);
    }
    return ocspResponse;
}

/**
 * @param certId ID
 * @return Cache
 * @throws CertificateEncodingException fail
 */
private OcspSigningCacheEntry getCacheEntry(final CertificateID certId)
        throws CertificateEncodingException {
    OcspSigningCacheEntry ocspSigningCacheEntry;
    ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getEntry(certId);
    if (ocspSigningCacheEntry == null) {
      // Could it be that we haven't updated the OCSP Signing Cache?
      ocspSigningCacheEntry = findAndAddMissingCacheEntry(certId);
    }
    return ocspSigningCacheEntry;
}

/**
 * @param m age
 * @param status status
 * @return max age
 */
private long updateMaxAge(final long m, final CertificateStatus status) {
    long maxAge = m;
    if (status.getCertificateProfileId()
            != CertificateProfileConstants.CERTPROFILE_NO_PROFILE
        && OcspConfiguration.isRevokedMaxAgeConfigured(
            status.getCertificateProfileId())) {
      maxAge =
          OcspConfiguration.getRevokedMaxAge(
              status.getCertificateProfileId());
    }
    return maxAge;
}

/**
 * @param n update
 * @param status status
 * @return new update
 */
private long updateNextUpdate(
        final long n, final CertificateStatus status) {
    long nextUpdate = n;
    if (status.getCertificateProfileId()
            != CertificateProfileConstants.CERTPROFILE_NO_PROFILE
        && OcspConfiguration.isRevokedUntilNextUpdateConfigured(
            status.getCertificateProfileId())) {
      nextUpdate =
          OcspConfiguration.getRevokedUntilNextUpdate(
              status.getCertificateProfileId());
    }
    return nextUpdate;
}

/**
 * @param certId ID
 * @return Hash
 */
private String getCertHash(final CertificateID certId) {
    byte[] hashbytes = certId.getIssuerNameHash();
    String hash = null;
    if (hashbytes != null) {
      hash = new String(Hex.encode(hashbytes));
    }
    return hash;
}

/**
 * @param extensionOids OIDs
 * @return Use
 */
private String getUseOid(final Collection<String> extensionOids) {
    String alwaysUseOid =
        OcspConfiguration.getAlwaysSendCustomOCSPExtension();
    if (alwaysUseOid != null && !extensionOids.contains(alwaysUseOid)) {
      extensionOids.add(alwaysUseOid);
    }
    return alwaysUseOid;
}

/**
 * @param nextUpdate date
 * @param responseList list
 * @param certId ID
 */
private void handleNullCache(final long nextUpdate,
        final List<OCSPResponseItem> responseList,
        final CertificateID certId) {
    GlobalOcspConfiguration ocspConfiguration =
        (GlobalOcspConfiguration)
            globalConfigurationSession.getCachedConfiguration(
                GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
    String defaultResponder =
        ocspConfiguration.getOcspDefaultResponderReference();
    String errMsg =
        INTRES.getLocalizedMessage(
            "ocsp.errorfindcacert",
            new String(Hex.encode(certId.getIssuerNameHash())),
            defaultResponder);
    LOG.error(errMsg);
    // If we are responding to multiple requests, the last found
    // ocspSigningCacheEntry will be used in the end
    // so even if there are not any one now, it might be later when it
    // is time to sign the responses.
    // Since we only will sign the entire response once if there is at
    // least one valid ocspSigningCacheEntry
    // we might as well include the unknown requests.
    responseList.add(
        new OCSPResponseItem(certId, new UnknownStatus(), nextUpdate));
}

/**
 * @param transactionLogger Log
 * @param ocspSigningCacheEntry Entry
 */
private void logIssuerDN(final TransactionLogger transactionLogger,
        final OcspSigningCacheEntry ocspSigningCacheEntry) {
    if (transactionLogger.isEnabled()) {
        // This will be the issuer DN of the signing certificate, whether an
        // OCSP responder or an internal CA
        transactionLogger.paramPut(
            TransactionLogger.ISSUER_NAME_DN,
            ocspSigningCacheEntry.getSigningCertificateIssuerDn());
        transactionLogger.paramPut(
            TransactionLogger.ISSUER_NAME_DN_RAW,
            ocspSigningCacheEntry.getSigningCertificateIssuerDnRaw());
      }
}

/**
 * @param transactionLogger Logger
 * @param nextUpdate Update
 * @param responseList List
 * @param certId ID
 */
private void handleDefaultCache(final TransactionLogger transactionLogger,
        final long nextUpdate,
        final List<OCSPResponseItem> responseList,
        final CertificateID certId) {
    String errMsg =
        INTRES.getLocalizedMessage(
            "ocsp.errorfindcacertusedefault",
            new String(Hex.encode(certId.getIssuerNameHash())));
    LOG.info(errMsg);
    // If we can not find the CA, answer UnknowStatus
    responseList.add(
        new OCSPResponseItem(certId, new UnknownStatus(), nextUpdate));
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_UNKNOWN);
      transactionLogger.writeln();
    }
}

/**
 * @param auditLogger Log
 * @param transactionLogger Log
 * @param e ex
 */
private void flushLoggers(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger, final IOException e) {
    LOG.error("Unexpected IOException caught.", e);
      if (transactionLogger.isEnabled()) {
        transactionLogger.flush();
      }
      if (auditLogger.isEnabled()) {
        auditLogger.flush();
      }
}

/**
 * @param m ahe
 * @param ocspSigningCacheEntry cache
 * @param status Status
 * @param k Mul
 * @return Age
 */
private long setMaxAge(final long m,
        final OcspSigningCacheEntry ocspSigningCacheEntry,
        final CertificateStatus status,
        final long k) {
    long maxAge = m;
    if (ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
        maxAge =
            ocspSigningCacheEntry.getOcspKeyBinding().getMaxAge() * k;
      }
      // If we have an explicit value configured for this certificate
      // profile, we override the the current value with this value
      if (status.getCertificateProfileId()
              != CertificateProfileConstants.CERTPROFILE_NO_PROFILE
          && OcspConfiguration.isMaxAgeConfigured(
              status.getCertificateProfileId())) {
        maxAge =
            OcspConfiguration.getMaxAge(status.getCertificateProfileId());
      }
    return maxAge;
}

/**
 * @param ocspSigningCacheEntry cacke
 * @param n date
 * @param status status
 * @param k mul
 * @return sate
 */
private long setNextUpdate(final OcspSigningCacheEntry ocspSigningCacheEntry,
        final long n,
        final CertificateStatus status,
        final long k) {
    long nextUpdate = n;
    if (ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
        nextUpdate =
            ocspSigningCacheEntry.getOcspKeyBinding().getUntilNextUpdate()
                * k;
      }
      // If we have an explicit value configured for this certificate
      // profile, we override the the current value with this value
      if (status.getCertificateProfileId()
              != CertificateProfileConstants.CERTPROFILE_NO_PROFILE
          && OcspConfiguration.isUntilNextUpdateConfigured(
              status.getCertificateProfileId())) {
        nextUpdate =
            OcspConfiguration.getUntilNextUpdate(
                status.getCertificateProfileId());
      }
    return nextUpdate;
}

/**
 * @param remoteAddress addr
 * @param xForwardedFor dwd
 * @param certId id
 * @param hash hash
 */
private void logInfoRecieved(final String remoteAddress,
        final String xForwardedFor, final CertificateID certId,
        final String hash) {
    if (xForwardedFor == null) {
      LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.inforeceivedrequest",
              certId.getSerialNumber().toString(16),
              hash,
              remoteAddress));
    } else {
      LOG.info(
          INTRES.getLocalizedMessage(
              "ocsp.inforeceivedrequestwxff",
              certId.getSerialNumber().toString(16),
              hash,
              remoteAddress,
              xForwardedFor));
    }
}

/**
 * @param auditLogger log
 * @param transactionLogger log
 * @param ocspRequest req
 * @return ID
 * @throws InvalidAlgorithmException fail
 */
private CertificateID getCertId(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final Req ocspRequest) throws InvalidAlgorithmException {
    CertificateID certId = ocspRequest.getCertID();
    ASN1ObjectIdentifier certIdhash = certId.getHashAlgOID();
    if (!OIWObjectIdentifiers.idSHA1.equals(certIdhash)
        && !NISTObjectIdentifiers.id_sha256.equals(certIdhash)) {
      throw new InvalidAlgorithmException(
          "CertID with SHA1 and SHA256 are supported, not: "
              + certIdhash.getId());
    }
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          TransactionLogger.SERIAL_NOHEX,
          certId.getSerialNumber().toByteArray());
      transactionLogger.paramPut(
          TransactionLogger.DIGEST_ALGOR,
          certId.getHashAlgOID().toString());
      transactionLogger.paramPut(
          TransactionLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
      transactionLogger.paramPut(
          TransactionLogger.ISSUER_KEY, certId.getIssuerKeyHash());
    }
    if (auditLogger.isEnabled()) {
      auditLogger.paramPut(
          AuditLogger.ISSUER_KEY, certId.getIssuerKeyHash());
      auditLogger.paramPut(
          AuditLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
      auditLogger.paramPut(
          AuditLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
    }
    return certId;
}

/**
 * @param responseExtensions ests
 * @param addExtendedRevokedExtension bool
 * @throws IllegalStateException fail
 */
private void handleRevokedExtension(
        final Map<ASN1ObjectIdentifier, Extension> responseExtensions,
        final boolean addExtendedRevokedExtension)
                throws IllegalStateException {
    if (addExtendedRevokedExtension) {
        // id-pkix-ocsp-extended-revoke OBJECT IDENTIFIER ::= {id-pkix-ocsp 9}
        final ASN1ObjectIdentifier extendedRevokedOID =
            OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke;
        try {
          responseExtensions.put(
              extendedRevokedOID,
              new Extension(
                  extendedRevokedOID, false, DERNull.INSTANCE.getEncoded()));
        } catch (IOException e) {
          throw new IllegalStateException(
              "Could not get encoding from DERNull.", e);
        }
      }
}

/**
 * @param auditLogger Logger
 * @param transactionLogger Logger
 * @param req Request
 * @param responseGenerator Generator
 * @param ocspSigningCacheEntry Cache
 * @param responseExtensions Ests
 * @param responseList List
 * @param producedAt Date
 * @return Response
 * @throws CryptoTokenOfflineException fail
 * @throws OCSPException fail
 */
private OCSPResp buildBasicResp(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger, final OCSPReq req,
        final OCSPRespBuilder responseGenerator,
        final OcspSigningCacheEntry ocspSigningCacheEntry,
        final Map<ASN1ObjectIdentifier, Extension> responseExtensions,
        final List<OCSPResponseItem> responseList, final Date producedAt)
        throws CryptoTokenOfflineException, OCSPException {
    OCSPResp ocspResponse;
    // Add responseExtensions
    Extensions exts =
        new Extensions(
            responseExtensions.values().toArray(new Extension[0]));
    // generate the signed response object
    BasicOCSPResp basicresp =
        signOcspResponse(
            req, responseList, exts, ocspSigningCacheEntry, producedAt);
    ocspResponse =
        responseGenerator.build(OCSPRespBuilder.SUCCESSFUL, basicresp);
    if (auditLogger.isEnabled()) {
      auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
    }
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          TransactionLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
    }
    return ocspResponse;
}

/**
 * @param auditLogger Log
 * @param transactionLogger Log
 * @param respBytes Bytes
 * @param startTime Time
 * @param oocspResponse Resp
 * @param responseGenerator Gen
 * @return Resp
 * @throws OCSPException fail
 */
private OCSPResp buildRespFromBytes(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final byte[] respBytes,
        final Date startTime, final OCSPResp oocspResponse,
        final OCSPRespBuilder responseGenerator)
        throws OCSPException {
    OCSPResp ocspResponse = oocspResponse;
    if (auditLogger.isEnabled()) {
        auditLogger.paramPut(
            AuditLogger.OCSPRESPONSE, new String(Hex.encode(respBytes)));
        auditLogger.writeln();
        auditLogger.flush();
      }
      if (transactionLogger.isEnabled()) {
        transactionLogger.flush();
      }
      if (OcspConfiguration.getLogSafer()) {
        // See if the Errorhandler has found any problems
        if (hasErrorHandlerFailedSince(startTime)) {
          LOG.info(
              "ProbableErrorhandler reported error, cannot answer request");
          // RFC 2560: responseBytes are not set on error.
          ocspResponse =
              responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null);
        }
        // See if the Appender has reported any problems
        if (!CanLogCache.INSTANCE.canLog()) {
          LOG.info(
              "SaferDailyRollingFileAppender reported error, cannot answer"
                  + " request");
          // RFC 2560: responseBytes are not set on error.
          ocspResponse =
              responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null);
        }
      }
    return ocspResponse;
}

/**
 * @param auditLogger Log
 * @param transactionLogger Log
 * @param responseGenerator Gen
 * @return Resp
 * @throws OCSPException Fail
 */
private OCSPResp buildUnsignedResp(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final OCSPRespBuilder responseGenerator) throws OCSPException {
    OCSPResp ocspResponse;
    if (LOG.isDebugEnabled()) {
      LOG.debug(INTRES.getLocalizedMessage("ocsp.errornocacreateresp"));
    }
    ocspResponse =
        responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
    logUnAuth(auditLogger, transactionLogger);
    return ocspResponse;
}

/**
 * @param auditLogger Log
 * @param transactionLogger Log
 * @param req Req
 * @return Return
 * @throws MalformedRequestException Fail
 */
private Req[] getOcspRequestArray(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger, final OCSPReq req)
        throws MalformedRequestException {
    Req[] ocspRequests = req.getRequestList();
      if (ocspRequests.length <= 0) {
        String infoMsg = INTRES.getLocalizedMessage("ocsp.errornoreqentities");
        LOG.info(infoMsg);
        throw new MalformedRequestException(infoMsg);
      }
      final int maxRequests = 100;
      if (ocspRequests.length > maxRequests) {
        String infoMsg =
            INTRES.getLocalizedMessage(
                "ocsp.errortoomanyreqentities", maxRequests);
        LOG.info(infoMsg);
        throw new MalformedRequestException(infoMsg);
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "The OCSP request contains "
                + ocspRequests.length
                + " simpleRequests.");
      }
      if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.NUM_CERT_ID, ocspRequests.length);
        transactionLogger.paramPut(
            TransactionLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
      }
    return ocspRequests;
}

/**
 * @param auditLogger Audit
 * @param transactionLogger Trans
 * @param responseGenerator Resp
 * @param e exception
 * @return response
 * @throws OCSPException fail
 */
private OCSPResp handleAlgException(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final OCSPRespBuilder responseGenerator,
        final InvalidAlgorithmException e) throws OCSPException {
    OCSPResp ocspResponse;
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(
            PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      }
      String errMsg =
          INTRES.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
      LOG.info(errMsg); // No need to log the full exception here
      // RFC 2560: responseBytes are not set on error.
      ocspResponse =
          responseGenerator.build(OCSPRespBuilder.MALFORMED_REQUEST, null);
      if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
        transactionLogger.writeln();
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(
            AuditLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
      }
    return ocspResponse;
}

/**
 * @param auditLogger Audit
 * @param transactionLogger Trans
 * @param responseGenerator Resp
 * @param e exception
 * @return response
 * @throws OCSPException fail
 */
private OCSPResp handleSigException(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final OCSPRespBuilder responseGenerator, final CesecoreException e)
                throws OCSPException {
    OCSPResp ocspResponse;
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(
            PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      }
      String errMsg =
          INTRES.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
      LOG.info(errMsg); // No need to log the full exception here
      // RFC 2560: responseBytes are not set on error.
      ocspResponse =
          responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
      if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
        transactionLogger.writeln();
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
      }
    return ocspResponse;
}

/**
 * @param auditLogger Audit
 * @param transactionLogger Trans
 * @param responseGenerator Resp
 * @param e exception
 * @return response
 * @throws OCSPException fail
 */
private OCSPResp handleSignReqException(final AuditLogger auditLogger,
        final TransactionLogger transactionLogger,
        final OCSPRespBuilder responseGenerator, final SignRequestException e)
                throws OCSPException {
    OCSPResp ocspResponse;
    if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(
            PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      }
      String errMsg =
          INTRES.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
      LOG.info(errMsg); // No need to log the full exception here
      // RFC 2560: responseBytes are not set on error.
      ocspResponse =
          responseGenerator.build(OCSPRespBuilder.SIG_REQUIRED, null);
      if (transactionLogger.isEnabled()) {
        transactionLogger.paramPut(
            TransactionLogger.STATUS, OCSPRespBuilder.SIG_REQUIRED);
        transactionLogger.writeln();
      }
      if (auditLogger.isEnabled()) {
        auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SIG_REQUIRED);
      }
    return ocspResponse;
}

/**
 * @param requestCertificates Certs
 * @param remoteAddress Address
 * @param req Request
 * @param ocspSigningCacheEntry Cache
 * @param responseExtensions Exts
 * @param extensionOids Oids
 * @param alwaysUseOid Bol
 * @param certStatus Status
 * @param certificateStatusHolder Holder
 * @param respItem Response
 */
private void handleOcspExtensions(final X509Certificate[] requestCertificates,
        final String remoteAddress,
        final OCSPReq req,
        final OcspSigningCacheEntry ocspSigningCacheEntry,
        final Map<ASN1ObjectIdentifier, Extension> responseExtensions,
        final Collection<String> extensionOids,
        final String alwaysUseOid,
        final org.bouncycastle.cert.ocsp.CertificateStatus certStatus,
        final CertificateStatusHolder certificateStatusHolder,
        final OCSPResponseItem respItem) {
    for (String oidstr : extensionOids) {
      boolean useAlways = false;
      if (oidstr.equals(alwaysUseOid)) {
        useAlways = true;
      }
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidstr);
      Extension extension = null;
      if (!useAlways && req.hasExtensions()) {
          extension = req.getExtension(oid);

      }
      // If found, or if it should be used anyway
      if (useAlways || extension != null) {
        // We found an extension, call the extension class
        if (LOG.isDebugEnabled()) {
          LOG.debug("Found OCSP extension oid: " + oidstr);
        }
        OCSPExtension extObj =
            OcspExtensionsCache.INSTANCE.getExtensions().get(oidstr);
        if (extObj != null
                && certificateStatusHolder != null
              && certificateStatusHolder.getCertificate() != null) {
            X509Certificate cert =
                (X509Certificate) certificateStatusHolder.getCertificate();
            // From EJBCA 6.2.10 and 6.3.2 the extension must perform the
            // reverse DNS lookup by itself if needed.
            final String remoteHost = remoteAddress;
            // Call the OCSP extension
            Map<ASN1ObjectIdentifier, Extension> retext = null;
            retext =
                extObj.process(
                    requestCertificates,
                    remoteAddress,
                    remoteHost,
                    cert,
                    certStatus,
                    ocspSigningCacheEntry.getOcspKeyBinding());
            if (retext != null) {
              // Add the returned X509Extensions to the responseExtension we
              // will add to the basic OCSP response
              if (extObj
                  .getExtensionType()
                  .contains(OCSPExtensionType.RESPONSE)) {
                responseExtensions.putAll(retext);
              }
              if (extObj
                  .getExtensionType()
                  .contains(OCSPExtensionType.SINGLE_RESPONSE)) {
                respItem.addExtensions(retext);
              }
            } else {
              LOG.error(
                  INTRES.getLocalizedMessage(
                      "ocsp.errorprocessextension",
                      extObj.getClass().getName(),
                      Integer.valueOf(extObj.getLastErrorCode())));
            }

        }
      }
    }
}

/**
 * @param ocspSigningCacheEntry cache
 * @return oids
 */
private Collection<String> getExtensionOids(
        final OcspSigningCacheEntry ocspSigningCacheEntry) {
    Collection<String> extensionOids = new ArrayList<>();
    if (ocspSigningCacheEntry.getOcspKeyBinding() != null) {
      extensionOids =
          ocspSigningCacheEntry.getOcspKeyBinding().getOcspExtensions();
    }
    return extensionOids;
}

/**
 * @param request req
 * @param auditLogger logger
 * @param transactionLogger logger
 */
private void startOcspLog(final byte[] request, final AuditLogger auditLogger,
        final TransactionLogger transactionLogger) {
    if (transactionLogger.isEnabled()) {
      transactionLogger.paramPut(
          PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
    }
    if (auditLogger.isEnabled()) {
      auditLogger.paramPut(
          PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
      auditLogger.paramPut(
          AuditLogger.OCSPREQUEST, new String(Hex.encode(request)));
    }
}

/**
 * @param request req
 * @param auditLogger logger
 * @param transactionLogger logger
 * @throws InvalidParameterException fail
 * @throws MalformedRequestException fail
 */
private void checkOcspParams(final byte[] request,
        final AuditLogger auditLogger,
        final TransactionLogger transactionLogger)
                throws InvalidParameterException, MalformedRequestException {
    if (auditLogger == null) {
      throw new InvalidParameterException(
          "Illegal to pass a null audit logger to"
              + " OcspResponseSession.getOcspResponse");
    }
    if (transactionLogger == null) {
      throw new InvalidParameterException(
          "Illegal to pass a null transaction logger to"
              + " OcspResponseSession.getOcspResponse");
    }
    // Validate byte array.
    if (request.length > MAX_REQUEST_SIZE) {
      final String msg =
          INTRES.getLocalizedMessage(
              "request.toolarge", MAX_REQUEST_SIZE, request.length);
      throw new MalformedRequestException(msg);
    }
}

  private boolean checkAddArchiveCuttoff(
      final String caCertificateSubjectDn, final CertificateID certId) {
    if (OcspConfiguration.getExpiredArchiveCutoff() == -1) {
      return false;
    }
    CertificateInfo info =
        certificateStoreSession.findFirstCertificateInfo(
            caCertificateSubjectDn, certId.getSerialNumber());
    Date expDate = info.getExpireDate();
    if (expDate.before(new Date())) {
      LOG.info(
          "Certificate with serial number '"
              + certId.getSerialNumber()
              + "' is not valid. "
              + "Adding singleExtension id-pkix-ocsp-archive-cutoff");
      return true;
    }
    return false;
  }

  private void addArchiveCutoff(final OCSPResponseItem respItem) {
    long archPeriod = OcspConfiguration.getExpiredArchiveCutoff();
    if (archPeriod == -1) {
      return;
    }
    long res = System.currentTimeMillis() - archPeriod;
    ASN1OctetString archiveCutoffValue;
    try {
      archiveCutoffValue =
          new DEROctetString(new ASN1GeneralizedTime(new Date(res)));
    } catch (IOException e) {
      throw new IllegalStateException(
          "IOException was caught when decoding static value.", e);
    }
    Extension archiveCutoff =
        new Extension(
            OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff,
            false,
            archiveCutoffValue);
    respItem.addExtensions(
        Collections.singletonMap(
            OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, archiveCutoff));
  }

  /**
   * returns a Map of responseExtensions to be added to the
   * BacisOCSPResponseGenerator with <code>
   * X509Extensions exts = new X509Extensions(table);
   * basicRes.setResponseExtensions(responseExtensions).
   * </code>
   *
   * @param req the OCSP request
   * @param ocspSigningCacheEntry the OCSP signing cache entry used
   * @return a HashMap, can be empty but not null
   * @throws IllegalNonceException if Nonce is larger than 32 bytes
   */
  private Map<ASN1ObjectIdentifier, Extension> getStandardResponseExtensions(
      final OCSPReq req, final OcspSigningCacheEntry ocspSigningCacheEntry)
      throws IllegalNonceException {
    HashMap<ASN1ObjectIdentifier, Extension> result = new HashMap<>();
    if (req.hasExtensions()) {
      // Table of extensions to include in the response
      // OCSP Nonce, if included in the request, the response must include the
      // same according to RFC6960
      Extension ext =
          req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      // Check the keybinding firsthand if nonce's are enabled, if there is no
      // keybinding (because a CA is replying), check the global value.
      boolean nonceEnable =
          ocspSigningCacheEntry.getOcspKeyBinding() != null
              ? ocspSigningCacheEntry.getOcspKeyBinding().isNonceEnabled()
              : ((GlobalOcspConfiguration)
                      globalConfigurationSession.getCachedConfiguration(
                          GlobalOcspConfiguration.OCSP_CONFIGURATION_ID))
                  .getNonceEnabled();
      if (null != ext && nonceEnable) {
        ASN1OctetString noncestr = ext.getExtnValue();
        // Limit Nonce to 32 bytes to avoid chosen-prefix attack on hash
        // collisions.
        // See
        // https://groups.google.com/forum/#!topic/mozilla.dev.security.policy
        //       /x3TOIJL7MGw
        final int max = 32;
        if (noncestr != null
            && noncestr.getOctets() != null
            && noncestr.getOctets().length > max) {
          LOG.info(
              "Received OCSP request with Nonce larger than 32 bytes,"
                  + " rejecting.");
          throw new IllegalNonceException("Nonce too large");
        }
        result.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
      }
    }
    return result;
  }

  /**
   * This method handles cache misses where there exists an active key binding
   * which hasn't been cached.
   *
   * @param certId the CertificateID for the certificate being requested.
   * @return the now cached entry, or null if none was found.
   * @throws CertificateEncodingException on fail
   */
  private OcspSigningCacheEntry findAndAddMissingCacheEntry(
      final CertificateID certId) throws CertificateEncodingException {
    OcspSigningCacheEntry ocspSigningCacheEntry = null;
    for (final int internalKeyBindingId
        : internalKeyBindingDataSession.getIds(
            OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
      final OcspKeyBinding ocspKeyBinding =
          (OcspKeyBinding)
              internalKeyBindingDataSession.getInternalKeyBinding(
                  internalKeyBindingId);
      if (ocspKeyBinding.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
        X509Certificate ocspCertificate =
            (X509Certificate)
                certificateStoreSession.findCertificateByFingerprint(
                    ocspKeyBinding.getCertificateId());
        if (ocspCertificate == null) {
          // There may be key binding with missing certificates normally
          // (waiting for certificate response?), so don't spam the log
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Could not find certificate for OCSP Key Binding '"
                    + ocspKeyBinding.getName()
                    + "'. Certificate fingerprint: "
                    + ocspKeyBinding.getCertificateId());
          }
        } else {
          X509Certificate issuingCertificate =
              certificateStoreSession.findLatestX509CertificateBySubject(
                  CertTools.getIssuerDN(ocspCertificate));
          if (issuingCertificate == null) {
            // There may be key binding with missing certificates normally
            // (waiting for certificate response?), so don't spam the log
            if (LOG.isDebugEnabled()) {
              LOG.info(
                  "Could not find issuer certificate for OCSP Key Binding '"
                      + ocspKeyBinding.getName()
                      + "'. Issuer DN: "
                      + ocspKeyBinding.getCertificateId());
            }
          } else {
            try {
              if (certId.matchesIssuer(
                  new JcaX509CertificateHolder(issuingCertificate),
                  new BcDigestCalculatorProvider())) {
                // We found it! Unless it's not active, or something else was
                // wrong with it.
                ocspSigningCacheEntry =
                    makeOcspSigningCacheEntry(ocspCertificate, ocspKeyBinding);
                // If it was all right, add it to the cache for future use.
                if (ocspSigningCacheEntry != null) {
                  OcspSigningCache.INSTANCE.addSingleEntry(
                      ocspSigningCacheEntry);
                  break;
                }
              }
            } catch (OCSPException e) {
              throw new IllegalStateException(
                  "Could not create BcDigestCalculatorProvider", e);
            }
          }
        }
      }
    }
    return ocspSigningCacheEntry;
  }

  private BasicOCSPResp signOcspResponse(
      final OCSPReq req,
      final List<OCSPResponseItem> responseList,
      final Extensions exts,
      final OcspSigningCacheEntry ocspSigningCacheEntry,
      final Date producedAt)
      throws CryptoTokenOfflineException {
    assertAcceptableResponseExtension(req);
    if (!ocspSigningCacheEntry.isSigningCertificateForOcspSigning()) {
      LOG.warn(
          "Signing with non OCSP certificate (no 'OCSP Signing' Extended Key"
              + " Usage) bound by OcspKeyBinding '"
              + ocspSigningCacheEntry.getOcspKeyBinding().getName()
              + "'.");
    }
    final X509Certificate signerCert =
        ocspSigningCacheEntry.getSigningCertificate();
    final String sigAlg = getSigAlg(req, ocspSigningCacheEntry, signerCert);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Signing algorithm: " + sigAlg);
    }
    try {
      // Now we can use the returned OCSPServiceResponse to get private key and
      // certificate chain to sign the ocsp response
      final BasicOCSPResp ocspresp =
          generateBasicOcspResp(
              exts,
              responseList,
              sigAlg,
              signerCert,
              ocspSigningCacheEntry,
              producedAt);
      if (CertTools.isCertificateValid(
          signerCert,
          false)) { // Don't warn about signer validity for each OCSP
                    // response...
        return ocspresp;
      } else {
        throw new OcspFailureException("Response was not validly signed.");
      }
    } catch (OCSPException ocspe) {
      throw new OcspFailureException(ocspe);
    } catch (NoSuchProviderException nspe) {
      throw new OcspFailureException(nspe);
    } catch (IllegalArgumentException e) {
      LOG.error("IllegalArgumentException: ", e);
      throw new OcspFailureException(e);
    }
  }

  private BasicOCSPResp generateBasicOcspResp(
      final Extensions exts,
      final List<OCSPResponseItem> responses,
      final String sigAlg,
      final X509Certificate signerCert,
      final OcspSigningCacheEntry ocspSigningCacheEntry,
      final Date producedAt)
      throws OCSPException, NoSuchProviderException,
          CryptoTokenOfflineException {
    final PrivateKey signerKey = ocspSigningCacheEntry.getPrivateKey();
    final String provider = ocspSigningCacheEntry.getSignatureProviderName();
    BasicOCSPResp returnval = null;
    BasicOCSPRespBuilder basicRes =
        new BasicOCSPRespBuilder(ocspSigningCacheEntry.getRespId());
    handleNullResponse(responses, signerCert, basicRes);
    if (exts != null) {
      @SuppressWarnings("rawtypes")
      Enumeration oids = exts.oids();
      if (oids.hasMoreElements()) {
        basicRes.setResponseExtensions(exts);
      }
    }
    final X509Certificate[] chain =
        ocspSigningCacheEntry.getResponseCertChain();
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "The response certificate chain contains "
              + chain.length
              + " certificates");
    }
    /*
     * The below code breaks the EJB standard by creating its own thread pool
     * and creating a single thread (of the HsmResponseThread
     * type). The reason for this is that the HSM may deadlock when requesting
     *  an OCSP response, which we need to guard against. Since
     * there is no way of performing this action within the EJB3.0 standard,
     * we are consciously creating threads here.
     *
     * Note that this does in no way break the spirit of the EJB standard,
     *  which is to not interrupt EJB's transaction handling by
     * competing with its own thread pool, since these operations have no
     * database impact.
     */
    final Future<BasicOCSPResp> task =
        service.submit(
            new HsmResponseThread(
                basicRes, sigAlg, signerKey, chain, provider, producedAt));
    try {
      returnval =
          task.get(HsmResponseThread.HSM_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      task.cancel(true);
      throw new CesecoreError(
          "OCSP response retrieval was interrupted while running. This should"
              + " not happen",
          e);
    } catch (ExecutionException e) {
      task.cancel(true);
      throw new OcspFailureException(
          "Failure encountered while retrieving OCSP response.", e);
    } catch (TimeoutException e) {
      task.cancel(true);
      throw new CryptoTokenOfflineException(
          "HSM timed out while trying to get OCSP response", e);
    }
    logSign(signerCert, ocspSigningCacheEntry, returnval);
    if (!ocspSigningCacheEntry.checkResponseSignatureVerified()) {
      // We only check the response signature the first time for each
      // OcspSigningCacheEntry to detect a misbehaving HSM.
      // The client is still responsible for validating the signature, see RFC
      // 6960 Section 3.2.2
      boolean verify;
      try {
        verify =
            returnval.isSignatureValid(
                CertTools.genContentVerifierProvider(
                    signerCert.getPublicKey()));
      } catch (OperatorCreationException e) {
        // Very fatal error
        throw new EJBException("Can not create Jca content signer: ", e);
      }
      logVerificationResult(signerCert, verify);
    }
    return returnval;
  }

/**
 * @param signerCert cert
 * @param ocspSigningCacheEntry cache
 * @param returnval val
 * @throws OcspFailureException fail
 */
private void logSign(final X509Certificate signerCert,
        final OcspSigningCacheEntry ocspSigningCacheEntry,
        final BasicOCSPResp returnval) throws OcspFailureException {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Signing OCSP response with OCSP signer cert: "
              + signerCert.getSubjectDN().getName());
    }
    if (!returnval.getResponderId().equals(ocspSigningCacheEntry.getRespId())) {
      LOG.error(
          "Response responderId does not match signer certificate"
              + " responderId!");
      throw new OcspFailureException(
          "Response responderId does not match signer certificate"
              + " responderId!");
    }
}

/**
 * @param signerCert cert
 * @param verify bool
 * @throws OcspFailureException fail
 */
private void logVerificationResult(final X509Certificate signerCert,
        final boolean verify) throws OcspFailureException {
    if (verify) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("The OCSP response is verifying.");
        }
      } else {
        LOG.error(
            "The response is NOT verifying! Attempted to sign using "
                + CertTools.getSubjectDN(signerCert)
                + " but signature was not valid.");
        throw new OcspFailureException(
            "Attempted to sign using "
                + CertTools.getSubjectDN(signerCert)
                + " but signature was not valid.");
      }
}

/**
 * @param responses responses
 * @param signerCert cert
 * @param basicRes builder
 */
private void handleNullResponse(final List<OCSPResponseItem> responses,
        final X509Certificate signerCert,
        final BasicOCSPRespBuilder basicRes) {
    if (responses != null) {
      for (OCSPResponseItem item : responses) {
        Date nextUpdate = item.getNextUpdate();
        // Adjust nextUpdate so that it can never exceed the OCSP responder
        // signing certificate validity
        if (signerCert != null
            && nextUpdate != null
            && signerCert.getNotAfter().before(nextUpdate)) {
          nextUpdate = signerCert.getNotAfter();
        }
        basicRes.addResponse(
            item.getCertID(),
            item.getCertStatus(),
            item.getThisUpdate(),
            nextUpdate,
            item.buildExtensions());
      }
    }
}

  /**
   * Method that checks with ProbableErrorHandler if an error has happened since
   * a certain time. Uses reflection to call ProbableErrorHandler because it is
   * dependent on JBoss log4j logging, which is not available on other
   * application servers.
   *
   * @param startTime time
   * @return true if an error has occurred since startTime
   */
  private boolean hasErrorHandlerFailedSince(final Date startTime) {
    boolean result = true; // Default true. If something goes wrong we will fail
    result = ProbableErrorHandler.hasFailedSince(startTime);
    if (result) {
      LOG.error("Audit and/or account logging failed since " + startTime);
    }
    return result;
  }

  /**
   * Returns a signing algorithm to use selecting from a list of possible
   * algorithms.
   *
   * @param sigalgs the list of possible algorithms, ;-separated. Example
   *     "SHA1WithRSA;SHA1WithECDSA".
   * @param pk public key of signer, so we can choose between RSA, DSA and ECDSA
   *     algorithms
   * @return A single algorithm to use Example: SHA1WithRSA, SHA1WithDSA or
   *     SHA1WithECDSA
   */
  private static String getSigningAlgFromAlgSelection(
      final String sigalgs, final PublicKey pk) {
    String sigAlg = null;
    String[] algs = StringUtils.split(sigalgs, ';');
    for (int i = 0; i < algs.length; i++) {
      if (AlgorithmTools.isCompatibleSigAlg(pk, algs[i])) {
        sigAlg = algs[i];
        break;
      }
    }
    LOG.debug("Using signature algorithm for response: " + sigAlg);
    return sigAlg;
  }

  private enum CanLogCache {
      /** singleton. */
    INSTANCE;

      /** bool. */
    private boolean canLog;

     CanLogCache() {
      this.canLog = true;
    }

    public boolean canLog() {
      return canLog;
    }

    public void setCanLog(final boolean doCanLog) {
      this.canLog = doCanLog;
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
  @Deprecated // Remove this method once upgrading from 5-6 is dropped
  public void adhocUpgradeFromPre60(final char[] activationPassword) {
    AuthenticationToken authenticationToken =
        new AlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal(
                OcspResponseGeneratorSessionBean.class.getSimpleName()
                    + ".adhocUpgradeFromPre60"));
    // Check if there are any OcspKeyBindings already, if so return
    if (!internalKeyBindingDataSession
        .getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS)
        .isEmpty()) {
      return;
    }
    // If ocsp.activation.doNotStorePasswordsInMemory=true, new Crypto Tokens
    // should not be auto-actived
    final boolean globalDoNotStorePasswordsInMemory =
        OcspConfiguration.getDoNotStorePasswordsInMemory();
    if (globalDoNotStorePasswordsInMemory && activationPassword == null) {
      LOG.info(
          "Postponing conversion of ocsp.properties configuration to"
              + " OcspKeyBindings since password is not yet available.");
      return;
    }
    LOG.info(
        "No OcspKeyBindings found. Processing ocsp.properties to see if we"
            + " need to perform conversion.");
    final List<InternalKeyBindingTrustEntry> trustDefaults =
        getOcspKeyBindingTrustDefaults();
    // Create CryptoTokens and AuthenticationKeyBinding from:
    //  ocsp.rekeying.swKeystorePath = wsKeyStore.jks
    //  ocsp.rekeying.swKeystorePassword = foo123
    //  if "ocsp.rekeying.swKeystorePath" isn't set, search the p11 slot later
    // on for an entry with an SSL certificate and use this
    final String swKeystorePath =
        ConfigurationHolderUtil.getString("ocsp.rekeying.swKeystorePath");
    final String swKeystorePassword =
        ConfigurationHolderUtil.getString("ocsp.rekeying.swKeystorePassword");
    ug60ConvertKeyStore(activationPassword, authenticationToken,
            globalDoNotStorePasswordsInMemory, trustDefaults,
            swKeystorePath, swKeystorePassword);
    if (OcspConfiguration.getP11Password() != null
        || activationPassword != null) {
      LOG.info(" Processing PKCS#11..");
      final String p11SharedLibrary = OcspConfiguration.getP11SharedLibrary();
      final String sunP11ConfigurationFile =
          OcspConfiguration.getSunP11ConfigurationFile();
      try {
        final String p11password =
            OcspConfiguration.getP11Password() == null
                ? new String(activationPassword)
                : OcspConfiguration.getP11Password();
        String cryptoTokenName = null;
        final Properties cryptoTokenProperties = new Properties();
        if (p11SharedLibrary != null && p11SharedLibrary.length() != 0) {
          cryptoTokenName = ug60ProvidedP11(p11SharedLibrary,
                  cryptoTokenProperties);
        } else if (sunP11ConfigurationFile != null
            && sunP11ConfigurationFile.length() != 0) {
          cryptoTokenName = ug60SunP11(sunP11ConfigurationFile,
                  cryptoTokenProperties);
        }
        ug60P11Upgrade(authenticationToken,
                globalDoNotStorePasswordsInMemory, trustDefaults, p11password,
                cryptoTokenName, cryptoTokenProperties);
      } catch (Exception e) {
        LOG.error("", e);
      }
    }
    ug60convertDirs(activationPassword, authenticationToken,
            globalDoNotStorePasswordsInMemory, trustDefaults);
  }

/**
 * @param authenticationToken Token
 * @param globalDoNotStorePasswordsInMemory Passwords
 * @param trustDefaults bool
 * @param p11password pwd
 * @param cryptoTokenName name
 * @param cryptoTokenProperties props
 * @throws Exception fail
 */
@SuppressWarnings("deprecation")
private void ug60P11Upgrade(final AuthenticationToken authenticationToken,
        final boolean globalDoNotStorePasswordsInMemory,
        final List<InternalKeyBindingTrustEntry> trustDefaults,
        final String p11password, final String cryptoTokenName,
        final Properties cryptoTokenProperties) throws Exception {
    if (cryptoTokenName != null
        && cryptoTokenManagementSession.getIdFromName(cryptoTokenName)
            == null) {
      if (!globalDoNotStorePasswordsInMemory) {
        LOG.info(" Auto-activation will be used.");
        BaseCryptoToken.setAutoActivatePin(
            cryptoTokenProperties, p11password, true);
      } else {
        LOG.info(" Auto-activation will not be used.");
      }
      final int p11CryptoTokenId =
          cryptoTokenManagementSession.createCryptoToken(
              authenticationToken,
              cryptoTokenName,
              PKCS11CryptoToken.class.getName(),
              cryptoTokenProperties,
              null,
              p11password.toCharArray());
      // Use reflection to dig out the certificate objects for each alias so
      // we can create an internal key binding for it
      final Method m =
          BaseCryptoToken.class.getDeclaredMethod("getKeyStore");
      m.setAccessible(true);
      final CachingKeyStoreWrapper cachingKeyStoreWrapper =
          (CachingKeyStoreWrapper)
              m.invoke(
                  cryptoTokenManagementSession.getCryptoToken(
                      p11CryptoTokenId));
      createInternalKeyBindings(
          authenticationToken,
          p11CryptoTokenId,
          cachingKeyStoreWrapper.getKeyStore(),
          trustDefaults);
    }
}

/**
 * @param p11SharedLibrary  Lib
 * @param cryptoTokenProperties Props
 * @return Name
 */
@SuppressWarnings("deprecation")
private String ug60ProvidedP11(final String p11SharedLibrary,
        final Properties cryptoTokenProperties) {
    String cryptoTokenName;
    LOG.info(
          " Processing PKCS#11 with shared library " + p11SharedLibrary);
      final String p11slot = OcspConfiguration.getP11SlotIndex();
      cryptoTokenProperties.put(
          PKCS11CryptoToken.SHLIB_LABEL_KEY, p11SharedLibrary);
      cryptoTokenProperties.put(
          PKCS11CryptoToken.SLOT_LABEL_VALUE, p11slot);
      // Guess label type in order index, number or label
      Pkcs11SlotLabelType type;
      if (Pkcs11SlotLabelType.SLOT_NUMBER.validate(p11slot)) {
        type = Pkcs11SlotLabelType.SLOT_NUMBER;
      } else if (Pkcs11SlotLabelType.SLOT_INDEX.validate(p11slot)) {
        type = Pkcs11SlotLabelType.SLOT_INDEX;
      } else {
        type = Pkcs11SlotLabelType.SLOT_LABEL;
      }
      cryptoTokenProperties.put(
          PKCS11CryptoToken.SLOT_LABEL_TYPE, type.getKey());
      cryptoTokenName = "PKCS11 slot " + p11slot;
    return cryptoTokenName;
}

/**
 * @param sunP11ConfigurationFile File
 * @param cryptoTokenProperties Token
 * @return Name
 * @throws IOException fail
 * @throws FileNotFoundException fail
 */
private String ug60SunP11(final String sunP11ConfigurationFile,
        final Properties cryptoTokenProperties)
        throws IOException, FileNotFoundException {
    String cryptoTokenName;
    LOG.info(
          " Processing PKCS#11 with Sun property file "
              + sunP11ConfigurationFile);
      // The following properties are of interest from this file
      // We will bravely ignore attributes.. it wouldn't be to hard for the
      // user to change the CryptoToken's attributes file later on
      // name=SafeNet
      // library=/opt/PTK/lib/libcryptoki.so
      // slot=1
      // slotListIndex=1
      // attributes(...) = {..}
      // ...
      final Properties p11ConfigurationFileProperties = new Properties();
      p11ConfigurationFileProperties.load(
          new FileInputStream(sunP11ConfigurationFile));
      String p11slot = p11ConfigurationFileProperties.getProperty("slot");
      cryptoTokenProperties.put(
          PKCS11CryptoToken.SLOT_LABEL_VALUE, p11slot);
      // Guess label type in order index, number or label
      Pkcs11SlotLabelType type;
      if (Pkcs11SlotLabelType.SLOT_NUMBER.validate(p11slot)) {
        type = Pkcs11SlotLabelType.SLOT_NUMBER;
      } else if (Pkcs11SlotLabelType.SLOT_INDEX.validate(p11slot)) {
        type = Pkcs11SlotLabelType.SLOT_INDEX;
      } else {
        type = Pkcs11SlotLabelType.SLOT_LABEL;
      }
      cryptoTokenProperties.put(
          PKCS11CryptoToken.SLOT_LABEL_TYPE, type.getKey());

      cryptoTokenProperties.put(
          PKCS11CryptoToken.SHLIB_LABEL_KEY,
          p11ConfigurationFileProperties.getProperty("library"));
      // cryptoTokenProperties.put(PKCS11CryptoToken.ATTRIB_LABEL_KEY,
      // null);
      LOG.warn(
          "Any attributes(..) = { ... } will be ignored and system"
              + " defaults will be used. You should reconfigure the"
              + " CryptoToken later if this is not sufficient.");
      cryptoTokenName =
          "PKCS11 slot "
              + p11ConfigurationFileProperties.getProperty(
                  "slot",
                  "i"
                      + p11ConfigurationFileProperties.getProperty(
                          "slotListIndex"));
    return cryptoTokenName;
}

/**
 * @param activationPassword PWD
 * @param authenticationToken Token
 * @param globalDoNotStorePasswordsInMemory bool
 * @param trustDefaults defaults
 */
@SuppressWarnings("deprecation")
private void ug60convertDirs(final char[] activationPassword,
        final AuthenticationToken authenticationToken,
        final boolean globalDoNotStorePasswordsInMemory,
        final List<InternalKeyBindingTrustEntry> trustDefaults) {
    if (OcspConfiguration.getSoftKeyDirectoryName() != null
        && (OcspConfiguration.getStorePassword() != null
            || activationPassword != null)) {
      final String softStorePassword =
          OcspConfiguration.getStorePassword() == null
              ? new String(activationPassword)
              : OcspConfiguration.getStorePassword();
      final String softKeyPassword =
          OcspConfiguration.getKeyPassword() == null
              ? new String(activationPassword)
              : OcspConfiguration.getKeyPassword();
      final String dirName = OcspConfiguration.getSoftKeyDirectoryName();
      if (dirName != null) {
        final File directory = new File(dirName);
        if (directory.isDirectory()) {
          LOG.info(" Processing Soft KeyStores..");
          for (final File file : directory.listFiles()) {
            processSoftKeystore(
                authenticationToken,
                file,
                softStorePassword,
                softKeyPassword,
                globalDoNotStorePasswordsInMemory,
                trustDefaults);
          }
        }
      }
    }
}

/**
 * @param activationPassword pwd
 * @param authenticationToken token
 * @param globalDoNotStorePasswordsInMemory bool
 * @param trustDefaults defaults
 * @param swKeystorePath path
 * @param swKeystorePassword pwd
 */
private void ug60ConvertKeyStore(final char[] activationPassword,
        final AuthenticationToken authenticationToken,
        final boolean globalDoNotStorePasswordsInMemory,
        final List<InternalKeyBindingTrustEntry> trustDefaults,
        final String swKeystorePath, final String swKeystorePassword) {
    if (swKeystorePath != null
        && (swKeystorePassword != null || activationPassword != null)) {
      final String password =
          swKeystorePassword == null
              ? new String(activationPassword)
              : swKeystorePassword;
      processSoftKeystore(
          authenticationToken,
          new File(swKeystorePath),
          password,
          password,
          globalDoNotStorePasswordsInMemory,
          trustDefaults);
    }
}

  @Deprecated // Remove this method as soon as upgrading from 5.0->6.x is
              // dropped
  private void processSoftKeystore(
      final AuthenticationToken authenticationToken,
      final File file,
      final String softStorePassword,
      final String softKeyPassword,
      final boolean doNotStorePasswordsInMemory,
      final List<InternalKeyBindingTrustEntry> trustDefaults) {
    KeyStore keyStore;
    final char[] passwordChars = softStorePassword.toCharArray();
    // Load keystore (JKS or PKCS#12)
    try {
      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(new FileInputStream(file), passwordChars);
    } catch (Exception e) {
      try {
        keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(new FileInputStream(file), passwordChars);
      } catch (Exception e2) {
        try {
          LOG.info(
              "Unable to process "
                  + file.getCanonicalPath()
                  + " as a KeyStore.");
        } catch (IOException e3) {
          LOG.warn(e3.getMessage());
        }
        return;
      }
    }

    // Strip issuer certs, etc. and convert to PKCS#12
    try {
      keyStore = makeKeysOnlyP12(keyStore, passwordChars);
    } catch (Exception e) {
      throw new CesecoreRuntimeException(
          "failed to convert keystore to P12 during keybindings upgrade", e);
    }

    final String name = file.getName();
    if (cryptoTokenManagementSession.getIdFromName(name) != null) {
      return; // already upgraded
    }
    LOG.info(
        " Processing Soft KeyStore '"
            + name
            + "' of type "
            + keyStore.getType());
    try {
      final ByteArrayOutputStream baos = new ByteArrayOutputStream();
      // Save the store using the same password as the keys are protected with
      // (not the store password)
      // so we don't have to replace the protection for each key
      keyStore.store(baos, softKeyPassword.toCharArray());
      final Properties cryptoTokenProperties = new Properties();
      if (!doNotStorePasswordsInMemory) {
        LOG.info(" Auto-activation will be used.");
        BaseCryptoToken.setAutoActivatePin(
            cryptoTokenProperties, softKeyPassword, true);
      } else {
        LOG.info(" Auto-activation will not be used.");
      }
      final int softCryptoTokenId =
          cryptoTokenManagementSession.createCryptoToken(
              authenticationToken,
              name,
              SoftCryptoToken.class.getName(),
              cryptoTokenProperties,
              baos.toByteArray(),
              softKeyPassword.toCharArray());
      createInternalKeyBindings(
          authenticationToken, softCryptoTokenId, keyStore, trustDefaults);
    } catch (Exception e) {
      LOG.warn(e.getMessage());
    }
  }

  /**
   * Creates a PKCS#12 KeyStore with keys only from an JKS file (no issuer certs
   * or trusted certs).
   *
   * @param keyStore key store
   * @param password password
   * @return new key store
   * @throws KeyStoreException on key store error
   * @throws NoSuchAlgorithmException if algo not found
   * @throws UnrecoverableEntryException if key store is corrupt
   * @throws NoSuchProviderException if algo not found
   * @throws CertificateException if cert is corrupt
   * @throws IOException On IO fail
   */
  @Deprecated // Remove this method as soon as upgrading from 5->6 is dropped
  private KeyStore makeKeysOnlyP12(
      final KeyStore keyStore, final char[] password)
      throws KeyStoreException, NoSuchAlgorithmException,
          UnrecoverableEntryException, NoSuchProviderException,
          CertificateException, IOException {
    final KeyStore p12 = KeyStore.getInstance("PKCS12", "BC");
    final KeyStore.ProtectionParameter protParam =
        password != null ? new KeyStore.PasswordProtection(password) : null;
    p12.load(null, password); // initialize

    final Enumeration<String> en = keyStore.aliases();
    while (en.hasMoreElements()) {
      final String alias = en.nextElement();
      if (!keyStore.isKeyEntry(alias)) {
          continue;
      }
      try {
        KeyStore.PrivateKeyEntry entry =
            (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protParam);
        Certificate[] chain = new Certificate[] {entry.getCertificate()};
        p12.setKeyEntry(alias, entry.getPrivateKey(), password, chain);
      } catch (UnsupportedOperationException uoe) {
        KeyStore.PrivateKeyEntry entry =
            (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        Certificate[] chain = new Certificate[] {entry.getCertificate()};
        p12.setKeyEntry(alias, entry.getPrivateKey(), null, chain);
      }
    }
    return p12;
  }

  /**
   * Create InternalKeyBindings for Ocsp signing and SSL client authentication
   * certs during ad-hoc upgrades.
   *
   * @param authenticationToken Auth
   * @param cryptoTokenId Token ID
   * @param keyStore Key store
   * @param trustDefaults Defaults
   * @throws KeyStoreException on key store error
   * @throws CryptoTokenOfflineException if offline
   * @throws InternalKeyBindingNameInUseException if binding name is in use
   * @throws AuthorizationDeniedException if access denied
   * @throws CertificateEncodingException If cert is corrupt
   * @throws CertificateImportException if import fails
   * @throws InvalidAlgorithmException if algo cannot be found
   */
  @Deprecated // Remove this method as soon as upgrading from 5->6 is dropped
  private void createInternalKeyBindings(
      final AuthenticationToken authenticationToken,
      final int cryptoTokenId,
      final KeyStore keyStore,
      final List<InternalKeyBindingTrustEntry> trustDefaults)
      throws KeyStoreException, CryptoTokenOfflineException,
          InternalKeyBindingNameInUseException, AuthorizationDeniedException,
          CertificateEncodingException, CertificateImportException,
          InvalidAlgorithmException {
    final Enumeration<String> aliases = keyStore.aliases();
    boolean noAliases = true;
    while (aliases.hasMoreElements()) {
      final String keyPairAlias = aliases.nextElement();
      noAliases = false;
      LOG.info(
          "Found alias " + keyPairAlias
              + ", trying to figure out if this is something we should convert"
              + " into a new KeyBinding...");
      final Certificate[] chain = keyStore.getCertificateChain(keyPairAlias);
      if (chain == null || chain.length == 0) {
        LOG.info(
            "Alias " + keyPairAlias
                + " does not contain any certificate and will be ignored.");
        continue; // Ignore entry
      }
      // Extract the default signature algorithm
      final String signatureAlgorithm =
          getSigningAlgFromAlgSelection(
              OcspConfiguration.getSignatureAlgorithm(),
              chain[0].getPublicKey());
      if (OcspKeyBinding.isOcspSigningCertificate(
          chain[0],
          (AvailableExtendedKeyUsagesConfiguration)
              globalConfigurationSession.getCachedConfiguration(
                  AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID))) {
        // Create the actual OcspKeyBinding
        LOG.info(
            "Alias " + keyPairAlias
                + " contains an OCSP certificate and will be converted to an"
                + " OcspKeyBinding.");
        int internalKeyBindingId =
            internalKeyBindingMgmtSession.createInternalKeyBinding(
                authenticationToken,
                OcspKeyBinding.IMPLEMENTATION_ALIAS,
                "OcspKeyBinding for " + keyPairAlias,
                InternalKeyBindingStatus.DISABLED,
                null,
                cryptoTokenId,
                keyPairAlias,
                signatureAlgorithm,
                getOcspKeyBindingDefaultProperties(),
                trustDefaults);
        internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(
            authenticationToken, internalKeyBindingId, chain[0].getEncoded());
        internalKeyBindingMgmtSession.setStatus(
            authenticationToken,
            internalKeyBindingId,
            InternalKeyBindingStatus.ACTIVE);
      } else if (AuthenticationKeyBinding.isClientSSLCertificate(
          chain[0],
          (AvailableExtendedKeyUsagesConfiguration)
              globalConfigurationSession.getCachedConfiguration(
                  AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID))) {
        LOG.info(
            "Alias " + keyPairAlias
                + " contains an SSL client certificate and will be converted"
                + " to an AuthenticationKeyBinding.");
        // We are looking for an SSL cert, use this to create an
        // AuthenticationKeyBinding
        int internalKeyBindingId =
            internalKeyBindingMgmtSession.createInternalKeyBinding(
                authenticationToken,
                AuthenticationKeyBinding.IMPLEMENTATION_ALIAS,
                "AuthenticationKeyBinding for " + keyPairAlias,
                InternalKeyBindingStatus.DISABLED,
                null,
                cryptoTokenId,
                keyPairAlias,
                signatureAlgorithm,
                null,
                null);
        internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(
            authenticationToken, internalKeyBindingId, chain[0].getEncoded());
        internalKeyBindingMgmtSession.setStatus(
            authenticationToken,
            internalKeyBindingId,
            InternalKeyBindingStatus.ACTIVE);
      } else {
        LOG.info(
            "Alias " + keyPairAlias
                + " contains certificate of unknown type and will be ignored.");
      }
    }
    if (noAliases) {
      LOG.info("No aliases to process were found in the key store.");
    }
  }

  /** @return a list of trusted signers or CAs */
  @Deprecated // This method is only used for upgrading to version 6
  private List<InternalKeyBindingTrustEntry> getOcspKeyBindingTrustDefaults() {
    // Import certificates used to verify OCSP request signatures and add these
    // to each OcspKeyBinding's trust-list
    //  ocsp.signtrustdir=signtrustdir
    //  ocsp.signtrustvalidtime should be ignored
    final List<InternalKeyBindingTrustEntry> trustedCertificateReferences =
        new ArrayList<InternalKeyBindingTrustEntry>();
    if (OcspConfiguration.getEnforceRequestSigning()
        && OcspConfiguration.getRestrictSignatures()) {
      // Import certificates and configure Issuer+serialnumber in trustlist for
      // each
      final String dirName = OcspConfiguration.getSignTrustDir();
      if (dirName != null) {
        final File directory = new File(dirName);
        if (directory.isDirectory()) {
          for (final File file : directory.listFiles()) {
            try {
              final List<Certificate> chain =
                  CertTools.getCertsFromPEM(new FileInputStream(file));
              if (!chain.isEmpty()) {
                final String issuerDn = CertTools.getIssuerDN(chain.get(0));
                final String subjectDn = CertTools.getSubjectDN(chain.get(0));
                if (OcspConfiguration.getRestrictSignaturesByMethod()
                    == OcspConfiguration.RESTRICTONSIGNER) {
                  final int caId = issuerDn.hashCode();
                  final BigInteger serialNumber =
                      CertTools.getSerialNumber(chain.get(0));
                  if (!caSession.existsCa(caId)) {
                    LOG.warn(
                        "Trusted certificate with serialNumber "
                            + serialNumber.toString(16)
                            + " is issued by an unknown CA with subject '"
                            + issuerDn
                            + "'. You should import this CA certificate as en"
                            + " external CA to make it known to the system.");
                  }
                  trustedCertificateReferences.add(
                      new InternalKeyBindingTrustEntry(caId, serialNumber));
                } else {
                  final int caId = subjectDn.hashCode();
                  if (!caSession.existsCa(caId)) {
                    LOG.warn(
                        "Trusted CA certificate with with subject '"
                            + subjectDn
                            + "' should be imported as en external CA to make"
                            + " it known to the system.");
                  }
                  trustedCertificateReferences.add(
                      new InternalKeyBindingTrustEntry(caId, null));
                }
              }
            } catch (CertificateException e) {
              LOG.warn(e.getMessage());
            } catch (FileNotFoundException e) {
              LOG.warn(e.getMessage());
            }
          }
        }
      }
    }
    return trustedCertificateReferences;
  }

  /**
   * @return OcspKeyBinding properties set to the current file-based
   *     configuration (per cert profile config is ignored here)
   */
  @SuppressWarnings("deprecation")
  private Map<String, Serializable> getOcspKeyBindingDefaultProperties() {
    final long k = 1000L;
    // Use global config as defaults for each new OcspKeyBinding
    final Map<String, Serializable> dataMap =
        new HashMap<String, Serializable>();
    dataMap.put(
        OcspKeyBinding.PROPERTY_INCLUDE_CERT_CHAIN,
        Boolean.valueOf(OcspConfiguration.getIncludeCertChain()));
    if (OcspConfiguration.getResponderIdType()
        == OcspConfiguration.RESPONDERIDTYPE_NAME) {
      dataMap.put(
          OcspKeyBinding.PROPERTY_RESPONDER_ID_TYPE,
          ResponderIdType.NAME.name());
    } else {
      dataMap.put(
          OcspKeyBinding.PROPERTY_RESPONDER_ID_TYPE,
          ResponderIdType.KEYHASH.name());
    }
    dataMap.put(
        OcspKeyBinding.PROPERTY_MAX_AGE,
        (long)
            (OcspConfiguration.getMaxAge(
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE)
                / k));
    dataMap.put(
        OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD,
        Boolean.valueOf(OcspConfiguration.getNonExistingIsGood()));
    dataMap.put(
        OcspKeyBinding.PROPERTY_NON_EXISTING_REVOKED,
        Boolean.valueOf(OcspConfiguration.getNonExistingIsRevoked()));
    dataMap.put(
        OcspKeyBinding.PROPERTY_UNTIL_NEXT_UPDATE,
        (long)
            (OcspConfiguration.getUntilNextUpdate(
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE)
                / k));
    dataMap.put(
        OcspKeyBinding.PROPERTY_REQUIRE_TRUSTED_SIGNATURE,
        Boolean.valueOf(OcspConfiguration.getEnforceRequestSigning()));
    return dataMap;
  }

  @Override
  public String healthCheck() {
    final StringBuilder sb = new StringBuilder();
    // Check that there are no ACTIVE OcspKeyBindings that are not in the cache
    // before checking usability..
    checkForActive(sb);
    if (sb.length() > 0) {
      return sb.toString();
    }
    try {
      final Collection<OcspSigningCacheEntry> ocspSigningCacheEntries =
          OcspSigningCache.INSTANCE.getEntries();
      if (ocspSigningCacheEntries.isEmpty()) {
        // Only report this in the server log. It is not an erroneous state to
        // have no ACTIVE OcspKeyBindings.
        logEmpty();
      } else {
        for (OcspSigningCacheEntry ocspSigningCacheEntry
            : ocspSigningCacheEntries) {
          // Only verify non-CA responders
          final X509Certificate ocspSigningCertificate =
              ocspSigningCacheEntry.getOcspSigningCertificate();
          if (ocspSigningCertificate == null) {
            continue;
          }
          final String subjectDn =
              CertTools.getSubjectDN(
                  ocspSigningCacheEntry.getCaCertificateChain().get(0));
          final String serialNumberForLog =
              CertTools.getSerialNumberAsString(
                  ocspSigningCacheEntry.getOcspSigningCertificate());
          final String errMsg =
              INTRES.getLocalizedMessage(
                  "ocsp.errorocspkeynotusable", subjectDn, serialNumberForLog);
          final PrivateKey privateKey = ocspSigningCacheEntry.getPrivateKey();
          if (privateKey == null) {
            sb.append('\n').append(errMsg);
            LOG.error("No key available. " + errMsg);
            continue;
          }
          if (OcspConfiguration.getHealthCheckCertificateValidity()
              && !CertTools.isCertificateValid(ocspSigningCertificate, true)) {
            sb.append('\n').append(errMsg);
            continue;
          }
          if (OcspConfiguration.getHealthCheckSignTest()) {
            try {
              final String providerName =
                  ocspSigningCacheEntry.getSignatureProviderName();
              KeyUtil.testKey(
                  privateKey,
                  ocspSigningCertificate.getPublicKey(),
                  providerName);
            } catch (InvalidKeyException e) {
              // thrown by testKey
              sb.append('\n').append(errMsg);
              LOG.error(
                  "Key not working. SubjectDN '"
                      + subjectDn
                      + "'. Error comment '"
                      + errMsg
                      + "'. Message '"
                      + e.getMessage());
              continue;
            }
          }
          logTest(ocspSigningCacheEntry);
        }
      }
    } catch (Exception e) {
      final String errMsg =
          INTRES.getLocalizedMessage("ocsp.errorloadsigningcerts");
      LOG.error(errMsg, e);
      sb.append(errMsg).append(": ").append(errMsg);
    }
    return sb.toString();
  }

/**
 * @param sb SB
 * @throws IllegalStateException fail
 */
private void checkForActive(final StringBuilder sb)
        throws IllegalStateException {
    for (InternalKeyBindingInfo internalKeyBindingInfo
       : internalKeyBindingMgmtSession.getAllInternalKeyBindingInfos(
            OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
      if (internalKeyBindingInfo
          .getStatus()
          .equals(InternalKeyBindingStatus.ACTIVE)) {
        final Certificate ocspCertificate =
            certificateStoreSession.findCertificateByFingerprint(
                internalKeyBindingInfo.getCertificateId());
        final X509Certificate issuingCertificate =
            certificateStoreSession.findLatestX509CertificateBySubject(
                CertTools.getIssuerDN(ocspCertificate));
        checkCacheEntry(sb, internalKeyBindingInfo, ocspCertificate,
                issuingCertificate);
      }
    }
}

/**
 * @param ocspSigningCacheEntry Entry
 */
private void logTest(final OcspSigningCacheEntry ocspSigningCacheEntry) {
    if (LOG.isDebugEnabled()) {
        final String name =
            ocspSigningCacheEntry.getOcspKeyBinding().getName();
        LOG.debug("Test of \"" + name + "\" OK!");
      }
}

/**
 *
 */
private void logEmpty() {
    if (LOG.isDebugEnabled()) {
      LOG.debug(INTRES.getLocalizedMessage("ocsp.errornosignkeys"));
    }
}

/**
 * @param sb SB
 * @param internalKeyBindingInfo Info
 * @param ocspCertificate Cert
 * @param issuingCertificate Cert
 * @throws IllegalStateException Fail
 */
private void checkCacheEntry(final StringBuilder sb,
        final InternalKeyBindingInfo internalKeyBindingInfo,
        final Certificate ocspCertificate,
        final X509Certificate issuingCertificate)
                throws IllegalStateException {
    OcspSigningCacheEntry ocspSigningCacheEntry = null;
    if (issuingCertificate != null) {
      final List<CertificateID> certIds =
          OcspSigningCache.getCertificateIDFromCertificate(
              issuingCertificate);
      // We only need to use the first certId type to find an entry in the
      // cache, certIds.get(0), since all of them should be in the cache
      ocspSigningCacheEntry =
          OcspSigningCache.INSTANCE.getEntry(certIds.get(0));
      if (ocspSigningCacheEntry == null) {
        // Could be a cache issue?
        try {
          ocspSigningCacheEntry =
              findAndAddMissingCacheEntry(certIds.get(0));
        } catch (CertificateEncodingException e) {
          throw new IllegalStateException(
              "Could not process certificate", e);
        }
      }
    } else {
      LOG.info(
          "Can not find issuer certificate from subject DN '"
              + CertTools.getIssuerDN(ocspCertificate)
              + "'.");
    }

    if (ocspSigningCacheEntry == null) {
      final String errMsg =
          INTRES.getLocalizedMessage(
              "ocsp.signingkeynotincache",
              internalKeyBindingInfo.getName());
      sb.append('\n').append(errMsg);
      LOG.error(errMsg);
    }
}
}

final class CardKeyHolder {
    /** Resource. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();
  /** Instance. */
  private static CardKeyHolder instance = null;
  /** keys. */
  private CardKeys cardKeys = null;

  private CardKeyHolder() {
    Logger log = Logger.getLogger(CardKeyHolder.class);
    String hardTokenClassName = OcspConfiguration.getHardTokenClassName();
    try {
      this.cardKeys =
          (CardKeys)
              OcspResponseGeneratorSessionBean.class
                  .getClassLoader()
                  .loadClass(hardTokenClassName)
                  .getConstructor()
                  .newInstance();
      this.cardKeys.autenticate(OcspConfiguration.getCardPassword());
    } catch (ClassNotFoundException e) {
      log.debug(
          INTRES.getLocalizedMessage("ocsp.classnotfound", hardTokenClassName));
    } catch (Exception e) {
      log.info("Could not create CardKeyHolder", e);
    }
  }

  public static synchronized CardKeyHolder getInstance() {
    if (instance == null) {
      instance = new CardKeyHolder();
    }
    return instance;
  }

  public CardKeys getCardKeys() {
    return cardKeys;
  }
}
