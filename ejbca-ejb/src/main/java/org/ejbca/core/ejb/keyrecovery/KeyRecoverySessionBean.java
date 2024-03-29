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

package org.ejbca.core.ejb.keyrecovery;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.util.KeyPairWrapper;
import org.cesecore.keys.util.KeyUtil;
import org.cesecore.util.Base64Util;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBUtil;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceResponse;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;

/**
 * Stores key recovery data.
 *
 * @version $Id: KeyRecoverySessionBean.java 26327 2017-08-16 14:36:31Z henriks
 *     $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyRecoverySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyRecoverySessionBean
    implements KeyRecoverySessionLocal, KeyRecoverySessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(KeyRecoverySessionBean.class);

  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** EJB. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** EJB. */
  @EJB private ApprovalSessionLocal approvalSession;
  /** EJB. */
  @EJB private ApprovalProfileSessionLocal approvalProfileSession;
  /** EJB. */
  @EJB private CertificateProfileSessionLocal certProfileSession;
  /** EJB. */
  @EJB private CAAdminSessionLocal caAdminSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;
  /** EJB. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** EJB. */
  @EJB private CryptoTokenSessionLocal cryptoTokenSession;
  /** EJB. */
  @EJB private SecurityEventsLoggerSessionLocal auditSession;

  /**
   * @param token The {@link AuthenticationToken} to check.
   * @return true if authorized to or /ra_functionality/keyrecovery
   */
  private boolean authorizedToAdministrateKeys(
      final AuthenticationToken token) {
    return authorizationSession.isAuthorizedNoLogging(
        token, AccessRulesConstants.REGULAR_KEYRECOVERY);
  }

  @Override
  public boolean authorizedToKeyRecover(
      final AuthenticationToken admin, final int profileid) {
    return authorizationSession.isAuthorizedNoLogging(
            admin,
            AccessRulesConstants.ENDENTITYPROFILEPREFIX
                + profileid
                + AccessRulesConstants.KEYRECOVERY_RIGHTS)
        && authorizationSession.isAuthorizedNoLogging(
            admin, AccessRulesConstants.REGULAR_KEYRECOVERY);
  }

  @Override
  public void checkIfApprovalRequired(
      final AuthenticationToken admin,
      final CertificateWrapper certificateWrapper,
      final String username,
      final int endEntityProfileId,
      final boolean checkNewest)
      throws ApprovalException, WaitingForApprovalException,
          CADoesntExistsException {
    final Certificate certificate = EJBUtil.unwrap(certificateWrapper);
    final int caid = CertTools.getIssuerDN(certificate).hashCode();
    final CAInfo cainfo = caSession.getCAInfoInternal(caid);
    final CertificateInfo certinfo =
        certificateStoreSession.getCertificateInfo(
            CertTools.getFingerprintAsString(certificate));
    final CertificateProfile certProfile =
        certProfileSession.getCertificateProfile(
            certinfo.getCertificateProfileId());

    // Check if approvals is required.
    final ApprovalProfile approvalProfile =
        approvalProfileSession.getApprovalProfileForAction(
            ApprovalRequestType.KEYRECOVER, cainfo, certProfile);
    if (approvalProfile != null) {
      KeyRecoveryApprovalRequest ar =
          new KeyRecoveryApprovalRequest(
              certificate,
              username,
              checkNewest,
              admin,
              null,
              caid,
              endEntityProfileId,
              approvalProfile);
      if (ApprovalExecutorUtil.requireApproval(
          ar, NONAPPROVABLECLASSNAMES_KEYRECOVERY)) {
        int requestId = approvalSession.addApprovalRequest(admin, ar);
        String msg = INTRES.getLocalizedMessage("keyrecovery.addedforapproval");
        throw new WaitingForApprovalException(msg, requestId);
      }
    }
  }

  private String getPublicKeyIdFromKey(
      final CryptoToken cryptoToken, final String keyAlias)
      throws CryptoTokenOfflineException {
    return new String(
        Base64Util.encode(
            KeyUtil.createSubjectKeyId(cryptoToken.getPublicKey(keyAlias))
                .getKeyIdentifier(),
            false),
        StandardCharsets.US_ASCII);
  }

  @Override
  public boolean addKeyRecoveryData(
      final AuthenticationToken admin,
      final CertificateWrapper certificateWrapper,
      final String username,
      final KeyPairWrapper keyPairWrapper)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addKeyRecoveryData(user: " + username + ")");
    }
    if (authorizedToAdministrateKeys(admin)) {
      final Certificate certificate = EJBUtil.unwrap(certificateWrapper);
      final KeyPair keypair = EJBUtil.unwrap(keyPairWrapper);
      final int caid = CertTools.getIssuerDN(certificate).hashCode();
      final String certSerialNumber =
          CertTools.getSerialNumberAsString(certificate);
      boolean returnval = false;
      try {
        KeyRecoveryCAServiceResponse response =
            (KeyRecoveryCAServiceResponse)
                caAdminSession.extendedService(
                    admin,
                    caid,
                    new KeyRecoveryCAServiceRequest(
                        KeyRecoveryCAServiceRequest.COMMAND_ENCRYPTKEYS,
                        keypair));
        entityManager.persist(
            new org.ejbca.core.ejb.keyrecovery.KeyRecoveryData(
                CertTools.getSerialNumber(certificate),
                CertTools.getIssuerDN(certificate),
                username,
                response.getKeyData(),
                response.getCryptoTokenId(),
                response.getKeyAlias(),
                response.getPublicKeyId()));
        // same method to make hex serno as in KeyRecoveryDataBean
        String msg =
            INTRES.getLocalizedMessage(
                "keyrecovery.addeddata",
                CertTools.getSerialNumber(certificate).toString(16),
                CertTools.getIssuerDN(certificate),
                response.getKeyAlias(),
                response.getPublicKeyId(),
                response.getCryptoTokenId());
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.KEYRECOVERY_ADDDATA,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.KEYRECOVERY,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            String.valueOf(caid),
            certSerialNumber,
            username,
            details);
        returnval = true;
      } catch (Exception e) {
        final String msg =
            INTRES.getLocalizedMessage(
                "keyrecovery.erroradddata",
                CertTools.getSerialNumber(certificate).toString(16),
                CertTools.getIssuerDN(certificate));
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.KEYRECOVERY_ADDDATA,
            EventStatus.FAILURE,
            EjbcaModuleTypes.KEYRECOVERY,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            String.valueOf(caid),
            certSerialNumber,
            username,
            details);
        LOG.error(msg, e);
      }
      LOG.trace("<addKeyRecoveryData()");
      return returnval;
    } else {
      throw new AuthorizationDeniedException(
          admin + " not authorized to administer keys");
    }
  }

  @Override
  public boolean addKeyRecoveryDataInternal(
      final AuthenticationToken admin,
      final CertificateWrapper certificateWrapper,
      final String username,
      final KeyPairWrapper keyPairWrapper,
      final int cryptoTokenId,
      final String keyAlias) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addKeyRecoveryDataInternal(user: " + username + ")");
    }
    final Certificate certificate = EJBUtil.unwrap(certificateWrapper);
    final KeyPair keypair = EJBUtil.unwrap(keyPairWrapper);
    final String certSerialNumber =
        CertTools.getSerialNumberAsString(certificate);
    boolean returnval = false;
    try {
      final CryptoToken cryptoToken =
          cryptoTokenSession.getCryptoToken(cryptoTokenId);
      final String publicKeyId = getPublicKeyIdFromKey(cryptoToken, keyAlias);

      final byte[] encryptedKeyData =
          X509CA.encryptKeys(cryptoToken, keyAlias, keypair);
      entityManager.persist(
          new org.ejbca.core.ejb.keyrecovery.KeyRecoveryData(
              CertTools.getSerialNumber(certificate),
              CertTools.getIssuerDN(certificate),
              username,
              encryptedKeyData,
              cryptoTokenId,
              keyAlias,
              publicKeyId));
      // same method to make hex serno as in KeyRecoveryDataBean
      String msg =
          INTRES.getLocalizedMessage(
              "keyrecovery.addeddata",
              CertTools.getSerialNumber(certificate).toString(16),
              CertTools.getIssuerDN(certificate),
              keyAlias,
              publicKeyId,
              cryptoTokenId);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_ADDDATA,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          certSerialNumber,
          username,
          details);
      returnval = true;
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage(
              "keyrecovery.erroradddata",
              CertTools.getSerialNumber(certificate).toString(16),
              CertTools.getIssuerDN(certificate));
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_ADDDATA,
          EventStatus.FAILURE,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          certSerialNumber,
          username,
          details);
      LOG.error(msg, e);
    }
    LOG.trace("<addKeyRecoveryDataInternal()");
    return returnval;
  }

  @Override
  public void removeKeyRecoveryData(
      final AuthenticationToken admin,
      final CertificateWrapper certificateWrapper)
      throws AuthorizationDeniedException {
    if (!authorizedToAdministrateKeys(admin)) {
      throw new AuthorizationDeniedException(
          admin + " not authorized to administer keys");
    }
    final Certificate certificate = EJBUtil.unwrap(certificateWrapper);
    final String hexSerial =
        CertTools.getSerialNumber(certificate).toString(16);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">removeKeyRecoveryData(certificate: "
              + CertTools.getSerialNumber(certificate).toString(16)
              + ")");
    }
    final String dn = CertTools.getIssuerDN(certificate);
    final int caid = dn.hashCode();
    try {
      String username = null;
      org.ejbca.core.ejb.keyrecovery.KeyRecoveryData krd =
          org.ejbca.core.ejb.keyrecovery.KeyRecoveryData.findByPK(
              entityManager, new KeyRecoveryDataPK(hexSerial, dn));
      if (krd == null) {
        throw new FinderException();
      }
      username = krd.getUsername();
      entityManager.remove(krd);
      String msg =
          INTRES.getLocalizedMessage("keyrecovery.removeddata", hexSerial, dn);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_REMOVEDATA,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          String.valueOf(caid),
          hexSerial,
          username,
          details);
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage(
              "keyrecovery.errorremovedata", hexSerial, dn);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_REMOVEDATA,
          EventStatus.FAILURE,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          String.valueOf(caid),
          hexSerial,
          null,
          details);
      LOG.error(msg, e);
    }
    LOG.trace("<removeKeyRecoveryData()");
  }

  @Override
  public void removeAllKeyRecoveryData(
      final AuthenticationToken admin, final String username) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeAllKeyRecoveryData(user: " + username + ")");
    }
    try {
      Collection<org.ejbca.core.ejb.keyrecovery.KeyRecoveryData> result =
          org.ejbca.core.ejb.keyrecovery.KeyRecoveryData.findByUsername(
              entityManager, username);
      Iterator<org.ejbca.core.ejb.keyrecovery.KeyRecoveryData> iter =
          result.iterator();
      while (iter.hasNext()) {
        entityManager.remove(iter.next());
      }
      String msg =
          INTRES.getLocalizedMessage("keyrecovery.removeduser", username);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_REMOVEDATA,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          username,
          details);
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage("keyrecovery.errorremoveuser", username);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_REMOVEDATA,
          EventStatus.FAILURE,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          username,
          details);
    }
    LOG.trace("<removeAllKeyRecoveryData()");
  }

  @Override
  public KeyRecoveryInformation recoverKeys(
      final AuthenticationToken admin,
      final String username,
      final int endEntityProfileId)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">keyRecovery(user: " + username + ")");
    }
    KeyRecoveryInformation returnval = null;
    X509Certificate certificate = null;
    if (authorizedToKeyRecover(admin, endEntityProfileId)) {
      Collection<KeyRecoveryData> result =
          KeyRecoveryData.findByUserMark(entityManager, username);
      try {
        String caidString = null;
        String certSerialNumber = null;
        String logMsg = null;
        for (final KeyRecoveryData krd : result) {
          if (returnval == null) {
            final int caid = krd.getIssuerDN().hashCode();
            caidString = String.valueOf(caid);
            final KeyRecoveryCAServiceResponse response =
                (KeyRecoveryCAServiceResponse)
                    caAdminSession.extendedService(
                        admin,
                        caid,
                        new KeyRecoveryCAServiceRequest(
                            KeyRecoveryCAServiceRequest.COMMAND_DECRYPTKEYS,
                            krd.getKeyDataAsByteArray(),
                            krd.getCryptoTokenId(),
                            krd.getKeyAlias()));
            final KeyPair keys = response.getKeyPair();
            certificate =
                (X509Certificate)
                    certificateStoreSession.findCertificateByIssuerAndSerno(
                        krd.getIssuerDN(), krd.getCertificateSN());
            returnval =
                new KeyRecoveryInformation(
                    krd.getCertificateSN(),
                    krd.getIssuerDN(),
                    krd.getUsername(),
                    krd.getMarkedAsRecoverable(),
                    keys,
                    certificate);
            certSerialNumber = CertTools.getSerialNumberAsString(certificate);
            logMsg =
                INTRES.getLocalizedMessage(
                    "keyrecovery.sentdata",
                    username,
                    response.getKeyAlias(),
                    response.getPublicKeyId(),
                    response.getCryptoTokenId());
          }
        }
        if (logMsg == null) {
          logMsg = INTRES.getLocalizedMessage("keyrecovery.nodata", username);
        }
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", logMsg);
        auditSession.log(
            EjbcaEventTypes.KEYRECOVERY_SENT,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.KEYRECOVERY,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            caidString,
            certSerialNumber,
            username,
            details);
      } catch (Exception e) {
        String msg =
            INTRES.getLocalizedMessage("keyrecovery.errorsenddata", username);
        LOG.error(msg, e);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.KEYRECOVERY_SENT,
            EventStatus.FAILURE,
            EjbcaModuleTypes.KEYRECOVERY,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            username,
            details);
      }
    } else {
      throw new AuthorizationDeniedException(
          admin
              + " not authorized to key recovery for end entity profile id "
              + endEntityProfileId);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<keyRecovery()");
    }
    return returnval;
  }

  @Override
  public KeyRecoveryInformation recoverKeysInternal(
      final AuthenticationToken admin,
      final String username,
      final int cryptoTokenId,
      final String keyAlias) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">recoverKeysInternal(user: " + username + ")");
    }
    KeyRecoveryInformation returnval = null;
    Collection<KeyRecoveryData> result =
        KeyRecoveryData.findByUserMark(entityManager, username);
    try {
      String caidString = null;
      String certSerialNumber = null;
      String logMsg = null;
      for (final KeyRecoveryData krd : result) {
        if (returnval == null) {
          final CryptoToken cryptoToken =
              cryptoTokenSession.getCryptoToken(cryptoTokenId);
          final String publicKeyId =
              getPublicKeyIdFromKey(cryptoToken, keyAlias);
          final KeyPair keys =
              X509CA.decryptKeys(
                  cryptoToken, keyAlias, krd.getKeyDataAsByteArray());
          returnval =
              new KeyRecoveryInformation(
                  krd.getCertificateSN(),
                  krd.getIssuerDN(),
                  krd.getUsername(),
                  krd.getMarkedAsRecoverable(),
                  keys,
                  null);
          certSerialNumber = krd.getCertificateSN().toString(16);
          logMsg =
              INTRES.getLocalizedMessage(
                  "keyrecovery.sentdata",
                  username,
                  keyAlias,
                  publicKeyId,
                  cryptoTokenId);
        }
      }
      if (logMsg == null) {
        logMsg = INTRES.getLocalizedMessage("keyrecovery.nodata", username);
      }
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", logMsg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_SENT,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          caidString,
          certSerialNumber,
          username,
          details);
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage("keyrecovery.errorsenddata", username);
      LOG.error(msg, e);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_SENT,
          EventStatus.FAILURE,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          username,
          details);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<recoverKeysInternal()");
    }
    return returnval;
  }

  /**
   * Class names. */
  private static final ApprovalOveradableClassName[]
      NONAPPROVABLECLASSNAMES_KEYRECOVERY = {
    new ApprovalOveradableClassName(
        org.ejbca.core.model.approval.approvalrequests
            .KeyRecoveryApprovalRequest.class
            .getName(),
        null),
  };

  @Override
  public boolean markNewestAsRecoverable(
      final AuthenticationToken admin,
      final String username,
      final int endEntityProfileId)
      throws AuthorizationDeniedException, ApprovalException,
          WaitingForApprovalException, CADoesntExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">markNewestAsRecoverable(user: " + username + ")");
    }
    boolean returnval = false;
    long newesttime = 0;
    KeyRecoveryData newest = null;
    X509Certificate certificate = null;
    X509Certificate newestcertificate = null;
    if (!isUserMarked(username)) {
      String caidString = null;
      String certSerialNumber = null;
      final Collection<KeyRecoveryData> result =
          KeyRecoveryData.findByUsername(entityManager, username);
      for (final KeyRecoveryData krd : result) {
        caidString = String.valueOf(krd.getIssuerDN().hashCode());
        certificate =
            (X509Certificate)
                certificateStoreSession.findCertificateByIssuerAndSerno(
                    krd.getIssuerDN(), krd.getCertificateSN());
        if (certificate != null) {
          if (certificate.getNotBefore().getTime() > newesttime) {
            newesttime = certificate.getNotBefore().getTime();
            newest = krd;
            newestcertificate = certificate;
            certSerialNumber =
                CertTools.getSerialNumberAsString(newestcertificate);
          }
        }
      }
      if (newest != null) {
        // Check that the administrator is authorized to keyrecover
        if (authorizedToKeyRecover(admin, endEntityProfileId)) {
          // Check if approvals is required.
          checkIfApprovalRequired(
              admin,
              EJBUtil.wrap(newestcertificate),
              username,
              endEntityProfileId,
              true);
          newest.setMarkedAsRecoverable(true);
          returnval = true;
        } else {
          throw new AuthorizationDeniedException(
              admin
                  + " not authorized to key recovery for end entity profile id "
                  + endEntityProfileId);
        }
      }
      if (returnval) {
        String msg =
            INTRES.getLocalizedMessage("keyrecovery.markeduser", username);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.KEYRECOVERY_MARKED,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.KEYRECOVERY,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            caidString,
            certSerialNumber,
            username,
            details);
      } else {
        String msg =
            INTRES.getLocalizedMessage("keyrecovery.errormarkuser", username);
        LOG.info(msg);
      }
    }
    LOG.trace("<markNewestAsRecoverable()");
    return returnval;
  }

  @Override
  public boolean markAsRecoverable(
      final AuthenticationToken admin,
      final Certificate certificate,
      final int endEntityProfileId)
      throws AuthorizationDeniedException, WaitingForApprovalException,
          ApprovalException, CADoesntExistsException {
    final String hexSerial =
        CertTools.getSerialNumber(certificate)
            .toString(16); // same method to make hex as in KeyRecoveryDataBean
    final String dn = CertTools.getIssuerDN(certificate);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">markAsRecoverable(issuer: "
              + dn
              + "; certificatesn: "
              + hexSerial
              + ")");
    }
    boolean returnval = false;
    org.ejbca.core.ejb.keyrecovery.KeyRecoveryData krd =
        org.ejbca.core.ejb.keyrecovery.KeyRecoveryData.findByPK(
            entityManager, new KeyRecoveryDataPK(hexSerial, dn));
    if (krd != null) {
      String username = krd.getUsername();
      // Check that the administrator is authorized to keyrecover
      if (authorizedToKeyRecover(admin, endEntityProfileId)) {
        // Check if approvals is required.
        checkIfApprovalRequired(
            admin,
            EJBUtil.wrap(certificate),
            username,
            endEntityProfileId,
            false);
        krd.setMarkedAsRecoverable(true);
        int caid = krd.getIssuerDN().hashCode();
        String msg =
            INTRES.getLocalizedMessage("keyrecovery.markedcert", hexSerial, dn);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.KEYRECOVERY_MARKED,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.KEYRECOVERY,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            String.valueOf(caid),
            hexSerial,
            username,
            details);
        returnval = true;
      } else {
        throw new AuthorizationDeniedException(
            admin
                + " not authorized to key recovery for end entity profile id "
                + endEntityProfileId);
      }
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "keyrecovery.errormarkcert", hexSerial, dn);
      LOG.info(msg + " No key recovery data found on this node.");
    }
    LOG.trace("<markAsRecoverable()");
    return returnval;
  }

  @Override
  public boolean markAsRecoverableInternal(
      final AuthenticationToken admin,
      final CertificateWrapper certificateWrapper,
      final String username) {
    final Certificate certificate = EJBUtil.unwrap(certificateWrapper);
    final String hexSerial =
        CertTools.getSerialNumber(certificate)
            .toString(16); // same method to make hex as in KeyRecoveryDataBean
    final String dn = CertTools.getIssuerDN(certificate);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">markAsRecoverable(issuer: "
              + dn
              + "; certificatesn: "
              + hexSerial
              + ")");
    }
    boolean returnval = false;
    org.ejbca.core.ejb.keyrecovery.KeyRecoveryData krd =
        org.ejbca.core.ejb.keyrecovery.KeyRecoveryData.findByPK(
            entityManager, new KeyRecoveryDataPK(hexSerial, dn));
    if (krd != null) {
      krd.setMarkedAsRecoverable(true);
      int caid = krd.getIssuerDN().hashCode();
      String msg =
          INTRES.getLocalizedMessage("keyrecovery.markedcert", hexSerial, dn);
      final Map<String, Object> details = new LinkedHashMap<>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.KEYRECOVERY_MARKED,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.KEYRECOVERY,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          String.valueOf(caid),
          hexSerial,
          username,
          details);
      returnval = true;
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "keyrecovery.errormarkcert", hexSerial, dn);
      LOG.info(msg);
    }
    LOG.trace("<markAsRecoverable()");
    return returnval;
  }

  @Override
  public void unmarkUser(
      final AuthenticationToken admin, final String username) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">unmarkUser(user: " + username + ")");
    }
    KeyRecoveryData krd = null;
    Collection<KeyRecoveryData> result =
        KeyRecoveryData.findByUserMark(entityManager, username);
    Iterator<KeyRecoveryData> i = result.iterator();
    while (i.hasNext()) {
      krd = i.next();
      krd.setMarkedAsRecoverable(false);
    }
    LOG.trace("<unmarkUser()");
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public boolean isUserMarked(final String username) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">isUserMarked(user: " + username + ")");
    }
    boolean returnval = false;
    Collection<KeyRecoveryData> result =
        KeyRecoveryData.findByUserMark(entityManager, username);
    for (KeyRecoveryData krd : result) {
      if (krd.getMarkedAsRecoverable()) {
        returnval = true;
        break;
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<isUserMarked(" + returnval + ")");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public boolean existsKeys(final CertificateWrapper certificateWrapper) {
    LOG.trace(">existsKeys()");
    final Certificate certificate = EJBUtil.unwrap(certificateWrapper);
    if (certificate == null) {
      LOG.debug("Key recovery requires a certificate to be present.");
      return false;
    }
    boolean returnval = false;
    final String hexSerial =
        CertTools.getSerialNumber(certificate)
            .toString(16); // same method to make hex as in KeyRecoveryDataBean
    final String dn = CertTools.getIssuerDN(certificate);
    KeyRecoveryData krd =
        KeyRecoveryData.findByPK(
            entityManager, new KeyRecoveryDataPK(hexSerial, dn));
    if (krd != null) {
      LOG.debug("Found key for user: " + krd.getUsername());
      returnval = true;
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<existsKeys(" + returnval + ")");
    }
    return returnval;
  }
}
