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
package org.cesecore.certificates.crl;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CRLHolder;
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
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderUtil;

/**
 * Business class for CRL actions, i.e. running CRLs.
 *
 * @version $Id: CrlCreateSessionBean.java 25498 2017-03-15 17:01:37Z jeklund $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "CrlCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlCreateSessionBean
    implements CrlCreateSessionLocal, CrlCreateSessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CrlCreateSessionBean.class);
  /** Internal localization of logs and errors. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** Auth. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** CRL. */
  @EJB private CrlStoreSessionLocal crlSession;
  /** Crypto. */
  @EJB private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
  /** Log. */
  @EJB private SecurityEventsLoggerSessionLocal logSession;

  /** Setup. */
  @PostConstruct
  public void postConstruct() {
    // Install BouncyCastle provider if not available
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }

  @Override
  public byte[] generateAndStoreCRL(
      final AuthenticationToken admin,
      final CA ca,
      final Collection<RevokedCertInfo> certs,
      final int basecrlnumber,
      final int onextCrlNumber)
      throws CryptoTokenOfflineException, AuthorizationDeniedException {
      int nextCrlNumber = onextCrlNumber;
    if (LOG.isTraceEnabled()) {
      LOG.trace(">createCRL(Collection)");
    }
    byte[] crlBytes = null; // return value

    // Check that we are allowed to create CRLs
    // Authorization for other things, that we have access to the CA has already
    // been done
    final int caid = ca.getCAId();
    authorizedToCreateCRL(admin, caid);

    try {
      assertActiveCA(ca);
      final X509CRLHolder crl;

      boolean deltaCRL = basecrlnumber > -1;
      final CryptoToken cryptoToken =
          cryptoTokenManagementSession.getCryptoToken(
              ca.getCAToken().getCryptoTokenId());
      assertTokenNotNull(ca, cryptoToken);
      if (deltaCRL) {
        // Workaround if transaction handling fails so that crlNumber for
        // deltaCRL would happen to be the same
        if (nextCrlNumber == basecrlnumber) {
          nextCrlNumber++;
        }
        crl =
            ca.generateDeltaCRL(
                cryptoToken, certs, nextCrlNumber, basecrlnumber);
      } else {
        crl = ca.generateCRL(cryptoToken, certs, nextCrlNumber);
      }
      if (crl != null) {
        // Store CRL in the database, this can still fail so the whole thing is
        // rolled back
        String cafp = CertTools.getFingerprintAsString(ca.getCACertificate());
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Encoding CRL to byte array. Free memory="
                  + Runtime.getRuntime().freeMemory());
        }
        byte[] tmpcrlBytes = crl.getEncoded();
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Finished encoding CRL to byte array. Free memory="
                  + Runtime.getRuntime().freeMemory());
          LOG.debug("Storing CRL in certificate store.");
        }
        crlSession.storeCRL(
            admin,
            tmpcrlBytes,
            cafp,
            nextCrlNumber,
            crl.getIssuer().toString(),
            crl.toASN1Structure().getThisUpdate().getDate(),
            crl.toASN1Structure().getNextUpdate().getDate(),
            deltaCRL ? 1 : -1);
        String msg =
            INTRES.getLocalizedMessage(
                "createcrl.createdcrl",
                Integer.valueOf(nextCrlNumber),
                ca.getName(),
                ca.getSubjectDN());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        logSession.log(
            EventTypes.CRL_CREATION,
            EventStatus.SUCCESS,
            ModuleTypes.CRL,
            ServiceTypes.CORE,
            admin.toString(),
            String.valueOf(caid),
            null,
            null,
            details);
        // Now all is finished and audit logged, now we are ready to "really"
        // set the return value
        crlBytes = tmpcrlBytes;
      }
    } catch (Exception e) {
      handleCRLException(admin, ca, caid, e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<createCRL(Collection)");
    }
    return crlBytes;
  }

/**
 * @param ca CA
 * @param cryptoToken Token
 * @throws CryptoTokenOfflineException Fail
 */
private void assertTokenNotNull(final CA ca, final CryptoToken cryptoToken)
        throws CryptoTokenOfflineException {
    if (cryptoToken == null) {
        throw new CryptoTokenOfflineException(
            "Could not find CryptoToken with id "
                + ca.getCAToken().getCryptoTokenId());
      }
}

/**
 * @param admin Admin
 * @param ca CA
 * @param caid ID
 * @param e Exception
 * @throws AuditRecordStorageException Fail
 * @throws EJBException Fail
 * @throws CryptoTokenOfflineException fail
 */
private void handleCRLException(final AuthenticationToken admin,
        final CA ca, final int caid, final Exception e)
        throws AuditRecordStorageException, EJBException,
        CryptoTokenOfflineException {
    LOG.info("Error generating CRL: ", e);
      String msg =
          INTRES.getLocalizedMessage(
              "createcrl.errorcreate", ca.getName(), e.getMessage());
      Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      logSession.log(
          EventTypes.CRL_CREATION,
          EventStatus.FAILURE,
          ModuleTypes.CRL,
          ServiceTypes.CORE,
          admin.toString(),
          String.valueOf(caid),
          null,
          null,
          details);
      if (e instanceof CryptoTokenOfflineException) { // NOPMD
          throw (CryptoTokenOfflineException) e;
      }
      if (e instanceof EJBException) { // NOPMD: no point in creating a new one
        throw (EJBException) e;
      }
      throw new EJBException(msg, e);
}

/**
 * @param ca CA
 * @throws CryptoTokenOfflineException fail
 */
private void assertActiveCA(final CA ca) throws CryptoTokenOfflineException {
    if (ca.getStatus() != CAConstants.CA_ACTIVE
          && ca.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
        String msg =
            INTRES.getLocalizedMessage(
                "createcert.canotactive", ca.getSubjectDN());
        throw new CryptoTokenOfflineException(msg);
      }
}

  private void authorizedToCreateCRL(
      final AuthenticationToken admin, final int caid)
      throws AuthorizationDeniedException {
    if (!authorizationSession.isAuthorized(
        admin, StandardRules.CREATECRL.resource())) {
      final String msg =
          INTRES.getLocalizedMessage(
              "createcrl.notauthorized", admin.toString(), caid);
      throw new AuthorizationDeniedException(msg);
    }
  }
}
