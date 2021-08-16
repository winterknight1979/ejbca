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

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating
 * and retrieving CRLs and information about CRLs. CRLs are signed using
 * SignSessionBean.
 *
 * @version $Id: CrlStoreSessionBean.java 25498 2017-03-15 17:01:37Z jeklund $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CrlStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlStoreSessionBean
    implements CrlStoreSessionLocal, CrlStoreSessionRemote {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(CrlStoreSessionBean.class);

  /** Internal localization of logs and errors. */
  protected static final InternalResources INTRES =
      InternalResources.getInstance();

  /** EM.  */
  @PersistenceContext(unitName = CesecoreConfigurationHelper.PERSISTENCE_UNIT)
  private EntityManager entityManager;

  /** Auth. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** Log. */
  @EJB private SecurityEventsLoggerSessionLocal logSession;

  @Override
  public void storeCRL(
      final AuthenticationToken admin,
      final byte[] incrl,
      final String cafp,
      final int number,
      final String issuerDN,
      final Date thisUpdate,
      final Date nextUpdate,
      final int deltaCRLIndicator)
      throws CrlStoreException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">storeCRL(" + cafp + ", " + number + ")");
    }
    // Check that user is authorized to the CA that issued this CRL
    String bcdn = CertTools.stringToBCDNString(issuerDN);
    int caid = bcdn.hashCode();
    authorizedToCA(admin, caid);

    try {
      boolean deltaCRL = deltaCRLIndicator > 0;
      int lastNo = getLastCRLNumber(issuerDN, deltaCRL);
      if (number <= lastNo) {
        // There is already a CRL with this number, or a later one stored. Don't
        // create duplicates
        final String msg =
            INTRES.getLocalizedMessage(
                "store.errorstorecrlwrongnumber",
                Integer.valueOf(number),
                Integer.valueOf(lastNo),
                issuerDN);
        throw new CrlStoreException(msg);
      }
      CRLData data =
          new CRLData(
              incrl,
              number,
              issuerDN,
              thisUpdate,
              nextUpdate,
              cafp,
              deltaCRLIndicator);
      this.entityManager.persist(data);
      String msg =
          INTRES.getLocalizedMessage(
              "store.storecrl",
              Integer.valueOf(number),
              data.getFingerprint(),
              data.getIssuerDN());
      Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      logSession.log(
          EventTypes.CRL_STORED,
          EventStatus.SUCCESS,
          ModuleTypes.CRL,
          ServiceTypes.CORE,
          admin.toString(),
          String.valueOf(caid),
          null,
          null,
          details);
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage(
              "store.errorstorecrl", Integer.valueOf(number), issuerDN);
      LOG.error(msg, e);
      throw new CrlStoreException(e); // will rollback etc
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<storeCRL()");
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public byte[] getLastCRL(final String issuerdn, final boolean deltaCRL) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getLastCRL(" + issuerdn + ", " + deltaCRL + ")");
    }
    int maxnumber = 0;
    try {
      maxnumber = getLastCRLNumber(issuerdn, deltaCRL);
      byte[] crlbytes = null;
      final CRLData data =
          CRLData.findByIssuerDNAndCRLNumber(
              entityManager, issuerdn, maxnumber);
      if (data != null) {
        crlbytes = data.getCRLBytes();
        if (crlbytes != null) {
          final String msg =
              INTRES.getLocalizedMessage(
                  "store.getcrl", issuerdn, Integer.valueOf(maxnumber));
          LOG.info(msg);
          return crlbytes;
        }
      }
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage("store.errorgetcrl", issuerdn);
      LOG.info(msg);
      throw new EJBException(e);
    }
    final String msg =
        INTRES.getLocalizedMessage(
            "store.errorgetcrl", issuerdn, Integer.valueOf(maxnumber));
    LOG.info(msg);
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getLastCRL()");
    }
    return null;
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public byte[] getCRL(final String issuerdn, final int crlNumber) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCRL(" + issuerdn + ", " + crlNumber + ")");
    }
    byte[] crlbytes = null;
    final CRLData data =
        CRLData.findByIssuerDNAndCRLNumber(entityManager, issuerdn, crlNumber);
    if (data != null) {
      crlbytes = data.getCRLBytes();
      if (crlbytes != null) {
        final String msg =
            INTRES.getLocalizedMessage(
                "store.getcrl", issuerdn, Integer.valueOf(crlNumber));
        LOG.info(msg);
        return crlbytes;
      }
    }
    final String msg =
        INTRES.getLocalizedMessage(
            "store.errorgetcrl", issuerdn, Integer.valueOf(crlNumber));
    LOG.info(msg);
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getCRL()");
    }
    return null;
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public CRLInfo getLastCRLInfo(final String issuerdn, final boolean deltaCRL) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getLastCRLInfo(" + issuerdn + ", " + deltaCRL + ")");
    }
    int crlnumber = 0;
    try {
      crlnumber = getLastCRLNumber(issuerdn, deltaCRL);
      CRLInfo crlinfo = null;
      final CRLData data =
          CRLData.findByIssuerDNAndCRLNumber(
              entityManager, issuerdn, crlnumber);
      if (data != null) {
        crlinfo =
            new CRLInfo(
                data.getIssuerDN(),
                crlnumber,
                data.getThisUpdate(),
                data.getNextUpdate());
      } else {
        if (deltaCRL && (crlnumber == 0)) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("No delta CRL exists for CA with dn '" + issuerdn + "'");
          }
        } else if (crlnumber == 0) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("No CRL exists for CA with dn '" + issuerdn + "'");
          }
        } else {
          final String msg =
              INTRES.getLocalizedMessage(
                  "store.errorgetcrl", issuerdn, Integer.valueOf(crlnumber));
          LOG.error(msg);
        }
      }
      if (LOG.isTraceEnabled()) {
        LOG.trace("<getLastCRLInfo()");
      }
      return crlinfo;
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage("store.errorgetcrlinfo", issuerdn);
      LOG.info(msg);
      throw new EJBException(e);
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public CRLInfo getCRLInfo(final String fingerprint) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getCRLInfo(" + fingerprint + ")");
    }
    try {
      CRLInfo crlinfo = null;
      final CRLData data =
          CRLData.findByFingerprint(entityManager, fingerprint);
      if (data != null) {
        crlinfo =
            new CRLInfo(
                data.getIssuerDN(),
                data.getCrlNumber(),
                data.getThisUpdate(),
                data.getNextUpdate());
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug("No CRL exists with fingerprint '" + fingerprint + "'");
        }
        final String msg =
            INTRES.getLocalizedMessage(
                "store.errorgetcrl", fingerprint, Integer.valueOf(0));
        LOG.info(msg);
      }
      if (LOG.isTraceEnabled()) {
        LOG.trace("<getCRLInfo()");
      }
      return crlinfo;
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage("store.errorgetcrlinfo", fingerprint);
      LOG.info(msg);
      throw new EJBException(e);
    }
  }

  @Override
  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  public int getLastCRLNumber(final String issuerdn, final boolean deltaCRL) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getLastCRLNumber(" + issuerdn + ", " + deltaCRL + ")");
    }
    int maxnumber = 0;
    Integer result =
        CRLData.findHighestCRLNumber(entityManager, issuerdn, deltaCRL);
    if (result != null) {
      maxnumber = result.intValue();
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getLastCRLNumber(" + maxnumber + ")");
    }
    return maxnumber;
  }

  private void authorizedToCA(final AuthenticationToken admin, final int caid)
      throws AuthorizationDeniedException {
    if (!authorizationSession.isAuthorized(
        admin, StandardRules.CAACCESS.resource() + caid)) {
      final String msg =
          INTRES.getLocalizedMessage(
              "caadmin.notauthorizedtoca", admin.toString(), caid);
      throw new AuthorizationDeniedException(msg);
    }
  }
}
