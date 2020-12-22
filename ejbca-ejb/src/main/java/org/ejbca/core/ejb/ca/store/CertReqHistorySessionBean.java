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

package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.store.CertReqHistory;

/**
 * Stores and manages CertReqHistory entries in the database. CertReqHistory
 * keeps a snapshot of the user data that was used to issue a specific
 * certificate.
 *
 * @version $Id: CertReqHistorySessionBean.java 28759 2018-04-20 13:50:37Z
 *     samuellb $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "CertReqHistorySessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertReqHistorySessionBean
    implements CertReqHistorySessionRemote, CertReqHistorySessionLocal {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CertReqHistorySessionBean.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** EJB. */
  @EJB private CertificateDataSessionLocal certificateDataSession;

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void addCertReqHistoryData(
      final Certificate cert, final EndEntityInformation endEntityInformation) {
    final String issuerDN = CertTools.getIssuerDN(cert);
    final String username = endEntityInformation.getUsername();
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">addCertReqHistoryData("
              + CertTools.getSerialNumberAsString(cert)
              + ", "
              + issuerDN
              + ", "
              + username
              + ")");
    }
    try {
      entityManager.persist(
          new CertReqHistoryData(cert, issuerDN, endEntityInformation));
      LOG.info(INTRES.getLocalizedMessage("store.storehistory", username));
    } catch (Exception e) {
      LOG.error(
          INTRES.getLocalizedMessage(
              "store.errorstorehistory", endEntityInformation.getUsername()));
      throw new EJBException(e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<addCertReqHistoryData()");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public void removeCertReqHistoryData(final String certFingerprint) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeCertReqHistData(" + certFingerprint + ")");
    }
    try {
      String msg =
          INTRES.getLocalizedMessage("store.removehistory", certFingerprint);
      LOG.info(msg);
      CertReqHistoryData crh =
          CertReqHistoryData.findById(entityManager, certFingerprint);
      if (crh == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Trying to remove CertReqHistory that does not exist: "
                  + certFingerprint);
        }
      } else {
        entityManager.remove(crh);
      }
    } catch (Exception e) {
      String msg =
          INTRES.getLocalizedMessage(
              "store.errorremovehistory", certFingerprint);
      LOG.info(msg);
      throw new EJBException(e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<removeCertReqHistData()");
    }
  }

  // getCertReqHistory() might perform database updates, so we always need to
  // run this in a transaction
  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public CertReqHistory retrieveCertReqHistory(
      final BigInteger certificateSN, final String issuerDN) {
    CertReqHistory retval = null;
    Collection<CertReqHistoryData> result =
        CertReqHistoryData.findByIssuerDNSerialNumber(
            entityManager, issuerDN, certificateSN.toString());
    if (result.iterator().hasNext()) {
      retval = result.iterator().next().getCertReqHistory();
    }
    return retval;
  }

  // getCertReqHistory() might perform database updates, so we always need to
  // run this in a transaction
  @TransactionAttribute(TransactionAttributeType.REQUIRED)
  @Override
  public List<CertReqHistory> retrieveCertReqHistory(final String username) {
    ArrayList<CertReqHistory> retval = new ArrayList<>();
    Collection<CertReqHistoryData> result =
        CertReqHistoryData.findByUsername(entityManager, username);
    Iterator<CertReqHistoryData> iter = result.iterator();
    while (iter.hasNext()) {
      retval.add(iter.next().getCertReqHistory());
    }
    return retval;
  }

  @Override
  public CertificateInfo findFirstCertificateInfo(
      final String issuerDN, final BigInteger serno) {
    return certificateDataSession.findFirstCertificateInfo(
        CertTools.stringToBCDNString(issuerDN), serno.toString());
  }
}
