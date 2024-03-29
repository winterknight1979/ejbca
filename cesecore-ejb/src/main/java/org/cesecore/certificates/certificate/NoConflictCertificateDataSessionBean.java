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
package org.cesecore.certificates.certificate;

import java.util.Collection;
import java.util.List;
import java.util.TimeZone;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.util.ValidityDateUtil;

/**
 * Low level CRUD functions to access NoConflictCertificateData.
 *
 * @version $Id: NoConflictCertificateDataSessionBean.java 28792 2018-04-27
 *     16:03:01Z samuellb $
 */
@Stateless // Local only bean, no remote interface
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class NoConflictCertificateDataSessionBean
    extends BaseCertificateDataSessionBean
    implements NoConflictCertificateDataSessionLocal {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(NoConflictCertificateDataSessionBean.class);

  /**
   * EM. */
  @PersistenceContext(unitName = CesecoreConfigurationHelper.PERSISTENCE_UNIT)
  private EntityManager entityManager;

  @Override
  protected String getTableName() {
    return "NoConflictCertificateData";
  }

  @Override
  protected EntityManager getEntityManager() {
    return entityManager;
  }

  //
  // Search functions.
  //
  @Override
  public List<NoConflictCertificateData> findByFingerprint(
      final String fingerprint) {
    final TypedQuery<NoConflictCertificateData> query =
        entityManager.createQuery(
            "SELECT a FROM NoConflictCertificateData a WHERE"
                + " a.fingerprint=:fingerprint",
            NoConflictCertificateData.class);
    query.setParameter("fingerprint", fingerprint);
    final List<NoConflictCertificateData> result = query.getResultList();
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "findByFingerprint("
              + fingerprint
              + ") yielded "
              + result.size()
              + " results.");
    }
    return result;
  }

  @Override
  public List<NoConflictCertificateData> findBySerialNumber(
      final String serialNumber) {
    final TypedQuery<NoConflictCertificateData> query =
        entityManager.createQuery(
            "SELECT a FROM NoConflictCertificateData a WHERE"
                + " a.serialNumber=:serialNumber",
            NoConflictCertificateData.class);
    query.setParameter("serialNumber", serialNumber);
    final List<NoConflictCertificateData> result = query.getResultList();
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "findBySerialNumber("
              + serialNumber
              + ") yielded "
              + result.size()
              + " results.");
    }
    return result;
  }

  @Override
  public List<NoConflictCertificateData> findByIssuerDNSerialNumber(
      final String issuerDN, final String serialNumber) {
    final String sql =
        "SELECT a FROM NoConflictCertificateData a WHERE a.issuerDN=:issuerDN"
            + " AND a.serialNumber=:serialNumber";
    final TypedQuery<NoConflictCertificateData> query =
        entityManager.createQuery(sql, NoConflictCertificateData.class);
    query.setParameter("issuerDN", issuerDN);
    query.setParameter("serialNumber", serialNumber);
    final List<NoConflictCertificateData> result = query.getResultList();
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "findByIssuerDNSerialNumber("
              + issuerDN
              + ", "
              + serialNumber
              + ") yielded "
              + result.size()
              + " results.");
    }
    return result;
  }

  @Override
  public Collection<RevokedCertInfo> getRevokedCertInfosWithDuplicates(
      final String issuerDN, final long lastbasecrldate) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Quering for revoked certificates in append-only table. IssuerDN: '"
              + issuerDN
              + "', Last Base CRL Date: "
              + FastDateFormat.getInstance(
                      ValidityDateUtil.ISO8601_DATE_FORMAT,
                      TimeZone.getTimeZone("GMT"))
                  .format(lastbasecrldate));
    }
    return getRevokedCertInfosInternal(issuerDN, lastbasecrldate, true);
  }
}
