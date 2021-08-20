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
package org.cesecore.audit.impl.integrityprotected;

import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogger;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.time.TrustedTime;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.QueryResultWrapper;

/**
 * An alternative implementation of the SecurityEventsLogger interface. It
 * handles the creation of a signed log for an event.
 *
 * <p>This was created to evaluate the performance of using database integrity
 * protection instead of custom code for log singing.
 *
 * @version $Id: IntegrityProtectedLoggerSessionBean.java 24600 2016-10-31
 *     12:01:55Z jeklund $
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class IntegrityProtectedLoggerSessionBean
    implements IntegrityProtectedLoggerSessionLocal {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(IntegrityProtectedLoggerSessionBean.class);

  /** EM. */
  @PersistenceContext(unitName = CesecoreConfigurationHelper.PERSISTENCE_UNIT)
  private EntityManager entityManager;

  /** Setup. */
  @PostConstruct
  public void postConstruct() {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }

  /**
   * Initialization of the log sequence number in combination with nodeId should
   * be performed exactly once.
   *
   * <p>This callback will be invoked on the first call to
   * NodeSequenceHolder.getNext(...) to perform this initialization.
   *
   * <p>In this callback implementation, the nodeId is first read from the
   * configuration (which may default to reading the current hostname from the
   * system). This hostname is then passed to the next method to figure out what
   * the highest present sequenceNumber for this nodeId is in the database (e.g.
   * last write before shutting down).
   */
  private final NodeSequenceHolder.OnInitCallBack sequenceHolderInitialization =
      new NodeSequenceHolder.OnInitCallBack() {
        @Override
        public String getNodeId() {
          return CesecoreConfigurationHelper.getNodeIdentifier();
        }

        @Override
        public long getMaxSequenceNumberForNode(final String nodeId) {
          // Get the latest sequenceNumber from last run from the database..
          final Query query =
              entityManager.createQuery(
                  "SELECT MAX(a.sequenceNumber) FROM AuditRecordData a WHERE"
                      + " a.nodeId=:nodeId");
          query.setParameter("nodeId", nodeId);
          return QueryResultWrapper.getSingleResult(query, Long.valueOf(-1))
              .longValue();
        }
      };

  @Override
  @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
  // Always persist audit log
  public void log(
      final TrustedTime trustedTime,
      final AuditLogger.Event event,
      final ModuleType module,
      final ServiceType service,
      final String authToken,
      final String customId,
      final AuditLogger.Details details)
      throws AuditRecordStorageException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          String.format(
              ">log:%s:%s:%s:%s:%s:%s",
              event.getEventType(),
              event.getEventStatus(),
              module,
              service,
              authToken,
              details.getAdditionalDetails()));
    }
    try {
      final Long sequenceNumber =
          NodeSequenceHolder.INSTANCE.getNext(sequenceHolderInitialization);
      // Make sure to use the Node Identifier that this log sequence was
      // initialized with (for example hostnames reported by the system could
      // change)
      final String nodeId = NodeSequenceHolder.INSTANCE.getNodeId();
      final Long timeStamp = Long.valueOf(trustedTime.getTime().getTime());
      final AuditRecordData auditRecordData =
          new AuditRecordData(
              nodeId,
              sequenceNumber,
              timeStamp,
              event.getEventType(),
              event.getEventStatus(),
              authToken,
              service,
              module,
              customId,
              details.getSearchDetail1(),
              details.getSearchDetail2(),
              details.getAdditionalDetails());
      entityManager.persist(auditRecordData);
    } catch (Exception e) {
      LOG.error(e.getMessage(), e);
      throw new AuditRecordStorageException(e.getMessage(), e);
    } finally {
      if (LOG.isTraceEnabled()) {
        LOG.trace("<log");
      }
    }
  }
}
