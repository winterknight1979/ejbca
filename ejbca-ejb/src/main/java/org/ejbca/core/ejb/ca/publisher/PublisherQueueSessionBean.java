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

package org.ejbca.core.ejb.ca.publisher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.annotation.Resource;
import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Manages publisher queues which contains data to be republished, either
 * because publishing failed or because publishing is done asynchronously.
 *
 * @version $Id: PublisherQueueSessionBean.java 30284 2018-10-30 08:45:42Z
 *     samuellb $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "PublisherQueueSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherQueueSessionBean implements PublisherQueueSessionLocal {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(PublisherQueueSessionBean.class);
  /** param. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();
  /** param. */
  private static final ReentrantLock EXEC_SERVICE_LOCK =
      new ReentrantLock(false);
  /** param. */
  private static final AtomicInteger BEAN_INST_COUNT = new AtomicInteger(0);
  /** param. */
  private static volatile ExecutorService executorService = null;

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** Resource. */
  @Resource private SessionContext sessionContext;

  /** EJB. */
  @EJB
  private NoConflictCertificateStoreSessionLocal
      noConflictCertificateStoreSession;

  /** not injected but created in ejbCreate, since it is ourself. */
  private PublisherQueueSessionLocal publisherQueueSession;

  /** Init. */
  @PostConstruct
  public void postConstruct() {
    publisherQueueSession =
        sessionContext.getBusinessObject(PublisherQueueSessionLocal.class);
    // Keep track of number of instances of this bean, so we can free the
    // executorService thread pool when the last is destroyed
    BEAN_INST_COUNT.incrementAndGet();
  }

  /** Dhutdown. */
  @PreDestroy
  public void preDestroy() {
    // Shut down the thread pool when the last instance of this SSB is destroyed
    if (BEAN_INST_COUNT.decrementAndGet() == 0) {
      EXEC_SERVICE_LOCK.lock();
      try {
        if (executorService != null) {
          executorService.shutdown();
          executorService = null;
        }
      } finally {
        EXEC_SERVICE_LOCK.unlock();
      }
    }
  }

  /**
   * @return a reference to the "CachedThreadPool" executor service (creating
   *     one if needed).
   */
  private ExecutorService getExecutorService() {
    if (executorService == null) {
      EXEC_SERVICE_LOCK.lock();
      try {
        if (executorService == null) {
          executorService = Executors.newCachedThreadPool();
        }
      } finally {
        EXEC_SERVICE_LOCK.unlock();
      }
    }
    return executorService;
  }

  @Override
  public void addQueueData(
      final int publisherId,
      final int publishType,
      final String fingerprint,
      final PublisherQueueVolatileInformation queueData,
      final int publishStatus)
      throws CreateException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addQueueData(publisherId: " + publisherId + ")");
    }
    try {
      entityManager.persist(
          new org.ejbca.core.ejb.ca.publisher.PublisherQueueData(
              publisherId, publishType, fingerprint, queueData, publishStatus));
    } catch (Exception e) {
      throw new CreateException(e.getMessage());
    }
    LOG.trace("<addQueueData()");
  }

  @Override
  public void removeQueueData(final String pk) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeQueueData(pk: " + pk + ")");
    }
    try {
      org.ejbca.core.ejb.ca.publisher.PublisherQueueData pqd =
          org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(
              entityManager, pk);
      if (pqd == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Trying to remove queue data that does not exist: " + pk);
        }
      } else {
        entityManager.remove(pqd);
      }
    } catch (Exception e) {
      LOG.info(e);
    }
    LOG.trace("<removeQueueData()");
  }

  @Override
  public Collection<PublisherQueueData> getPendingEntriesForPublisher(
      final int publisherId) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">getPendingEntriesForPublisher(publisherId: " + publisherId + ")");
    }
    Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas =
        org.ejbca.core.ejb.ca.publisher.PublisherQueueData
            .findDataByPublisherIdAndStatus(
                entityManager, publisherId, PublisherConst.STATUS_PENDING, 0);
    if (datas.isEmpty()) {
      LOG.debug(
          "No publisher queue entries found for publisher " + publisherId);
    }
    Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
    Iterator<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> iter =
        datas.iterator();
    while (iter.hasNext()) {
      org.ejbca.core.ejb.ca.publisher.PublisherQueueData d = iter.next();
      PublisherQueueData pqd =
          new PublisherQueueData(
              d.getPk(),
              new Date(d.getTimeCreated()),
              new Date(d.getLastUpdate()),
              d.getPublishStatus(),
              d.getTryCounter(),
              d.getPublishType(),
              d.getFingerprint(),
              d.getPublisherId(),
              d.getPublisherQueueVolatileData());
      ret.add(pqd);
    }
    LOG.trace("<getPendingEntriesForPublisher()");
    return ret;
  }

  @Override
  public int getPendingEntriesCountForPublisher(final int publisherId) {
    return (int)
        org.ejbca.core.ejb.ca.publisher.PublisherQueueData
            .findCountOfPendingEntriesForPublisher(entityManager, publisherId);
  }

  @Override
  public int[] getPendingEntriesCountForPublisherInIntervals(
      final int publisherId, final int[] lowerBounds, final int[] upperBounds) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">getPendingEntriesCountForPublisherInIntervals(publisherId: "
              + publisherId
              + ", lower:"
              + Arrays.toString(lowerBounds)
              + ", upper:"
              + Arrays.toString(upperBounds)
              + ")");
    }
    if (lowerBounds.length != upperBounds.length) {
      throw new IllegalArgumentException(
          "lowerBounds and upperBounds must have equal length");
    }
    List<Integer> entryCountList =
        org.ejbca.core.ejb.ca.publisher.PublisherQueueData
            .findCountOfPendingEntriesForPublisher(
                entityManager, publisherId, lowerBounds, upperBounds);
    int[] result = new int[lowerBounds.length];
    for (int i = 0; i < lowerBounds.length && i < result.length; i++) {
      result[i] = entryCountList.get(i).intValue();
    }
    LOG.trace("<getPendingEntriesCountForPublisherInIntervals()");
    return result;
  }

  @Override
  public Collection<PublisherQueueData> getPendingEntriesForPublisherWithLimit(
      final int publisherId,
      final int limit,
      final int timeout,
      final String orderBy) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">getPendingEntriesForPublisherWithLimit(publisherId: "
              + publisherId
              + ")");
    }
    Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
    // TODO: This code has been modified from JDBC to JPA fetching, which might
    // negatively affect performance. Investigate.
    List<org.ejbca.core.ejb.ca.publisher.PublisherQueueData>
        publisherQueueDataList =
            org.ejbca.core.ejb.ca.publisher.PublisherQueueData
                .findDataByPublisherIdAndStatus(
                    entityManager,
                    publisherId,
                    PublisherConst.STATUS_PENDING,
                    limit);
    for (org.ejbca.core.ejb.ca.publisher.PublisherQueueData publisherQueueData
        : publisherQueueDataList) {
      PublisherQueueData pqd =
          new PublisherQueueData(
              publisherQueueData.getPk(),
              new Date(publisherQueueData.getTimeCreated()),
              new Date(publisherQueueData.getLastUpdate()),
              PublisherConst.STATUS_PENDING,
              publisherQueueData.getTryCounter(),
              publisherQueueData.getPublishType(),
              publisherQueueData.getFingerprint(),
              publisherId,
              publisherQueueData.getPublisherQueueVolatileData());
      ret.add(pqd);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Return pending record with pk "
                + publisherQueueData.getPk()
                + ", and timeCreated "
                + new Date(publisherQueueData.getTimeCreated()));
      }
    }
    LOG.trace("<getPendingEntriesForPublisherWithLimit()");
    return ret;
  }

  @Override
  public Collection<PublisherQueueData> getEntriesByFingerprint(
      final String fingerprint) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getEntriesByFingerprint(fingerprint: " + fingerprint + ")");
    }
    Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
    Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas =
        org.ejbca.core.ejb.ca.publisher.PublisherQueueData
            .findDataByFingerprint(entityManager, fingerprint);
    if (datas.isEmpty()) {
      LOG.debug(
          "No publisher queue entries found for fingerprint " + fingerprint);
    } else {
      Iterator<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> iter =
          datas.iterator();
      while (iter.hasNext()) {
        org.ejbca.core.ejb.ca.publisher.PublisherQueueData d = iter.next();
        PublisherQueueData pqd =
            new PublisherQueueData(
                d.getPk(),
                new Date(d.getTimeCreated()),
                new Date(d.getLastUpdate()),
                d.getPublishStatus(),
                d.getTryCounter(),
                d.getPublishType(),
                d.getFingerprint(),
                d.getPublisherId(),
                d.getPublisherQueueVolatileData());
        ret.add(pqd);
      }
    }
    LOG.trace("<getEntriesByFingerprint()");
    return ret;
  }

  @Override
  public void updateData(
      final String pk, final int status, final int tryCounter) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">updateData(pk: " + pk + ", status: " + status + ")");
    }
    org.ejbca.core.ejb.ca.publisher.PublisherQueueData data =
        org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(
            entityManager, pk);
    if (data != null) {
      if (status > 0) {
        data.setPublishStatus(status);
      }
      data.setLastUpdate(new Date().getTime());
      if (tryCounter > -1) {
        data.setTryCounter(tryCounter);
      }
    } else {
      LOG.debug("Trying to set status on nonexisting data, pk: " + pk);
    }
    LOG.trace("<updateData()");
  }

  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public void plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(
      final AuthenticationToken admin,
      final int publisherId,
      final BasePublisher publisher) {
    int successcount = 0;
    // Repeat this process as long as we actually manage to publish something
    // this is because when publishing starts to work we want to publish
    // everything in one go, if possible.
    // However we don't want to publish more than 20000 certificates each time,
    // because we want to commit to the database some time as well.
    int totalcount = 0;
    final int max = 20000;
    do {
      successcount =
          publisherQueueSession.doChunk(admin, publisherId, publisher);
      totalcount += successcount;
    } while ((successcount > 0) && (totalcount < max));
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
  @Override
  public int doChunk(
      final AuthenticationToken admin,
      final int publisherId,
      final BasePublisher publisher) {
    final Collection<PublisherQueueData> c =
        getPendingEntriesForPublisherWithLimit(
            publisherId, 100, 60, "order by timeCreated");
    return doPublish(admin, publisherId, publisher, c);
  }

  /**
   * @param admin Admin
   * @param publisherId ID
   * @param publisher Pub
   * @param c Data
   * @return how many publishes that succeeded
   */
  private int doPublish(
      final AuthenticationToken admin,
      final int publisherId,
      final BasePublisher publisher,
      final Collection<PublisherQueueData> c) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Found "
              + c.size()
              + " certificates to republish for publisher "
              + publisherId);
    }
    int successcount = 0;
    int failcount = 0;

    for (PublisherQueueData pqd : c) {

      String fingerprint = pqd.getFingerprint();
      int publishType = pqd.getPublishType();
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Publishing from queue to publisher: "
                + publisherId
                + ", fingerprint: "
                + fingerprint
                + ", pk: "
                + pqd.getPk()
                + ", type: "
                + publishType);
      }
      PublisherQueueVolatileInformation voldata = pqd.getVolatileData();
      String password = null;
      ExtendedInformation ei = null;
      String userDataDN = null;
      if (voldata != null) {
        password = voldata.getPassword();
        ei = voldata.getExtendedInformation();
        userDataDN = voldata.getUserDN();
      }
      boolean published = false;

      try {
        if (publishType == PublisherConst.PUBLISH_TYPE_CERT) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing Certificate");
          }
          if (publisher != null) {
            // Read the actual certificate and try to publish it
            // again
            // TODO: we might need change fetch-type for all but the
            // actual cert or a native query w SqlResultSetMapping..
            final CertificateDataWrapper certificateDataWrapper =
                noConflictCertificateStoreSession.getCertificateData(
                    fingerprint);
            if (certificateDataWrapper == null) {
              throw new FinderException();
            }
            try {
              published =
                  publisherQueueSession.storeCertificateNonTransactional(
                      publisher,
                      admin,
                      certificateDataWrapper,
                      password,
                      userDataDN,
                      ei);
            } catch (EJBException e) {
              final Throwable t = e.getCause();
              if (t instanceof PublisherException) {
                throw (PublisherException) t;
              } else {
                throw e;
              }
            }
          } else {
            String msg =
                INTRES.getLocalizedMessage(
                    "publisher.nopublisher", publisherId);
            LOG.info(msg);
          }
        } else if (publishType == PublisherConst.PUBLISH_TYPE_CRL) {
          if (LOG.isDebugEnabled()) {
            LOG.debug("Publishing CRL");
          }

          CRLData crlData =
              CRLData.findByFingerprint(entityManager, fingerprint);

          if (crlData == null) {
            throw new FinderException();
          }
          try {
            published =
                publisherQueueSession.storeCRLNonTransactional(
                    publisher,
                    admin,
                    crlData.getCRLBytes(),
                    crlData.getCaFingerprint(),
                    crlData.getCrlNumber(),
                    userDataDN);
          } catch (EJBException e) {
            final Throwable t = e.getCause();
            if (t instanceof PublisherException) {
              throw (PublisherException) t;
            } else {
              throw e;
            }
          }
        } else {
          String msg =
              INTRES.getLocalizedMessage("publisher.unknowntype", publishType);
          LOG.error(msg);
        }
      } catch (FinderException e) {
        final String msg =
            INTRES.getLocalizedMessage("publisher.errornocert", fingerprint)
                + e.getMessage();
        LOG.info(msg);
      } catch (PublisherException e) {
        // Publisher session have already logged this error nicely to
        // getLogSession().log
        LOG.debug(e.getMessage());
        // We failed to publish, update failcount so we can break early
        // if nothing succeeds but everything fails.
        failcount++;
      }
      if (published) {

        if (publisher.getKeepPublishedInQueue()) {
          // Update with information that publishing was successful
          updateData(
              pqd.getPk(), PublisherConst.STATUS_SUCCESS, pqd.getTryCounter());
        } else {
          // We are done with this one.. nuke it!
          removeQueueData(pqd.getPk());
        }

        successcount++; // jipeee update success counter
      } else {
        // Update with new tryCounter, but same status as before
        int tryCount = pqd.getTryCounter() + 1;
        updateData(pqd.getPk(), pqd.getPublishStatus(), tryCount);
      }
      // If we don't manage to publish anything, but fails on all the
      // first ten ones we expect that this publisher is dead for now. We
      // don't have to try with every record.
      if ((successcount == 0) && (failcount > 10)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Breaking out of publisher loop because everything seems to fail"
                  + " (at least the first 10 entries)");
        }
        break;
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Returning from publisher with "
              + successcount
              + " entries published successfully.");
    }
    return successcount;
  }

  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public boolean storeCertificateNonTransactional(
      final BasePublisher publisher,
      final AuthenticationToken admin,
      final CertificateDataWrapper certWrapper,
      final String password,
      final String userDN,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    if (publisher.isFullEntityPublishingSupported()) {
      return publisher.storeCertificate(
          admin,
          certWrapper.getCertificateDataOrCopy(),
          certWrapper.getBase64CertData(),
          password,
          userDN,
          extendedinformation);
    } else {
      final BaseCertificateData certificateData =
          certWrapper.getBaseCertificateData();
      final String cAFingerprint = certificateData.getCaFingerprint();
      final int status = certificateData.getStatus();
      final int type = certificateData.getType();
      final long revocationDate = certificateData.getRevocationDate();
      final int revocationReason = certificateData.getRevocationReason();
      final String username = certificateData.getUsername();
      final String tag = certificateData.getTag();
      final Integer certificateProfileId =
          certificateData.getCertificateProfileId();
      final Long updateTime = certificateData.getUpdateTime();
      return publisher.storeCertificate(
          admin,
          certWrapper.getCertificate(),
          username,
          password,
          userDN,
          cAFingerprint,
          status,
          type,
          revocationDate,
          revocationReason,
          tag,
          certificateProfileId,
          updateTime,
          extendedinformation);
    }
  }

  /**
   * Publishers do not run a part of regular transactions and expect to run in
   * auto-commit mode.
   */
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public boolean storeCRLNonTransactional(
      final BasePublisher publisher,
      final AuthenticationToken admin,
      final byte[] incrl,
      final String cafp,
      final int number,
      final String userDN)
      throws PublisherException {
    return publisher.storeCRL(admin, incrl, cafp, number, userDN);
  }

  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public List<Object> storeCertificateNonTransactionalInternal(
      final List<BasePublisher> publishers,
      final AuthenticationToken admin,
      final CertificateDataWrapper certWrapper,
      final String password,
      final String userDN,
      final ExtendedInformation extendedinformation) {
    final List<Object> publisherResults = new ArrayList<Object>();
    @SuppressWarnings("deprecation")
    final boolean parallel = EjbcaConfiguration.isPublishParallelEnabled();
    // Are we doing parallel publishing (only meaningful if there is more than
    // one publisher configured)?
    if (parallel && publishers.size() > 1) {
      final List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();
      BasePublisher publisherFirst = null;
      for (final BasePublisher publisher : publishers) {
        if (publisherFirst == null) {
          // We will execute the first of the publishers in the main thread...
          publisherFirst = publisher;
        } else {
          // ...and the rest of the publishers will be executed in new threads
          final Future<Boolean> future =
              getExecutorService()
                  .submit(
                      new Callable<Boolean>() {
                        @Override
                        public Boolean call() throws Exception {
                          if (!storeCertificateNonTransactional(
                              publisher,
                              admin,
                              certWrapper,
                              password,
                              userDN,
                              extendedinformation)) {
                            throw new PublisherException(
                                "Return code from publisher is false.");
                          }
                          return Boolean.TRUE;
                        }
                      });
          futures.add(future);
        }
      }
      // Wait at most 300 seconds in total for all the publishers to complete.
      final long deadline = System.currentTimeMillis() + 300000L;
      // Execute the first publishing in the calling thread
      Object publisherResultFirst;
      try {
        if (!storeCertificateNonTransactional(
            publisherFirst,
            admin,
            certWrapper,
            password,
            userDN,
            extendedinformation)) {
          throw new PublisherException("Return code from publisher is false.");
        }
        publisherResultFirst = Boolean.TRUE;
      } catch (Exception e) {
        publisherResultFirst = getAsPublisherException(e);
      }
      publisherResults.add(publisherResultFirst);
      // Wait for all the background threads to finish and get the result from
      // each invocation
      for (final Future<Boolean> future : futures) {
        Object publisherResult;
        try {
          final long maxTimeToWait =
              Math.max(1000L, deadline - System.currentTimeMillis());
          publisherResult =
              Boolean.valueOf(future.get(maxTimeToWait, TimeUnit.MILLISECONDS));
        } catch (Exception e) {
          publisherResult = getAsPublisherException(e);
        }
        publisherResults.add(publisherResult);
      }
    } else {
      // Perform publishing sequentially (old fall back behavior)
      for (final BasePublisher publisher : publishers) {
        try {
          if (!storeCertificateNonTransactional(
              publisher,
              admin,
              certWrapper,
              password,
              userDN,
              extendedinformation)) {
            throw new PublisherException(
                "Return code from publisher is false.");
          }
          publisherResults.add(Boolean.TRUE);
        } catch (Exception e) {
          publisherResults.add(getAsPublisherException(e));
        }
      }
    }
    return publisherResults;
  }

  private PublisherException getAsPublisherException(final Exception e) {
    LOG.debug("Publisher threw exception", e);
    if (e instanceof PublisherException) {
      return (PublisherException) e;
    }
    Throwable t = e;
    while (t.getCause() != null) {
      t = t.getCause();
      if (t instanceof PublisherException) {
        return (PublisherException) t;
      }
    }
    return new PublisherException(e.getMessage());
  }
}
