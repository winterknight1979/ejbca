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

import java.util.Collection;
import java.util.List;
import javax.ejb.CreateException;
import javax.ejb.Local;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Local interface for PublisherQueueSession.
 *
 * @version $Id: PublisherQueueSessionLocal.java 29124 2018-06-06 10:37:55Z
 *     tarmo_r_helmes $
 */
@Local
public interface PublisherQueueSessionLocal {
  /**
   * Adds an entry to the publisher queue.
   *
   * @param publisherId the publisher that this should be published to
   * @param publishType the type of entry it is,
   *     PublisherQueueData#PUBLISH_TYPE_CERT or CRL
   * @param fingerprint FP
   * @param queueData Daya
   * @param publishStatus status
   * @throws CreateException if the entry can not be created
   */
  void addQueueData(
      int publisherId,
      int publishType,
      String fingerprint,
      PublisherQueueVolatileInformation queueData,
      int publishStatus)
      throws CreateException;

  /**
   * Removes an entry from the publisher queue.
   *
   * @param pk pk
   */
  void removeQueueData(String pk);

  /**
   * Finds all entries with status PublisherQueueData.STATUS_PENDING for a
   * specific publisherId.
   *
   * @param publisherId Id
   * @return Collection of PublisherQueueData, never null
   */
  Collection<PublisherQueueData> getPendingEntriesForPublisher(int publisherId);

  /**
   * Gets the number of pending entries for a publisher.
   *
   * @param publisherId The publisher to count the number of pending entries
   *     for.
   * @return The number of pending entries.
   */
  int getPendingEntriesCountForPublisher(int publisherId);

  /**
   * Gets an array with the number of new pending entries for a publisher in
   * each intervals specified by <i>lowerBounds</i> and <i>upperBounds</i>.
   *
   * <p>The interval is defined as from lowerBounds[i] to upperBounds[i] and the
   * unit is seconds from now. A negative or 0 value results in no boundary.
   *
   * @param publisherId The publisher to count the number of pending entries
   *     for.
   * @param lowerBounds bound
   * @param upperBounds bound
   * @return Array with the number of pending entries corresponding to each
   *     element in <i>interval</i>.
   */
  int[] getPendingEntriesCountForPublisherInIntervals(
      int publisherId, int[] lowerBounds, int[] upperBounds);

  /**
   * Finds all entries with status PublisherQueueData.STATUS_PENDING for a
   * specific publisherId.
   *
   * @param publisherId ID
   * @param limit limit
   * @param timeout timeout
   * @param orderBy order by clause for the SQL to the database, for example
   *     "order by timeCreated desc".
   * @return Collection of PublisherQueueData, never null
   */
  Collection<PublisherQueueData> getPendingEntriesForPublisherWithLimit(
      int publisherId, int limit, int timeout, String orderBy);

  /**
   * Finds all entries for a specific fingerprint.
   *
   * @param fingerprint FP
   * @return Collection of PublisherQueueData, never null
   */
  Collection<PublisherQueueData> getEntriesByFingerprint(String fingerprint);

  /**
   * Updates a record with new status.
   *
   * @param pk primary key of data entry
   * @param status status from PublisherQueueData.STATUS_SUCCESS etc, or -1 to
   *     not update status
   * @param tryCounter an updated try counter, or -1 to not update counter
   */
  void updateData(String pk, int status, int tryCounter);

  /**
   * Intended for use from PublishQueueProcessWorker.
   *
   * <p>Publishing algorithm that is a plain fifo queue, but limited to
   * selecting entries to republish at 100 records at a time. It will select
   * from the database for this particular publisher id, and process the record
   * that is returned one by one. The records are ordered by date, descending so
   * the oldest record is returned first. Publishing is tried every time for
   * every record returned, with no limit. Repeat this process as long as we
   * actually manage to publish something this is because when publishing starts
   * to work we want to publish everything in one go, if possible. However we
   * don't want to publish more than 20000 certificates each time, because we
   * want to commit to the database some time as well. Now, the OCSP publisher
   * uses a non-transactional data source so it commits every time so...
   *
   * @param admin admin
   * @param publisherId ID
   * @param publisher pub
   */
  void plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(
      AuthenticationToken admin, int publisherId, BasePublisher publisher);

  /**
   * Publishers do not run a part of regular transactions and expect to run in
   * auto-commit mode.
   *
   * @param publisher Pub
   * @param admin admin
   * @param cert cert
   * @param password pwd
   * @param userDN DN
   * @param extendedinformation info
   * @return bool
   * @throws PublisherException fail
   */
  boolean storeCertificateNonTransactional(
      BasePublisher publisher,
      AuthenticationToken admin,
      CertificateDataWrapper cert,
      String password,
      String userDN,
      ExtendedInformation extendedinformation)
      throws PublisherException;

  /**
   * Publishers do not run as part of regular transactions and expect to run in
   * auto-commit mode.
   *
   * @param publisher pub
   * @param admin admin
   * @param incrl crl
   * @param cafp fp
   * @param number num
   * @param userDN dn
   * @return crl
   * @throws PublisherException fail
   */
  boolean storeCRLNonTransactional(
      BasePublisher publisher,
      AuthenticationToken admin,
      byte[] incrl,
      String cafp,
      int number,
      String userDN)
      throws PublisherException;

  /**
   * Publishers do not run as part of regular transactions and expect to run in
   * auto-commit mode. This method is invoked locally to publish to multiple
   * publishers in parallel.
   *
   * <p>The implementing method returns the result in the same order as the
   * publishers are provided. Each result Object is either a PublisherException
   * (if the publishing failed) or a Boolean.TRUE (if the publishing succeeded).
   *
   * @param publishers pub
   * @param admin admin
   * @param certWrapper cert
   * @param password pwd
   * @param userDN dn
   * @param extendedinformation info
   * @return list
   */
  List<Object> storeCertificateNonTransactionalInternal(
      List<BasePublisher> publishers,
      AuthenticationToken admin,
      CertificateDataWrapper certWrapper,
      String password,
      String userDN,
      ExtendedInformation extendedinformation);

  /**
   * Publishers digest queues in transaction-based "chunks".
   *
   * @param admin admin
   * @param publisherId id
   * @param publisher pub
   * @return int
   */
  int doChunk(
      AuthenticationToken admin, int publisherId, BasePublisher publisher);
}
