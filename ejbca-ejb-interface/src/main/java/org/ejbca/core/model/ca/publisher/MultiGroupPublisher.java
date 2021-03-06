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
package org.ejbca.core.model.ca.publisher;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.ThreadLocalRandom;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Publishes to multiple groups of publishers. For each group it publishes to
 * one random publisher.
 *
 * <p>Useful when you have a lot of publishers, and you want to manage them in a
 * single place.
 *
 * @version $Id: MultiGroupPublisher.java 34192 2020-01-07 15:10:21Z aminkh $
 */
public class MultiGroupPublisher extends BasePublisher {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(MultiGroupPublisher.class);

  private static final long serialVersionUID = 1L;

  /** Config. */
  private static final float LATEST_VERSION = 1.0F;
  /** Config. */
  private static final String PROPERTYKEY_PUBLISHERGROUPS = "publishergroups";

  /** Param. */
  private transient PublisherSessionLocal cachedPublisherSession;

  /** Null constructor. */
  public MultiGroupPublisher() {
    super();
    data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
    data.put(PROPERTYKEY_PUBLISHERGROUPS, new ArrayList<>());
  }

  /**
   * @return Groups
   */
  @SuppressWarnings("unchecked")
  public List<TreeSet<Integer>> getPublisherGroups() {
    final Object value = data.get(PROPERTYKEY_PUBLISHERGROUPS);
    return value != null
        ? (List<TreeSet<Integer>>) value
        : new ArrayList<TreeSet<Integer>>();
  }

  /**
   * @param publisherGroups Groups
   */
  public void setPublisherGroups(final List<TreeSet<Integer>> publisherGroups) {
    data.put(PROPERTYKEY_PUBLISHERGROUPS, new ArrayList<>(publisherGroups));
  }

  private PublisherSessionLocal getPublisherSession() {
    if (cachedPublisherSession == null) {
      cachedPublisherSession = new EjbLocalHelper().getPublisherSession();
    }
    return cachedPublisherSession;
  }

  private BasePublisher getPublisher(final int publisherId) {
    return getPublisherSession().getPublisher(publisherId);
  }

  /**
   * Returns a list of publishers to use for some certificate or CRL. The result
   * is randomized, so it will return a different result each time. This method
   * uses the PublisherCache for better performance.
   *
   * @param getAll Return ALL publishers in each group, instead of only a random
   *     one.
   * @return List of publishers to use.
   */
  private List<BasePublisher> getPublishersToUse(final boolean getAll) {
    final List<BasePublisher> publishers = new ArrayList<>();
    for (final TreeSet<Integer> group : getPublisherGroups()) {
      if (getAll) {
        for (int publisherId : group) {
          final BasePublisher publisher = getPublisher(publisherId);
          if (publisher != null) {
            publishers.add(publisher);
          } else if (LOG.isDebugEnabled()) {
            LOG.debug("Ignoring non-existent publisher: " + publisherId);
          }
        }
      } else {
        final List<Integer> ids = new ArrayList<>(group);
        while (!ids.isEmpty()) {
          // Grab a random publisher
          final int index = ThreadLocalRandom.current().nextInt(ids.size());
          final int publisherId = ids.get(index);
          final BasePublisher publisher = getPublisher(publisherId);
          if (publisher != null) {
            publishers.add(publisher);
            break;
          } else {
            // This happens when clicking "Test Connection", so it won't spam
            // the logs
            LOG.warn(
                "Ignoring non-existent publisher "
                    + publisherId
                    + " in publisher "
                    + getName());
          }
          ids.remove(index);
        }
      }
    }
    return publishers;
  }

  @Override
  public boolean willPublishCertificate(
      final int status, final int revocationReason) {
    LOG.trace(">willPublishCertificate");
    // We don't know exactly which publishers storeCertificate will use,
    // so we just check the "first" one in each group. ("first" means lowest ID)
    for (final TreeSet<Integer> group : getPublisherGroups()) {
      if (group.isEmpty()) {
        LOG.debug("An empty group was found in publisher '" + getName() + "'");
      }
      final int publisherId = group.first();
      final BasePublisher publisher = getPublisher(publisherId);
      if (publisher.willPublishCertificate(status, revocationReason)) {
        LOG.trace("<willPublishCertificate: true");
        return true;
      }
    }
    LOG.trace("<willPublishCertificate: false");
    return false;
  }

  @Override
  public boolean storeCertificate(
      final AuthenticationToken admin,
      final Certificate incert,
      final String username,
      final String password,
      final String userDN,
      final String cafp,
      final int status,
      final int type,
      final long revocationDate,
      final int revocationReason,
      final String tag,
      final int certificateProfileId,
      final long lastUpdate,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    throw new UnsupportedOperationException(
        "Legacy storeCertificate method should never have been invoked for"
            + " this publisher.");
  }

  @Override
  public boolean storeCertificate(
      final AuthenticationToken authenticationToken,
      final CertificateData certificateData,
      final Base64CertData base64CertData)
      throws PublisherException {
    throw new UnsupportedOperationException(
        "Internal error. Wrong storeCertificate method was called.");
  }

  @Override
  public boolean storeCertificate(
      final AuthenticationToken authenticationToken,
      final CertificateData certificateData,
      final Base64CertData base64CertData,
      final String password,
      final String userDN,
      final ExtendedInformation extendedinformation)
      throws PublisherException {
    LOG.trace(">storeCertificate");
    final List<Integer> publisherIdsToUse = new ArrayList<>();
    for (final BasePublisher publisher : getPublishersToUse(false)) {
      final boolean willPublish =
          publisher.willPublishCertificate(
              certificateData.getStatus(),
              certificateData.getRevocationReason());
      if (willPublish) {
        publisherIdsToUse.add(publisher.getPublisherId());
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Will "
                + (willPublish ? "" : "NOT ")
                + "publish certificate "
                + certificateData.getSerialNumberHex()
                + " to publisher '"
                + publisher.getName()
                + "'");
      }
    }
    if (!publisherIdsToUse.isEmpty()) {
      try {
        getPublisherSession()
            .storeCertificate(
                authenticationToken,
                publisherIdsToUse,
                new CertificateDataWrapper(
                    null, certificateData, base64CertData),
                password,
                userDN,
                extendedinformation);
      } catch (AuthorizationDeniedException e) {
        throw new PublisherException(
            "Authorization was denied: " + e.getMessage());
      }
    }
    LOG.trace("<storeCertificate");
    return true;
  }

  @Override
  public boolean isFullEntityPublishingSupported() {
    return true;
  }

  @Override
  public boolean storeCRL(
      final AuthenticationToken admin,
      final byte[] incrl,
      final String cafp,
      final int number,
      final String userDN)
      throws PublisherException {
    final List<Integer> publisherIdsToUse = new ArrayList<>();
    LOG.trace(">storeCRL");
    for (final BasePublisher publisher : getPublishersToUse(false)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Will publish CRL "
                + number
                + " for CA "
                + cafp
                + " to publisher '"
                + publisher.getName()
                + "'");
      }
      publisherIdsToUse.add(publisher.getPublisherId());
    }
    if (publisherIdsToUse.isEmpty()) {
      LOG.info(
          "No publishers available in multi group publisher '"
              + getName()
              + "'. Can't publish CRL "
              + number
              + " for CA "
              + cafp);
      return false;
    }
    try {
      getPublisherSession()
          .storeCRL(admin, publisherIdsToUse, incrl, cafp, number, userDN);
    } catch (AuthorizationDeniedException e) {
      throw new PublisherException(
          "Authorization was denied: " + e.getMessage());
    }
    LOG.trace("<storeCRL");
    return true;
  }

  @Override
  public void testConnection() throws PublisherConnectionException {
    Exception publisherException = null;
    List<String> failedNames = new ArrayList<>();
    LOG.debug("Testing all publishers in multi group publisher.");
    for (final BasePublisher publisher : getPublishersToUse(true)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Testing publisher: " + publisher.getName());
      }
      try {
        publisher.testConnection();
      } catch (PublisherConnectionException | RuntimeException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Publisher '"
                  + publisher.getName()
                  + "' failed: "
                  + e.getMessage(),
              e);
        }
        failedNames.add(publisher.getName());
        if (publisherException == null) {
          publisherException = e;
        }
      }
    }
    LOG.debug("Done testing publishers in multi group publisher.");
    if (publisherException != null) {
      final String msg =
          "Publishers ["
              + StringUtils.join(failedNames, ", ")
              + "] failed. First failure: "
              + publisherException.getMessage();
      LOG.info(msg, publisherException);
      throw new PublisherConnectionException(msg, publisherException);
    }
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    final MultiGroupPublisher clone = new MultiGroupPublisher();
    final LinkedHashMap<Object, Object> clonedata = new LinkedHashMap<>();
    clonedata.putAll(data);
    final List<TreeSet<Integer>> publisherGroupsClone = new ArrayList<>();
    for (final TreeSet<Integer> publisherGroup : getPublisherGroups()) {
      publisherGroupsClone.add(new TreeSet<>(publisherGroup));
    }
    clonedata.put(PROPERTYKEY_PUBLISHERGROUPS, publisherGroupsClone);
    clone.loadData(clonedata);
    return clone;
  }

  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implemtation of UpgradableDataHashMap function upgrade. */
  @Override
  public void upgrade() {
    LOG.trace(">upgrade");
    if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
      // Does nothing currently
      data.put(VERSION, Float.valueOf(LATEST_VERSION));
    }
    LOG.trace("<upgrade");
  }

  @Override
  public void validateDataSource(final String dataSource)
      throws PublisherException {
    // Method not applicable for this publisher type!
  }
}
