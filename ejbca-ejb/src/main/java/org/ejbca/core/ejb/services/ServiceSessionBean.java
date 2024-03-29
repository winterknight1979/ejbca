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

package org.ejbca.core.ejb.services;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
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
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.util.ProfileIDUtil;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;

/**
 * Session bean that handles adding and editing services as displayed in EJBCA.
 * This bean manages the service configuration as stored in the database, and
 * executes services at timeouts triggered by the timeoutHandler.
 *
 * @version $Id: ServiceSessionBean.java 34133 2019-12-19 14:28:28Z anatom $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ServiceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceSessionBean
    implements ServiceSessionLocal, ServiceSessionRemote {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(ServiceSessionBean.class);

  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /**
   * Constant indicating the Id of the "service loader" service. Used in a
   * clustered environment to periodically load available services
   */
  private static final Integer SERVICELOADER_ID = 0;

  /** Timrout. */
  private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;

  /** Context. */
  @Resource private SessionContext sessionContext;
  /** Service. */
  private TimerService
      timerService; // When the sessionContext is injected, the timerService
                    // should be looked up.

  /** EJB. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** EJB. */
  @EJB private SecurityEventsLoggerSessionLocal auditSession;
  /** EJB. */
  @EJB private InternalSecurityEventsLoggerSessionLocal internalAuditSession;
  /** EJB. */
  @EJB private ServiceDataSessionLocal serviceDataSession;

  /** Session. */
  private ServiceSessionLocal serviceSession;

  // Additional dependencies from the services we executeServiceInTransaction
  /** EJB. */
  @EJB private ApprovalSessionLocal approvalSession;
  /** EJB. */
  @EJB private ApprovalProfileSessionLocal approvalProfileSession;
  /** EJB. */
  @EJB private EndEntityAuthenticationSessionLocal authenticationSession;
  /** EJB. */
  @EJB private CAAdminSessionLocal caAdminSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;
  /** EJB. */
  @EJB private CertificateProfileSessionLocal certificateProfileSession;
  /** EJB. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;
  /** EJB. */
  @EJB private CrlCreateSessionLocal crlCreateSession;
  /** EJB. */
  @EJB private CrlStoreSessionLocal crlStoreSession;
  /** EJB. */
  @EJB private EndEntityAccessSessionLocal endEntityAccessSession;
  /** EJB. */
  @EJB private EndEntityProfileSessionLocal endEntityProfileSession;
  /** EJB. */
  @EJB private HardTokenSessionLocal hardTokenSession;
  /** EJB. */
  @EJB private KeyRecoverySessionLocal keyRecoverySession;
  /** EJB. */
  @EJB private AdminPreferenceSessionLocal raAdminSession;
  /** EJB. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** EJB. */
  @EJB private SignSessionLocal signSession;
  /** EJB. */
  @EJB private EndEntityManagementSessionLocal endEntityManagementSession;
  /** EJB. */
  @EJB private PublisherQueueSessionLocal publisherQueueSession;
  /** EJB. */
  @EJB private PublisherSessionLocal publisherSession;
  /** EJB. */
  @EJB private CertificateRequestSessionLocal certificateRequestSession;
  /** EJB. */
  @EJB private WebAuthenticationProviderSessionLocal webAuthenticationSession;
  /** EJB. */
  @EJB private PublishingCrlSessionLocal publishingCrlSession;
  /** EJB. */
  @EJB private CryptoTokenManagementSessionLocal cryptoTokenSession;
  /** EJB. */
  @EJB private CmpMessageDispatcherSessionLocal cmpMsgDispatcherSession;
  /** EJB. */
  @EJB private ImportCrlSessionLocal importCrlSession;
  /** EJB. */
  @EJB private KeyStoreCreateSessionLocal keyStoreCreateSession;

  /** Constant. */
  private final int msPerS = 1000;

  /** Init. */
  @PostConstruct
  public void ejbCreate() {
    timerService = sessionContext.getTimerService();
    serviceSession =
        sessionContext.getBusinessObject(ServiceSessionLocal.class);
  }

  @Override
  public void addService(
      final AuthenticationToken admin,
      final String name,
      final ServiceConfiguration serviceConfiguration)
      throws ServiceExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addService(name: " + name + ")");
    }
    addService(admin, findFreeServiceId(), name, serviceConfiguration);
    LOG.trace("<addService()");
  }

  @Override
  public void addService(
      final AuthenticationToken admin,
      final int id,
      final String name,
      final ServiceConfiguration serviceConfiguration)
      throws ServiceExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addService(name: " + name + ", id: " + id + ")");
    }
    boolean success = addServiceInternal(admin, id, name, serviceConfiguration);
    if (success) {
      final String msg =
          INTRES.getLocalizedMessage("services.serviceadded", name);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.SERVICE_ADD,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.SERVICE,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      final String msg =
          INTRES.getLocalizedMessage("services.erroraddingservice", name);
      LOG.info(msg);
      throw new ServiceExistsException(msg);
    }
    LOG.trace("<addService()");
  }

  private boolean addServiceInternal(
      final AuthenticationToken admin,
      final int id,
      final String name,
      final ServiceConfiguration serviceConfiguration)
      throws ServiceExistsException {
    boolean success = false;
    if (isAuthorizedToEditService(admin)) {
      if (serviceDataSession.findByName(name) == null) {
        if (serviceDataSession.findById(Integer.valueOf(id)) == null) {
          serviceDataSession.addServiceData(id, name, serviceConfiguration);
          success = true;
        }
      }
    } else {
      final String msg =
          INTRES.getLocalizedMessage("services.notauthorizedtoadd", name);
      LOG.info(msg);
    }
    return success;
  }

  @Override
  public void cloneService(
      final AuthenticationToken admin,
      final String oldname,
      final String newname)
      throws ServiceExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">cloneService(name: " + oldname + ")");
    }
    ServiceConfiguration servicedata = null;
    ServiceData htp = serviceDataSession.findByName(oldname);
    if (htp == null) {
      String msg = "Error cloning service: No such service found.";
      LOG.error(msg);
      throw new EJBException(msg);
    }
    try {
      servicedata =
          (ServiceConfiguration) htp.getServiceConfiguration().clone();
      if (isAuthorizedToEditService(admin)) {
        addServiceInternal(admin, findFreeServiceId(), newname, servicedata);
        final String msg =
            INTRES.getLocalizedMessage(
                "services.servicecloned", newname, oldname);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.SERVICE_ADD,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.SERVICE,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            null,
            details);
      } else {
        final String msg =
            INTRES.getLocalizedMessage("services.notauthorizedtoedit", oldname);
        LOG.info(msg);
      }
    } catch (CloneNotSupportedException e) {
      LOG.error("Error cloning service: ", e);
      throw new EJBException(e);
    }
    LOG.trace("<cloneService()");
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public boolean removeService(
      final AuthenticationToken admin, final String name) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeService(name: " + name + ")");
    }
    boolean retval = false;
    try {
      ServiceData htp = serviceDataSession.findByName(name);
      if (htp == null) {
        throw new FinderException("Cannot find service " + name);
      }
      ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
      if (isAuthorizedToEditService(admin)) {
        IWorker worker =
            getWorker(
                serviceConfiguration,
                name,
                htp.getRunTimeStamp(),
                htp.getNextRunTimeStamp());
        if (worker != null) {
          serviceSession.cancelTimer(htp.getId());
        }
        serviceDataSession.removeServiceData(htp.getId());
        final String msg =
            INTRES.getLocalizedMessage("services.serviceremoved", name);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.SERVICE_REMOVE,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.SERVICE,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            null,
            details);
        retval = true;
      } else {
        final String msg =
            INTRES.getLocalizedMessage("services.notauthorizedtoedit", name);
        LOG.info(msg);
      }
    } catch (Exception e) {
      final String msg =
          INTRES.getLocalizedMessage("services.errorremovingservice", name);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      details.put("error", e.getMessage());
      auditSession.log(
          EjbcaEventTypes.SERVICE_REMOVE,
          EventStatus.FAILURE,
          EjbcaModuleTypes.SERVICE,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    }
    LOG.trace("<removeService)");
    return retval;
  }

  @Override
  public void renameService(
      final AuthenticationToken admin,
      final String oldname,
      final String newname)
      throws ServiceExistsException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">renameService(from " + oldname + " to " + newname + ")");
    }
    boolean success = false;
    if (serviceDataSession.findByName(newname) == null) {
      ServiceData htp = serviceDataSession.findByName(oldname);
      if (htp != null) {
        if (isAuthorizedToEditService(admin)) {
          htp.setName(newname);
          success = true;
        } else {
          final String msg =
              INTRES.getLocalizedMessage(
                  "services.notauthorizedtoedit", oldname);
          LOG.info(msg);
        }
      }
    }
    if (success) {
      final String msg =
          INTRES.getLocalizedMessage(
              "services.servicerenamed", oldname, newname);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.SERVICE_RENAME,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.SERVICE,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      final String msg =
          INTRES.getLocalizedMessage(
              "services.errorrenamingservice", oldname, newname);
      LOG.info(msg);
      throw new ServiceExistsException(msg);
    }
    LOG.trace("<renameService()");
  }

  @Override
  public Collection<Integer> getVisibleServiceIds() {
    Collection<Integer> allVisibleServiceIds = new ArrayList<Integer>();
    Collection<Integer> allServiceIds = getServiceIdToNameMap().keySet();
    for (int id : allServiceIds) {
      // Remove hidden services here..
      if (!getServiceConfiguration(id).isHidden()) {
        allVisibleServiceIds.add(Integer.valueOf(id));
      }
    }

    return allVisibleServiceIds;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public ServiceConfiguration getService(final String name) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getService: " + name);
    }
    ServiceConfiguration returnval = null;
    ServiceData serviceData = serviceDataSession.findByName(name);
    if (serviceData != null) {
      returnval = serviceData.getServiceConfiguration();
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getService: " + name);
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public int getServiceId(final String name) {
    int returnval = 0;
    ServiceData serviceData = serviceDataSession.findByName(name);
    if (serviceData != null) {
      returnval = serviceData.getId();
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public void activateServiceTimer(
      final AuthenticationToken admin, final String name) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">activateServiceTimer(name: " + name + ")");
    }
    ServiceData htp = serviceDataSession.findByName(name);
    if (htp != null) {
      ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
      if (isAuthorizedToEditService(admin)) {
        IWorker worker =
            getWorker(
                serviceConfiguration,
                name,
                htp.getRunTimeStamp(),
                htp.getNextRunTimeStamp());
        if (worker != null) {
          serviceSession.cancelTimer(htp.getId());
          if (serviceConfiguration.isActive()
              && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
            addTimer(worker.getNextInterval() * msPerS, htp.getId());
          }
        }
      } else {
        final String msg =
            INTRES.getLocalizedMessage("services.notauthorizedtoedit", name);
        LOG.info(msg);
      }
    } else {
      LOG.error("Can not find service: " + name);
    }
    LOG.trace("<activateServiceTimer()");
  }

  private int findFreeServiceId() {
    final ProfileIDUtil.DB db =
        new ProfileIDUtil.DB() {
          @Override
          public boolean isFree(final int i) {
            return ServiceSessionBean.this.serviceDataSession.findById(
                    Integer.valueOf(i))
                == null;
          }
        };
    return ProfileIDUtil.getNotUsedID(db);
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public String getServiceName(final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getServiceName(id: " + id + ")");
    }
    String returnval = null;
    ServiceData serviceData = serviceDataSession.findById(id);
    if (serviceData != null) {
      returnval = serviceData.getName();
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getServiceName()");
    }
    return returnval;
  }

  /**
   * Method implemented from the TimerObject and is the main method of this
   * session bean. It calls the work object for each object.
   *
   * @param timer timer whose expiration caused this notification.
   */
  @Override
  @Timeout
  // Glassfish 2.1.1:
  // "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute
  // of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
  // JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource
  // transactions.
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  public void timeoutHandler(final Timer timer) {
    final int defaultTO = 30;
    if (LOG.isTraceEnabled()) {
      LOG.trace(">ejbTimeout");
    }
    final long startOfTimeOut = System.currentTimeMillis();
    long serviceInterval = IInterval.DONT_EXECUTE;
    Integer timerInfo = (Integer) timer.getInfo();
    if (timerInfo.equals(SERVICELOADER_ID)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Running the internal Service loader.");
      }
      load();
    } else {
      String serviceName = null;
      try {
        serviceName = serviceDataSession.findNameById(timerInfo);
      } catch (
          Throwable
              t) { // NOPMD: we really need to catch everything to not risk
                   // hanging somewhere in limbo
        LOG.warn(
            "Exception finding service name: ",
            t); // if this throws, there is a failed database or similar
        // Unexpected error (probably database related). We need to reschedule
        // the service with a default interval.
        addTimer(defaultTO * msPerS, timerInfo);
      }
      if (serviceName == null) {
        final String msg =
            INTRES.getLocalizedMessage("services.servicenotfound", timerInfo);
        LOG.info(msg);
      } else {
        // Get interval of worker
        try {
          serviceInterval = serviceSession.getServiceInterval(timerInfo);
        } catch (
            Throwable
                t) { // NOPMD: we really need to catch everything to not risk
                     // hanging somewhere in limbo
          LOG.warn(
              "Exception getting service interval: ",
              t); // if this throws, there is a failed database or similar
          // Unexpected error (probably database related). We need to reschedule
          // the service with a default interval.
          addTimer(defaultTO * msPerS, timerInfo);
        }
        // Reschedule timer
        IWorker worker = null;
        if (serviceInterval != IInterval.DONT_EXECUTE) {
          Timer nextTrigger = addTimer(serviceInterval * msPerS, timerInfo);
          try {
            // Try to acquire lock / see if this node should run
            worker =
                serviceSession.getWorkerIfItShouldRun(
                    timerInfo, nextTrigger.getNextTimeout().getTime());
          } catch (
              Throwable
                  t) { // NOPMD: we really need to catch everything to not risk
                       // hanging somewhere in limbo
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Exception: ",
                  t); // Don't spam log with stacktraces in normal production
                      // cases
            }
          }
          if (worker != null) {
            try {
              serviceSession.executeServiceInNoTransaction(worker, serviceName);
            } catch (RuntimeException e) {
          /*
           * If the service worker fails with a RuntimeException we need to
           * swallow this here. If we allow it to propagate outside the
           * ejbTimeout method it is up to the application server config how it
           * should be retried, but we have already scheduled a new try
           * previously in this method. We still want to log this as an ERROR
           * since it is some kind of catastrophic failure..
           */
              LOG.error("Service worker execution failed.", e);
            }
          } else {
            if (LOG.isDebugEnabled()) {
              Object o = timerInfo;
              if (serviceName != null) {
                o = serviceName;
              }
              final String msg =
                  INTRES.getLocalizedMessage(
                      "services.servicerunonothernode", o);
              LOG.debug(msg);
            }
          }
          if (System.currentTimeMillis() - startOfTimeOut
              > serviceInterval * msPerS) {
            LOG.warn(
                "Service '"
                    + serviceName
                    + "' took longer than it's configured service interval ("
                    + serviceInterval
                    + "). This can trigger simultanious service execution on"
                    + " several nodes in a cluster. Increase interval or lower"
                    + " each invocations work load.");
          }
        }
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<ejbTimeout");
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
  @Override
  public IWorker getWorkerIfItShouldRun(
      final Integer serviceId, final long nextTimeout) {
    return getWorkerIfItShouldRun(serviceId, nextTimeout, false);
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
  @Override
  public IWorker getWorkerIfItShouldRun(
      final Integer serviceId,
      final long nextTimeout,
      final boolean testRunOnOtherNode) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">getWorkerIfItShouldRun: "
              + serviceId
              + ", "
              + nextTimeout
              + ", "
              + testRunOnOtherNode);
    }
    IWorker worker = null;
    ServiceData serviceData = serviceDataSession.findById(serviceId);
    ServiceConfiguration serviceConfiguration =
        serviceData.getServiceConfiguration();
    if (!serviceConfiguration.isActive()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Service " + serviceId + " is inactive.");
      }
      return null; // Don't return an inactive worker to run
    }
    String serviceName = serviceData.getName();
    final String hostname = getHostName();
    if (shouldRunOnThisNode(
        hostname, Arrays.asList(serviceConfiguration.getPinToNodes()))) {
      long oldRunTimeStamp = serviceData.getRunTimeStamp();
      long oldNextRunTimeStamp = serviceData.getNextRunTimeStamp();
      worker =
          getWorker(
              serviceConfiguration,
              serviceName,
              oldRunTimeStamp,
              oldNextRunTimeStamp);
      if (worker.getNextInterval() == IInterval.DONT_EXECUTE) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Service "
                  + serviceName
                  + " has interval IInterval.DONT_EXECUTE.");
        }
        return null; // Don't return an inactive worker to run
      }
      // nextRunDateCheck will typically be the same (or just a millisecond
      // earlier) as now here
      final Date runDateCheck = new Date(oldNextRunTimeStamp);
      final Date currentDate = new Date();
      if (LOG.isDebugEnabled()) {
        final Date nextRunDate = new Date(nextTimeout);
        LOG.debug("nextRunDate is:  " + nextRunDate);
        LOG.debug("runDateCheck is: " + runDateCheck);
        LOG.debug("currentDate is:  " + currentDate);
      }
      // Check if this is a service that should run on all nodes, i.e. ignore if
      // it is already running on another node in a cluster
      // This is used for services that do (lighter) work local to each node,
      // such as HSM keepalive service
      if (!serviceConfiguration.isRunOnAllNodes()) {
        /*
         * Check if the current date is after when the service should run. If a
         * service on another cluster node has updated this timestamp already,
         * then it will return false and this service will not run. This is a
         * semaphore (not the best one admitted) so that services in a cluster
         * only runs on one node and don't compete with each other. If a worker
         * on one node for instance runs for a very long time, there is a chance
         * that another worker on another node will break this semaphore and run
         * as well.
         */
        if (currentDate.after(runDateCheck)) {
          /*
           * We only update the nextRunTimeStamp if the service
           * is allowed to run on this node.
           *
           * However, we need to make sure that no other node has
           *  already acquired the semaphore
           * if our current database allows non-repeatable reads.
           */
          final boolean updateTimestamps =
              serviceDataSession.updateTimestamps(
                  serviceId,
                  oldRunTimeStamp,
                  oldNextRunTimeStamp,
                  runDateCheck.getTime(),
                  nextTimeout);
          if (!updateTimestamps || testRunOnOtherNode) {
            if (testRunOnOtherNode && updateTimestamps) {
              LOG.info(
                  "testRunOnOtherNode == true, we are returning null even"
                      + " though another node had not updated the database."
                      + " This node will not run the service "
                      + serviceName
                      + ".");
            } else {
              LOG.debug(
                  "Another node had already updated the database at this"
                      + " point. This node will not run the service "
                      + serviceName
                      + ".");
            }
            worker =
                null; // Failed to update the database.
          } else {
            if (LOG.isTraceEnabled()) {
              LOG.trace(
                  "Timestamps updated, service "
                      + serviceName
                      + " will run: "
                      + currentDate
                      + ", "
                      + runDateCheck);
            }
          }
        } else {
          if (LOG.isTraceEnabled()) {
            LOG.trace(
                "!currentDate.after(runDateCheck), service "
                    + serviceName
                    + " will not run: "
                    + currentDate
                    + ", "
                    + runDateCheck);
          }
          worker =
              null; // Don't return a worker, since this node should not run
        }
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Service "
                  + serviceName
                  + " is set to run on all nodes and will run on this node: \""
                  + hostname
                  + "\", updating timeStamps");
        }
        // Always update timestamp so we have a record of running, and
        // nextTimeout is set for service reload
        serviceDataSession.updateTimestamps(
            serviceId,
            oldRunTimeStamp,
            oldNextRunTimeStamp,
            runDateCheck.getTime(),
            nextTimeout);
      }
    } else {
      worker = null;
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Service "
                + serviceName
                + " will not run on this node: \""
                + hostname
                + "\", Pinned to: "
                + Arrays.toString(serviceConfiguration.getPinToNodes()));
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<getWorkerIfItShouldRun: "
              + serviceName
              + ", ret: "
              + (worker != null ? worker.getClass().getName() : "null"));
    }
    return worker;
  }

  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public void executeServiceInNoTransaction(
      final IWorker worker, final String serviceName) {
    try {
      // Awkward way of letting POJOs get interfaces, but shows dependencies on
      // the EJB level for all used classes. Injection wont work, since
      // we have circular dependencies!
      Map<Class<?>, Object> ejbs = new HashMap<Class<?>, Object>();
      ejbs.put(ApprovalSessionLocal.class, approvalSession);
      ejbs.put(ApprovalProfileSessionLocal.class, approvalProfileSession);
      ejbs.put(
          EndEntityAuthenticationSessionLocal.class, authenticationSession);
      ejbs.put(AuthorizationSessionLocal.class, authorizationSession);
      ejbs.put(CAAdminSessionLocal.class, caAdminSession);
      ejbs.put(CaSessionLocal.class, caSession);
      ejbs.put(CertificateProfileSessionLocal.class, certificateProfileSession);
      ejbs.put(CertificateStoreSessionLocal.class, certificateStoreSession);
      ejbs.put(CrlCreateSessionLocal.class, crlCreateSession);
      ejbs.put(CrlStoreSessionLocal.class, crlStoreSession);
      ejbs.put(EndEntityProfileSessionLocal.class, endEntityProfileSession);
      ejbs.put(HardTokenSessionLocal.class, hardTokenSession);
      ejbs.put(SecurityEventsLoggerSessionLocal.class, auditSession);
      ejbs.put(
          InternalSecurityEventsLoggerSessionLocal.class, internalAuditSession);
      ejbs.put(KeyRecoverySessionLocal.class, keyRecoverySession);
      ejbs.put(AdminPreferenceSessionLocal.class, raAdminSession);
      ejbs.put(
          GlobalConfigurationSessionLocal.class, globalConfigurationSession);
      ejbs.put(SignSessionLocal.class, signSession);
      ejbs.put(
          EndEntityManagementSessionLocal.class, endEntityManagementSession);
      ejbs.put(PublisherQueueSessionLocal.class, publisherQueueSession);
      ejbs.put(PublisherSessionLocal.class, publisherSession);
      ejbs.put(CertificateRequestSessionLocal.class, certificateRequestSession);
      ejbs.put(EndEntityAccessSessionLocal.class, endEntityAccessSession);
      ejbs.put(
          WebAuthenticationProviderSessionLocal.class,
          webAuthenticationSession);
      ejbs.put(PublishingCrlSessionLocal.class, publishingCrlSession);
      ejbs.put(CryptoTokenManagementSessionLocal.class, cryptoTokenSession);
      ejbs.put(CmpMessageDispatcherSessionLocal.class, cmpMsgDispatcherSession);
      ejbs.put(ImportCrlSessionLocal.class, importCrlSession);
      ejbs.put(KeyStoreCreateSessionLocal.class, keyStoreCreateSession);
      worker.work(ejbs);
      final String msg =
          INTRES.getLocalizedMessage("services.serviceexecuted", serviceName);
      LOG.info(msg);
    } catch (ServiceExecutionFailedException e) {
      final String msg =
          INTRES.getLocalizedMessage(
              "services.serviceexecutionfailed", serviceName);
      LOG.info(msg, e);
    }
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public void changeService(
      final AuthenticationToken admin,
      final String name,
      final ServiceConfiguration serviceConfiguration,
      final boolean noLogging) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">changeService(name: " + name + ")");
    }
    if (isAuthorizedToEditService(admin)) {
      ServiceData oldservice = serviceDataSession.findByName(name);
      if (oldservice != null) {
        final Map<Object, Object> diff =
            oldservice.getServiceConfiguration().diff(serviceConfiguration);
        if (serviceDataSession.updateServiceConfiguration(
            name, serviceConfiguration)) {
          final String msg =
              INTRES.getLocalizedMessage("services.serviceedited", name);
          if (noLogging) {
            LOG.info(msg);
          } else {
            final Map<String, Object> details =
                new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
              details.put(
                  entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(
                EjbcaEventTypes.SERVICE_EDIT,
                EventStatus.SUCCESS,
                EjbcaModuleTypes.SERVICE,
                EjbcaServiceTypes.EJBCA,
                admin.toString(),
                null,
                null,
                null,
                details);
          }
        } else {
          String msg =
              INTRES.getLocalizedMessage("services.serviceedited", name);
          if (noLogging) {
            LOG.error(msg);
          } else {
            final Map<String, Object> details =
                new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(
                EjbcaEventTypes.SERVICE_EDIT,
                EventStatus.FAILURE,
                EjbcaModuleTypes.SERVICE,
                EjbcaServiceTypes.EJBCA,
                admin.toString(),
                null,
                null,
                null,
                details);
          }
        }
      } else {
        LOG.error("Can not find service to change: " + name);
      }
    } else {
      String msg =
          INTRES.getLocalizedMessage("services.notauthorizedtoedit", name);
      LOG.info(msg);
    }
    LOG.trace("<changeService()");
  }

  // We don't want the appserver to persist/update the timer in the same
  // transaction if they are stored in different non XA DataSources
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public void load() {
    // Get all services
    Collection<Timer> currentTimers = timerService.getTimers();
    Iterator<Timer> iter = currentTimers.iterator();
    HashSet<Serializable> existingTimers = new HashSet<Serializable>();
    while (iter.hasNext()) {
      Timer timer = iter.next();
      try {
        Serializable info = timer.getInfo();
        existingTimers.add(info);
      } catch (
          Throwable
              e) { // NOPMD: we really need to catch everything to not risk
                   // hanging somewhere in limbo
        // EJB 2.1 only?: We need this try because weblogic seems to ... suck
        // ...
        LOG.debug("Error invoking timer.getInfo(): ", e);
      }
    }

    // Get new services and add timeouts
    Map<Integer, Long> newTimeouts =
        serviceSession.getNewServiceTimeouts(existingTimers);
    for (Integer id : newTimeouts.keySet()) {
      addTimer(newTimeouts.get(id), id);
    }

    if (!existingTimers.contains(SERVICELOADER_ID)) {
      // load the service timer
      addTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
    }
  }

  @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
  @Override
  public Map<Integer, Long> getNewServiceTimeouts(
      final HashSet<Serializable> existingTimers) {
    Map<Integer, Long> ret = new HashMap<Integer, Long>();
    HashMap<Integer, String> idToNameMap = getServiceIdToNameMap();
    Collection<Integer> allServices = idToNameMap.keySet();
    Iterator<Integer> iter2 = allServices.iterator();
    while (iter2.hasNext()) {
      Integer id = iter2.next();
      ServiceData htp = serviceDataSession.findById(id);
      if (htp != null) {
        if (!existingTimers.contains(id)) {
          ServiceConfiguration serviceConfiguration =
              htp.getServiceConfiguration();
          IWorker worker =
              getWorker(
                  serviceConfiguration,
                  idToNameMap.get(id),
                  htp.getRunTimeStamp(),
                  htp.getNextRunTimeStamp());
          if (worker != null
              && serviceConfiguration.isActive()
              && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
            ret.put(id, Long.valueOf((worker.getNextInterval()) * msPerS));
          }
        }
      } else {
        // Service does not exist, strange, but no panic.
        LOG.debug("Can not find service with id " + id);
      }
    }
    return ret;
  }

  // We don't want the appserver to persist/update the timer in the same
  // transaction if they are stored in different non XA DataSources
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public void unload() {
    LOG.debug("Unloading all timers.");
    // Get all services
    for (final Timer timer : timerService.getTimers()) {
      try {
        timer.cancel();
      } catch (Exception e) {
        /*
         * EJB 2.1 only?: We need to catch this because Weblogic 10
         * throws an exception if we have not scheduled this timer, so
         * we don't have anything to cancel. Only weblogic though...
         */
        LOG.info("Caught exception canceling timer: " + e.getMessage());
      }
    }
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
    if (LOG.isDebugEnabled()) {
      LOG.debug("addTimer: " + id);
    }
    return timerService.createSingleActionTimer(
        interval, new TimerConfig(id, false));
  }

  /**
   * Cancels all existing timeouts for this id.
   *
   * @param id the id of the timer
   */
  // We don't want the appserver to persist/update the timer in the same
  // transaction if they are stored in different non XA DataSources. This method
  // should not be run from within a transaction.
  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public void cancelTimer(final Integer id) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("cancelTimer: " + id);
    }
    for (final Timer next : timerService.getTimers()) {
      try {
        if (id.equals(next.getInfo())) {
          next.cancel();
          break;
        }
      } catch (Exception e) {
        /*
         * EJB 2.1 only?: We need to catch this because Weblogic 10
         * throws an exception if we have not scheduled this timer, so
         * we don't have anything to cancel. Only weblogic though...
         */
        LOG.error("Caught exception canceling timer: " + e.getMessage(), e);
      }
    }
  }

  /** Use an internal admin, allow all, to initialize the service, the service
  must be allowed to work on everything. */
  private final AuthenticationToken intAdmin =
      new AlwaysAllowLocalAuthenticationToken(
          new UsernamePrincipal("ServiceSession"));
  /**
   * Method that creates a worker from the service configuration.
   *
   * @param serviceConfiguration Config
   * @param serviceName Name
   * @param runTimeStamp the time this service runs
   * @param nextRunTimeStamp the time this service will run next time
   * @return a worker object or null if the worker is misconfigured.
   */
  private IWorker getWorker(
      final ServiceConfiguration serviceConfiguration,
      final String serviceName,
      final long runTimeStamp,
      final long nextRunTimeStamp) {
    IWorker worker = null;
    try {
      String clazz = serviceConfiguration.getWorkerClassPath();
      if (StringUtils.isNotEmpty(clazz)) {
        worker =
            (IWorker)
                Thread.currentThread()
                    .getContextClassLoader()
                    .loadClass(clazz)
                    .getConstructor()
                    .newInstance();
        worker.init(
            intAdmin,
            serviceConfiguration,
            serviceName,
            runTimeStamp,
            nextRunTimeStamp);
      } else {
        LOG.info("Worker has empty classpath for service " + serviceName);
      }
    } catch (Exception e) {
      // Only display a real error if it is a worker that we are actually
      // using
      if (serviceConfiguration.isActive()) {
        LOG.error("Worker is misconfigured, check the classpath", e);
      } else {
        LOG.info(
            "Worker is misconfigured, check the classpath: " + e.getMessage());
      }
    }
    return worker;
  }

  @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
  @Override
  public long getServiceInterval(final Integer serviceId) {
    long ret = IInterval.DONT_EXECUTE;
    ServiceData htp = serviceDataSession.findById(serviceId);
    if (htp != null) {
      ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
      if (serviceConfiguration.isActive()) {
        IWorker worker =
            getWorker(
                serviceConfiguration,
                "temp",
                0,
                0); // A bit dirty, but it works..
        if (worker != null) {
          ret = worker.getNextInterval();
        }
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Service " + serviceId + " is inactive.");
        }
      }
    }
    return ret;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public ServiceConfiguration getServiceConfiguration(final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getServiceConfiguration: " + id);
    }
    ServiceConfiguration returnval = null;
    try {
      ServiceData serviceData =
          serviceDataSession.findById(Integer.valueOf(id));
      if (serviceData != null) {
        returnval = serviceData.getServiceConfiguration();
      } else {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Returnval is null for service id: " + id);
        }
      }
    } catch (Exception e) {
      // return null if we cant find it, if it is not due to underlying
      // database error
      LOG.debug(
          "Got an Exception for service with id " + id + ": " + e.getMessage());
      /*
       * If we don't re-throw here it will be treated as the service id
       * does not exist and the service will not be rescheduled to run.
       */
      throw new EJBException(e);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getServiceConfiguration: " + id);
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public HashMap<Integer, String> getServiceIdToNameMap() {
    HashMap<Integer, String> returnval = new HashMap<Integer, String>();
    Collection<ServiceData> result = serviceDataSession.findAll();
    for (ServiceData next : result) {
      returnval.put(next.getId(), next.getName());
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<String> getServicesUsingCertificateProfile(
      final Integer certificateProfileId) {
    List<String> result = new ArrayList<String>();
    // Since the service types are embedded in the data objects there is no more
    // elegant way to to this.
    List<ServiceData> allServices = serviceDataSession.findAll();
    for (ServiceData service : allServices) {
      String certificateProfiles =
          service
              .getServiceConfiguration()
              .getWorkerProperties()
              .getProperty(BaseWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK);
      if (certificateProfiles != null && !certificateProfiles.equals("")) {
        for (String certificateProfile : certificateProfiles.split(";")) {
          if (certificateProfile.equals(certificateProfileId.toString())) {
            result.add(service.getName());
            break;
          }
        }
      }
    }
    return result;
  }

  /**
   * Method to check if an admin is authorized to edit a service. Allow access
   * for /services/edit
   *
   * @param admin Admin
   * @return true if the administrator is authorized
   */
  private boolean isAuthorizedToEditService(final AuthenticationToken admin) {
    return authorizationSession.isAuthorizedNoLogging(
        admin, AccessRulesConstants.SERVICES_EDIT);
  }

  /**
   * Return true if the service should run on the node given the list of nodes
   * it is pinned to. An empty list means that the service is not pinned to any
   * particular node and should run on all.
   *
   * @param hostname Host
   * @param nodes list of nodes the service is pinned to
   * @return true if the service should run on this node
   */
  private boolean shouldRunOnThisNode(
      final String hostname, final List<String> nodes) {
    final boolean result;
    if (nodes == null || nodes.isEmpty()) {
      result = true;
    } else if (hostname == null) {
      result = false;
    } else {
      result = nodes.contains(hostname);
    }
    return result;
  }

  /** @return The host's name or null if it could not be determined. */
  private String getHostName() {
    String hostname = null;
    try {
      InetAddress addr = InetAddress.getLocalHost();
      // Get hostname
      hostname = addr.getHostName();
    } catch (UnknownHostException e) {
      LOG.error("Hostname could not be determined", e);
    }
    return hostname;
  }
}
