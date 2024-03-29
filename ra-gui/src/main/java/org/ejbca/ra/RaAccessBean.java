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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.access.AuthorizationCacheReload;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.cache.RemoteAccessSetCacheHelper;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.util.ConcurrentCache;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Managed bean with isAuthorized method.
 *
 * @version $Id: RaAccessBean.java 28562 2018-03-27 14:07:49Z undulf $ TODO: Use
 *     CDI beans
 */
@SuppressWarnings("deprecation")
@ManagedBean
@SessionScoped
public class RaAccessBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RaAccessBean.class);

  /** Param. */
  private static final long CACHE_READ_TIMEOUT = 2000L; // milliseconds

  /** Param. */
  @EJB private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
  /** Param. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** Param. */
  @EJB private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

  /** Param. */
  @ManagedProperty(value = "#{raAuthenticationBean}")
  private RaAuthenticationBean raAuthenticationBean;


  /**
   * @param araAuthenticationBean bean
   */
  public void setRaAuthenticationBean(
      final RaAuthenticationBean araAuthenticationBean) {
    this.raAuthenticationBean = araAuthenticationBean;
  }

  /** Param. */
  private static AtomicBoolean reloadEventRegistered = new AtomicBoolean(false);

  private boolean isAuthorized(final String... resources) {
    final AuthenticationToken authenticationToken =
        raAuthenticationBean.getAuthenticationToken();
    if (raMasterApiProxyBean.getApiVersion() >= 1) {
      return raMasterApiProxyBean.isAuthorizedNoLogging(
          authenticationToken, resources);
    } else {
      return isAuthorizedViaAccessSet(authenticationToken, resources);
    }
  }

  /**
   * Check authorization using AccessSet which do not support deny rules.
   *
   * @param authenticationToken Token
   * @param resources Resources
   * @return bool
   * @deprecated since EJBCA 6.8.0
   */
  @Deprecated
  private boolean isAuthorizedViaAccessSet(
      final AuthenticationToken authenticationToken,
      final String... resources) {
    ensureCacheReloadEventRegistered();
    AccessSet myAccess;
    final ConcurrentCache<AuthenticationToken, AccessSet> cache =
        RemoteAccessSetCacheHelper.getCache();

    // Try to read from cache
    final ConcurrentCache<AuthenticationToken, AccessSet>.Entry entry =
        cache.openCacheEntry(authenticationToken, CACHE_READ_TIMEOUT);
    if (entry == null) {
      // Other thread could not fetch the AccessSet on time
      throw new IllegalStateException("Timed out waiting for access rules");
    }
    try {
      if (entry.isInCache()) {
        myAccess = entry.getValue();
      } else {
        try {
          myAccess = raMasterApiProxyBean.getUserAccessSet(authenticationToken);
        } catch (AuthenticationFailedException e) {
          LOG.info(
              "Failed to match authentication token '"
                  + authenticationToken
                  + "' to a role.");
          myAccess = new AccessSet();
        }
        entry.putValue(myAccess);
      }
    } finally {
      entry.close();
    }
    return myAccess.isAuthorized(resources);
  }

  @Deprecated
  private void ensureCacheReloadEventRegistered() {
    if (reloadEventRegistered.compareAndSet(false, true)) {
      accessTreeUpdateSession.addReloadEvent(
          new AuthorizationCacheReloadListener() {
            private int lastUpdate = -1;

            @Override
            public void onReload(final AuthorizationCacheReload event) {
              if (event.getAccessTreeUpdateNumber() > lastUpdate) {
                lastUpdate = event.getAccessTreeUpdateNumber();
                RemoteAccessSetCacheHelper.forceEmptyCache();
              }
            }

            @Override
            public String getListenerName() {
              return RemoteAccessSetCacheHelper.class.getName();
            }
          });
    }
  }

  // Methods for checking authorization to various parts of EJBCA can be defined
  // below

  /**
   * Example method.
   *
   * @return bool
   */
  @Deprecated
  public boolean isAuthorizedToRootTEST() {
    return isAuthorized(StandardRules.ROLE_ROOT.resource());
  }

  /**
   * correspond to menu items in menu.xhtml This method shows and hides the
   * whole enrollment menu.
   *
   * @return bool
   */
  public boolean isAuthorizedToEnroll() {
    return isAuthorizedToEnrollMakeRequest()
        || isAuthorizedToEnrollWithRequestId();
  }

  /**
   * correspond to menu items in menu.xhtml This method shows and hides the make
   * request sub menu item.
   *
   * @return bool
   */
  public boolean isAuthorizedToEnrollMakeRequest() {
    /*
     * Only check if this admin has been configured to create end entities
     * to display the meny.
     * In order to actually make a request, the admin has to have access to
     *  AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId
     *  + AccessRulesConstants.CREATE_END_ENTITY
     * and the CAs available via this profile.
     */
    return isAuthorized(AccessRulesConstants.REGULAR_CREATEENDENTITY);
  }

  /**
   * correspond to menu items in menu.xhtml This method shows and hides the use
   * request id sub menu item.
   *
   * @return bool
   */
  public boolean isAuthorizedToEnrollWithRequestId() {
    // There are no access rules available for "finalizing" requests, i.e.
    // retrieving the certificate for your request
    // For starters we will assume that the same person who made the request is
    // finalizing it with request ID, therefore
    // The same access rules aply as when making a request.
    // This is a safe default until we can add access rules to allow "public"
    // users to enroll
    return isAuthorizedToEnrollMakeRequest();
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToCas() {
    final boolean auth = isAuthorized(StandardRules.CAVIEW.resource());
    if (!auth && LOG.isDebugEnabled()) {
      LOG.debug(
          ">isAuthorizedToCas: Not authorized to "
              + StandardRules.CAVIEW.resource());
    }
    return auth;
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToManageRequests() {
    final boolean auth =
        isAuthorized(AccessRulesConstants.REGULAR_APPROVEENDENTITY)
            || isAuthorized(AccessRulesConstants.REGULAR_APPROVECAACTION)
            || isAuthorized(AccessRulesConstants.REGULAR_VIEWAPPROVALS)
            || isAuthorized(AuditLogRules.VIEW.resource());
    if (!auth && LOG.isDebugEnabled()) {
      LOG.debug(
          ">isAuthorizedToManageRequests: Not authorized to "
              + AccessRulesConstants.REGULAR_APPROVEENDENTITY
              + ", "
              + AccessRulesConstants.REGULAR_APPROVECAACTION
              + ", "
              + AccessRulesConstants.REGULAR_VIEWAPPROVALS
              + " or "
              + AuditLogRules.VIEW.resource());
    }
    return auth;
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToApproveEndEntityRequests() {
    final boolean auth =
        isAuthorized(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
    if (!auth && LOG.isDebugEnabled()) {
      LOG.debug(
          ">isAuthorizedToApproveEndEntityRequests: Not authorized to "
              + AccessRulesConstants.REGULAR_APPROVEENDENTITY);
    }
    return auth;
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToApproveCARequests() {
    final boolean auth =
        isAuthorized(AccessRulesConstants.REGULAR_APPROVECAACTION);
    if (!auth && LOG.isDebugEnabled()) {
      LOG.debug(
          ">isAuthorizedToApproveCARequests: Not authorized to "
              + AccessRulesConstants.REGULAR_APPROVECAACTION);
    }
    return auth;
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToEditEndEntities() {
    return isAuthorized(AccessRulesConstants.REGULAR_EDITENDENTITY);
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToSearch() {
    return isAuthorizedToSearchCerts() || isAuthorizedToSearchEndEntities();
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToSearchCerts() {
    return isAuthorized(AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToSearchEndEntities() {
    return isAuthorized(AccessRulesConstants.REGULAR_VIEWENDENTITY);
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToRoles() {
    return isAuthorizedToRoleRules() || isAuthorizedToRoleMembers();
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToEditRoleRules() {
    return isAuthorized(StandardRules.EDITROLES.resource());
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToRoleRules() {
    return isAuthorized(StandardRules.VIEWROLES.resource());
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToRoleMembers() {
    return isAuthorized(StandardRules.VIEWROLES.resource());
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToEditRoleMembers() {
    return isAuthorized(StandardRules.EDITROLES.resource());
  }

  /**
   * @return bool
   */
  public boolean isAuthorizedToRevokeCertificates() {
    return isAuthorized(AccessRulesConstants.REGULAR_REVOKEENDENTITY);
  }

  /**
   * Determine if the RA master API is functional. Note that this method will
   * return true if there is a signing CA available locally on this RA.
   *
   * @return true if there is at least one CA serving this RA
   */
  public boolean isBackendAvailable() {
    final boolean isBackendAvailable =
        raMasterApiProxyBean.isBackendAvailable();
    if (!isBackendAvailable) {
      LOG.warn(
          "Unable to serve RA requests since there is no connection to the"
              + " upstream CA or lack of authorization of this RA node.");
    }
    return isBackendAvailable;
  }
}
