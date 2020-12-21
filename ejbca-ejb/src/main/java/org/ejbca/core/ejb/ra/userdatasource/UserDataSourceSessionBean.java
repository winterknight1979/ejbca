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

package org.ejbca.core.ejb.ra.userdatasource;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.ProfileID;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;

/**
 * Stores data used by web server clients.
 *
 * @version $Id: UserDataSourceSessionBean.java 34163 2020-01-02 15:00:17Z
 *     samuellb $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "UserDataSourceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class UserDataSourceSessionBean
    implements UserDataSourceSessionLocal, UserDataSourceSessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(UserDataSourceSessionBean.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();

  /** EM. */
  @PersistenceContext(unitName = "ejbca")
  private EntityManager entityManager;

  /** EJB. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** EJB. */
  @EJB private CaSessionLocal caSession;
  /** EJB. */
  @EJB private SecurityEventsLoggerSessionLocal auditSession;

  @Override
  public Collection<UserDataSourceVO> fetch(
      final AuthenticationToken admin,
      final Collection<Integer> userdatasourceids,
      final String searchstring)
      throws AuthorizationDeniedException, UserDataSourceException {
    Iterator<Integer> iter = userdatasourceids.iterator();
    ArrayList<UserDataSourceVO> result = new ArrayList<UserDataSourceVO>();
    while (iter.hasNext()) {
      Integer id = iter.next();
      UserDataSourceData pdl = UserDataSourceData.findById(entityManager, id);
      if (pdl != null) {
        BaseUserDataSource userdatasource = getUserDataSource(pdl);
        if (isAuthorizedToUserDataSource(
            admin, id.intValue(), userdatasource, false)) {
          try {
            result.addAll(
                getUserDataSource(pdl)
                    .fetchUserDataSourceVOs(admin, searchstring));
            String msg =
                INTRES.getLocalizedMessage(
                    "userdatasource.fetcheduserdatasource", pdl.getName());
            final Map<String, Object> details =
                new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(
                EjbcaEventTypes.RA_USERDATASOURCEFETCHDATA,
                EventStatus.SUCCESS,
                EjbcaModuleTypes.RA,
                EjbcaServiceTypes.EJBCA,
                admin.toString(),
                null,
                null,
                null,
                details);
          } catch (UserDataSourceException pe) {
            String msg =
                INTRES.getLocalizedMessage(
                    "userdatasource.errorfetchuserdatasource", pdl.getName());
            LOG.info(msg, pe);
            throw pe;
          }
        } else {
          String msg =
              INTRES.getLocalizedMessage(
                  "userdatasource.errornotauth", pdl.getName());
          LOG.info(msg);
        }
      } else {
        String msg =
            INTRES.getLocalizedMessage(
                "userdatasource.erroruserdatasourceexist", id);
        LOG.info(msg);
        throw new UserDataSourceException(msg);
      }
    }
    return result;
  }

  @Override
  public boolean removeUserData(
      final AuthenticationToken admin,
      final Collection<Integer> userdatasourceids,
      final String searchstring,
      final boolean removeMultipleMatch)
      throws AuthorizationDeniedException, MultipleMatchException,
          UserDataSourceException {
    boolean retval = false;
    Iterator<Integer> iter = userdatasourceids.iterator();
    while (iter.hasNext()) {
      Integer id = iter.next();
      UserDataSourceData pdl = UserDataSourceData.findById(entityManager, id);
      if (pdl != null) {
        BaseUserDataSource userdatasource = getUserDataSource(pdl);
        if (isAuthorizedToUserDataSource(
            admin, id.intValue(), userdatasource, true)) {
          try {
            retval =
                retval
                    || getUserDataSource(pdl)
                        .removeUserData(
                            admin, searchstring, removeMultipleMatch);
            String msg =
                INTRES.getLocalizedMessage(
                    "userdatasource.removeduserdata", pdl.getName());
            final Map<String, Object> details =
                new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(
                EjbcaEventTypes.RA_USERDATASOURCEREMOVEDATA,
                EventStatus.SUCCESS,
                EjbcaModuleTypes.RA,
                EjbcaServiceTypes.EJBCA,
                admin.toString(),
                null,
                null,
                null,
                details);
          } catch (UserDataSourceException pe) {
            String msg =
                INTRES.getLocalizedMessage(
                    "userdatasource.errorremovinguserdatasource",
                    pdl.getName());
            LOG.info(msg);
            throw pe;
          }
        } else {
          String msg =
              INTRES.getLocalizedMessage(
                  "userdatasource.errornotauth", pdl.getName());
          LOG.info(msg);
        }
      } else {
        String msg =
            INTRES.getLocalizedMessage(
                "userdatasource.erroruserdatasourceexist", id);
        LOG.info(msg);
        throw new UserDataSourceException(msg);
      }
    }
    return retval;
  }

  @Override
  public void testConnection(
      final AuthenticationToken admin, final int userdatasourceid)
      throws UserDataSourceConnectionException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">testConnection(id: " + userdatasourceid + ")");
    }
    UserDataSourceData pdl =
        UserDataSourceData.findById(entityManager, userdatasourceid);
    if (pdl != null) {
      BaseUserDataSource userdatasource = getUserDataSource(pdl);
      authorizedToEditUserDataSource(admin, pdl.getName(), userdatasource);
      try {
        userdatasource.testConnection(admin);
        String msg =
            INTRES.getLocalizedMessage(
                "userdatasource.testedcon", pdl.getName());
        LOG.info(msg);
      } catch (UserDataSourceConnectionException pe) {
        String msg =
            INTRES.getLocalizedMessage(
                "userdatasource.errortestcon", pdl.getName());
        LOG.info(msg);
        throw pe;
      }
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "userdatasource.erroruserdatasourceexist",
              Integer.valueOf(userdatasourceid));
      LOG.info(msg);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<testConnection(id: " + userdatasourceid + ")");
    }
  }

  @Override
  public void addUserDataSource(
      final AuthenticationToken admin,
      final String name,
      final BaseUserDataSource userdatasource)
      throws UserDataSourceExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addUserDataSource(name: " + name + ")");
    }
    addUserDataSource(admin, findFreeUserDataSourceId(), name, userdatasource);
    LOG.trace("<addUserDataSource()");
  }

  @Override
  public void addUserDataSource(
      final AuthenticationToken admin,
      final int id,
      final String name,
      final BaseUserDataSource userdatasource)
      throws UserDataSourceExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">addUserDataSource(name: " + name + ", id: " + id + ")");
    }
    try {
      addUserDataSourceInternal(admin, id, name, userdatasource);
      String msg =
          INTRES.getLocalizedMessage("userdatasource.addedsource", name);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.RA_USERDATASOURCEADD,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.RA,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } catch (UnsupportedEncodingException e) {
      LOG.info(
          "UnsupportedEncodingException adding user data source "
              + name
              + ", "
              + id
              + ": ",
          e);
      throw new EJBException(e);
    }
    LOG.trace("<addUserDataSource()");
  }

  private void addUserDataSourceInternal(
      final AuthenticationToken admin,
      final int id,
      final String name,
      final BaseUserDataSource userdatasource)
      throws AuthorizationDeniedException, UserDataSourceExistsException,
          UnsupportedEncodingException {
    authorizedToEditUserDataSource(admin, name, userdatasource);
    if (UserDataSourceData.findByName(entityManager, name) == null) {
      if (UserDataSourceData.findById(entityManager, id) == null) {
        entityManager.persist(
            new UserDataSourceData(Integer.valueOf(id), name, userdatasource));
      } else {
        String msg =
            INTRES.getLocalizedMessage("userdatasource.erroraddsource", id);
        LOG.info(msg);
        throw new UserDataSourceExistsException();
      }
    } else {
      String msg =
          INTRES.getLocalizedMessage("userdatasource.erroraddsource", name);
      LOG.info(msg);
      throw new UserDataSourceExistsException();
    }
  }

  @Override
  public void changeUserDataSource(
      final AuthenticationToken admin,
      final String name,
      final BaseUserDataSource userdatasource)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">changeUserDataSource(name: " + name + ")");
    }
    authorizedToEditUserDataSource(admin, name, userdatasource);
    UserDataSourceData htp = UserDataSourceData.findByName(entityManager, name);
    if (htp != null) {
      final BaseUserDataSource oldsource = getUserDataSource(htp);
      final Map<Object, Object> diff = oldsource.diff(userdatasource);

      htp.setUserDataSource(userdatasource);

      final String msg =
          INTRES.getLocalizedMessage("userdatasource.changedsource", name);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      for (Map.Entry<Object, Object> entry : diff.entrySet()) {
        details.put(entry.getKey().toString(), entry.getValue().toString());
      }
      auditSession.log(
          EjbcaEventTypes.RA_USERDATASOURCEEDIT,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.RA,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      String msg =
          INTRES.getLocalizedMessage("userdatasource.errorchangesource", name);
      LOG.info(msg);
    }
    LOG.trace("<changeUserDataSource()");
  }

  @Override
  public void cloneUserDataSource(
      final AuthenticationToken admin,
      final String oldname,
      final String newname)
      throws UserDataSourceExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">cloneUserDataSource(name: " + oldname + ")");
    }
    BaseUserDataSource userdatasourcedata = null;
    UserDataSourceData htp =
        UserDataSourceData.findByName(entityManager, oldname);
    if (htp == null) {
      String msg =
          INTRES.getLocalizedMessage(
              "userdatasource.errorclonesource", newname, oldname);
      LOG.error(msg);
      throw new EJBException(msg);
    }
    try {
      userdatasourcedata = (BaseUserDataSource) getUserDataSource(htp).clone();
      authorizedToEditUserDataSource(admin, newname, userdatasourcedata);
      try {
        addUserDataSourceInternal(
            admin, findFreeUserDataSourceId(), newname, userdatasourcedata);
        String msg =
            INTRES.getLocalizedMessage(
                "userdatasource.clonedsource", newname, oldname);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(
            EjbcaEventTypes.RA_USERDATASOURCEADD,
            EventStatus.SUCCESS,
            EjbcaModuleTypes.RA,
            EjbcaServiceTypes.EJBCA,
            admin.toString(),
            null,
            null,
            null,
            details);
      } catch (UnsupportedEncodingException f) {
        String msg =
            INTRES.getLocalizedMessage(
                "userdatasource.errorclonesource", newname, oldname);
        LOG.info(msg, f);
        throw new EJBException(f);
      }
    } catch (CloneNotSupportedException e) {
      String msg =
          INTRES.getLocalizedMessage(
              "userdatasource.errorclonesource", newname, oldname);
      LOG.error(msg, e);
      throw new EJBException(e);
    }
    LOG.trace("<cloneUserDataSource()");
  }

  @Override
  public boolean removeUserDataSource(
      final AuthenticationToken admin, final String name)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">removeUserDataSource(name: " + name + ")");
    }
    boolean retval = false;
    UserDataSourceData htp = UserDataSourceData.findByName(entityManager, name);
    if (htp != null) {
      BaseUserDataSource userdatasource = getUserDataSource(htp);
      authorizedToEditUserDataSource(admin, name, userdatasource);
      entityManager.remove(htp);
      String msg =
          INTRES.getLocalizedMessage("userdatasource.removedsource", name);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.RA_USERDATASOURCEREMOVE,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.RA,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
      retval = true;
    } else {
      LOG.info("No such UserDataSource. trying to remove: " + name);
    }
    LOG.trace("<removeUserDataSource()");
    return retval;
  }

  @Override
  public void renameUserDataSource(
      final AuthenticationToken admin,
      final String oldname,
      final String newname)
      throws UserDataSourceExistsException, AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">renameUserDataSource(from " + oldname + " to " + newname + ")");
    }
    boolean success = false;
    if (UserDataSourceData.findByName(entityManager, newname) == null) {
      UserDataSourceData htp =
          UserDataSourceData.findByName(entityManager, oldname);
      if (htp != null) {
        authorizedToEditUserDataSource(admin, oldname, getUserDataSource(htp));
        htp.setName(newname);
        success = true;
      }
    }
    if (success) {
      String msg =
          INTRES.getLocalizedMessage(
              "userdatasource.renamedsource", oldname, newname);
      final Map<String, Object> details = new LinkedHashMap<String, Object>();
      details.put("msg", msg);
      auditSession.log(
          EjbcaEventTypes.RA_USERDATASOURCERENAME,
          EventStatus.SUCCESS,
          EjbcaModuleTypes.RA,
          EjbcaServiceTypes.EJBCA,
          admin.toString(),
          null,
          null,
          null,
          details);
    } else {
      String msg =
          INTRES.getLocalizedMessage(
              "userdatasource.errorrenamesource", oldname, newname);
      LOG.info(msg);
      throw new UserDataSourceExistsException();
    }
    LOG.trace("<renameUserDataSource()");
  }

  @Override
  public Collection<Integer> getAuthorizedUserDataSourceIds(
      final AuthenticationToken admin, final boolean includeAnyCA) {
    HashSet<Integer> returnval = new HashSet<Integer>();
    boolean superadmin = false;
    // If superadmin return all available user data sources
    superadmin =
        authorizationSession.isAuthorizedNoLogging(
            admin, StandardRules.ROLE_ROOT.resource());
    Collection<Integer> authorizedcas = caSession.getAuthorizedCaIds(admin);
    Iterator<UserDataSourceData> i =
        UserDataSourceData.findAll(entityManager).iterator();
    while (i.hasNext()) {
      UserDataSourceData next = i.next();
      if (superadmin) {
        returnval.add(next.getId());
      } else {
        BaseUserDataSource userdatasource = getUserDataSource(next);
        if (userdatasource
            .getApplicableCAs()
            .contains(Integer.valueOf(BaseUserDataSource.ANYCA))) {
          if (includeAnyCA) {
            returnval.add(next.getId());
          }
        } else {
          if (authorizedcas.containsAll(userdatasource.getApplicableCAs())) {
            returnval.add(next.getId());
          }
        }
      }
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public Map<Integer, String> getUserDataSourceIdToNameMap() {
    final Map<Integer, String> ret = new HashMap<>();
    for (final UserDataSourceData userDataSourceData
        : UserDataSourceData.findAll(entityManager)) {
      ret.put(userDataSourceData.getId(), userDataSourceData.getName());
    }
    return ret;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public HashMap<Integer, String> getUserDataSourceIdToNameMap(
      final AuthenticationToken admin) {
    HashMap<Integer, String> returnval = new HashMap<Integer, String>();
    Collection<UserDataSourceData> result =
        UserDataSourceData.findAll(entityManager);
    Iterator<UserDataSourceData> i = result.iterator();
    while (i.hasNext()) {
      UserDataSourceData next = i.next();
      returnval.put(next.getId(), next.getName());
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public BaseUserDataSource getUserDataSource(
      final AuthenticationToken admin, final String name) {
    BaseUserDataSource returnval = null;
    UserDataSourceData udsd =
        UserDataSourceData.findByName(entityManager, name);
    if (udsd != null) {
      BaseUserDataSource result = getUserDataSource(udsd);
      try {
        authorizedToEditUserDataSource(admin, name, result);
        returnval = result;
      } catch (AuthorizationDeniedException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Admin not authorized to user data source, not returning: "
                  + e.getMessage());
        }
      }
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public BaseUserDataSource getUserDataSource(
      final AuthenticationToken admin, final int id) {
    BaseUserDataSource returnval = null;
    UserDataSourceData udsd = UserDataSourceData.findById(entityManager, id);
    if (udsd != null) {
      BaseUserDataSource result = getUserDataSource(udsd);
      try {
        authorizedToEditUserDataSource(admin, udsd.getName(), result);
        returnval = result;
      } catch (AuthorizationDeniedException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Admin not authorized to user data source, not returning: "
                  + e.getMessage());
        }
      }
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public int getUserDataSourceUpdateCount(
      final AuthenticationToken admin, final int userdatasourceid) {
    int returnval = 0;
    UserDataSourceData udsd =
        UserDataSourceData.findById(entityManager, userdatasourceid);
    if (udsd != null) {
      returnval = udsd.getUpdateCounter();
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public int getUserDataSourceId(
      final AuthenticationToken admin, final String name) {
    int returnval = 0;
    UserDataSourceData udsd =
        UserDataSourceData.findByName(entityManager, name);
    if (udsd != null) {
      returnval = udsd.getId();
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public String getUserDataSourceName(
      final AuthenticationToken admin, final int id) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getUserDataSourceName(id: " + id + ")");
    }
    String returnval = null;
    UserDataSourceData udsd = UserDataSourceData.findById(entityManager, id);
    if (udsd != null) {
      returnval = udsd.getName();
    }
    LOG.trace("<getUserDataSourceName()");
    return returnval;
  }

  /**
   * Method to check if an admin is authorized to fetch user data from userdata
   * source The following checks are performed.
   *
   * <p>1. If the admin is an administrator 2. If the admin is authorized to all
   * cas applicable to userdata source. or If the userdatasource have "ANYCA"
   * set. 3. The admin is authorized to the fetch or remove rule depending on
   * the remove parameter
   *
   * @param admin Admin
   * @param id ID
   * @param userdatasource data
   * @param remove if the call is a remove call, othervise fetch authorization
   *     is used.
   * @return true if the administrator is authorized
   */
  private boolean isAuthorizedToUserDataSource(
      final AuthenticationToken admin,
      final int id,
      final BaseUserDataSource userdatasource,
      final boolean remove) {
    if (authorizationSession.isAuthorizedNoLogging(
        admin, StandardRules.ROLE_ROOT.resource())) {
      return true;
    }
    if (remove) {
      if (!authorizationSession.isAuthorized(
          admin,
          AccessRulesConstants.USERDATASOURCEPREFIX
              + id
              + AccessRulesConstants.UDS_REMOVE_RIGHTS)) {
        return false;
      }
    } else {
      if (!authorizationSession.isAuthorized(
          admin,
          AccessRulesConstants.USERDATASOURCEPREFIX
              + id
              + AccessRulesConstants.UDS_FETCH_RIGHTS)) {
        return false;
      }
    }
    if (authorizationSession.isAuthorizedNoLogging(
        admin, AccessRulesConstants.ROLE_ADMINISTRATOR)) {
      if (userdatasource
          .getApplicableCAs()
          .contains(Integer.valueOf(BaseUserDataSource.ANYCA))) {
        return true;
      }
      Collection<Integer> authorizedcas = caSession.getAuthorizedCaIds(admin);
      if (authorizedcas.containsAll(userdatasource.getApplicableCAs())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Method to check if an admin is authorized to edit an user data source The
   * following checks are performed.
   *
   * <p>1. If the admin is an administrator 2. If tha admin is authorized
   * AccessRulesConstants.REGULAR_EDITUSERDATASOURCES 3. Only the superadmin
   * should have edit access to user data sources with 'ANYCA' set 4.
   * Administrators should be authorized to all the user data source applicable
   * cas.
   *
   * @param admin Admin
   * @param name name
   * @param userdatasource Daya
   * @throws AuthorizationDeniedException if the administrator is not authorized
   */
  private void authorizedToEditUserDataSource(
      final AuthenticationToken admin,
      final String name,
      final BaseUserDataSource userdatasource)
      throws AuthorizationDeniedException {

    boolean ret = false;
    if (authorizationSession.isAuthorizedNoLogging(
        admin, StandardRules.ROLE_ROOT.resource())) {
      ret = true;
    }

    if (authorizationSession.isAuthorizedNoLogging(
            admin, AccessRulesConstants.ROLE_ADMINISTRATOR)
        && authorizationSession.isAuthorizedNoLogging(
            admin, AccessRulesConstants.REGULAR_EDITUSERDATASOURCES)) {
      if (userdatasource
          .getApplicableCAs()
          .contains(Integer.valueOf(BaseUserDataSource.ANYCA))) {
        ret = false;
      }
      Collection<Integer> authorizedcas = caSession.getAuthorizedCaIds(admin);
      if (authorizedcas.containsAll(userdatasource.getApplicableCAs())) {
        ret = true;
      }
    }
    if (!ret) {
      final String msg =
          INTRES.getLocalizedMessage("userdatasource.errornotauth", name);
      throw new AuthorizationDeniedException(msg);
    }
  }

  private int findFreeUserDataSourceId() {
    final ProfileID.DB db =
        new ProfileID.DB() {
          @Override
          public boolean isFree(final int i) {
            return UserDataSourceData.findById(
                    UserDataSourceSessionBean.this.entityManager, i)
                == null;
          }
        };
    return ProfileID.getNotUsedID(db);
  }

  /**
   * Method that returns the UserDataSource data and updates it if necessary.
   *
   * @param udsData Data
   * @return Updated
   */
  private BaseUserDataSource getUserDataSource(
      final UserDataSourceData udsData) {
    BaseUserDataSource userdatasource = udsData.getCachedUserDataSource();
    if (userdatasource == null) {
      final HashMap<?, ?> h;
      try (SecureXMLDecoder decoder =
          new SecureXMLDecoder(
              new java.io.ByteArrayInputStream(
                  udsData.getData().getBytes(StandardCharsets.UTF_8)))) {
        h = (HashMap<?, ?>) decoder.readObject();
      } catch (IOException e) {
        final String msg =
            "Failed to parse AcmeOrderData data map in database: "
                + e.getMessage();
        if (LOG.isDebugEnabled()) {
          LOG.debug(msg + ". Data:\n" + udsData.getData());
        }
        throw new IllegalStateException(msg, e);
      }
      // Handle Base64 encoded string values
      HashMap<?, ?> data = new Base64GetHashMap(h);
      switch (((Integer) (data.get(BaseUserDataSource.TYPE))).intValue()) {
        case CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER:
          userdatasource = new CustomUserDataSourceContainer();
          break;
        default: break;
      }
      userdatasource.loadData(data);
    }
    return userdatasource;
  }
}
