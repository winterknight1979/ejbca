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
package org.ejbca.core.ejb.ra;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBUtil;
import org.cesecore.util.StringUtil;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;

/**
 * @version $Id: EndEntityAccessSessionBean.java 29301 2018-06-21 10:27:38Z
 *     andresjakobs $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityAccessSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EndEntityAccessSessionBean
    implements EndEntityAccessSessionLocal, EndEntityAccessSessionRemote {

  /** Columns in the database used in select. */
  private static final String USERDATA_CREATED_COL = "timeCreated";

  /** Log. */
  private static final Logger LOG =
      Logger.getLogger(EndEntityAccessSessionBean.class);
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
  @EJB private EndEntityProfileSessionLocal endEntityProfileSession;
  /** EJB. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** EJB. */
  @EJB private CertificateStoreSessionLocal certificateStoreSession;

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public AbstractMap.SimpleEntry<String, SupportedPasswordHashAlgorithm>
      getPasswordAndHashAlgorithmForUser(final String username)
          throws NotFoundException {
    UserData user = findByUsername(username);
    if (user == null) {
      throw new NotFoundException(
          "End Entity of name " + username + " not found in database");
    } else {
      return new AbstractMap.SimpleEntry<
          String, SupportedPasswordHashAlgorithm>(
          user.getPasswordHash(), user.findHashAlgorithm());
    }
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<EndEntityInformation> findUserBySubjectDN(
      final AuthenticationToken admin, final String subjectdn)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findUserBySubjectDN(" + subjectdn + ")");
    }
    // String used in SQL so strip it
    final String dn =
        CertTools.stringToBCDNString(StringUtil.strip(subjectdn));
    if (LOG.isDebugEnabled()) {
      LOG.debug("Looking for users with subjectdn: " + dn);
    }
    final TypedQuery<UserData> query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN",
            UserData.class);
    query.setParameter("subjectDN", dn);
    final List<UserData> dataList = query.getResultList();

    if (dataList.size() == 0) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Cannot find user with subjectdn: " + dn);
      }
    }
    final List<EndEntityInformation> result =
        new ArrayList<EndEntityInformation>();
    for (UserData data : dataList) {
      result.add(convertUserDataToEndEntityInformation(admin, data, null));
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findUserBySubjectDN(" + subjectdn + ")");
    }
    return result;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<UserData> findNewOrKeyrecByHardTokenIssuerId(
      final int hardTokenIssuerId, final int maxResults) {
    final TypedQuery<UserData> query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE"
                + " a.hardTokenIssuerId=:hardTokenIssuerId AND"
                + " a.tokenType>=:tokenType AND (a.status=:status1 OR"
                + " a.status=:status2)",
            UserData.class);
    query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
    query.setParameter("tokenType", SecConst.TOKEN_HARD_DEFAULT);
    query.setParameter("status1", EndEntityConstants.STATUS_NEW);
    query.setParameter("status2", EndEntityConstants.STATUS_KEYRECOVERY);
    if (maxResults > 0) {
      query.setMaxResults(maxResults);
    }
    return query.getResultList();
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<String> findSubjectDNsByCaIdAndNotUsername(
      final int caId, final String username, final String serialnumber) {
    final TypedQuery<String> query =
        entityManager.createQuery(
            "SELECT a.subjectDN FROM UserData a WHERE a.caId=:caId AND"
                + " a.username!=:username AND a.subjectDN LIKE :serial",
            String.class);
    query.setParameter("caId", caId);
    query.setParameter("username", username);
    query.setParameter("serial", "%SN=" + serialnumber + "%");
    return query.getResultList();
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<EndEntityInformation> findUserBySubjectAndIssuerDN(
      final AuthenticationToken admin,
      final String subjectdn,
      final String issuerdn)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">findUserBySubjectAndIssuerDN(" + subjectdn + ", " + issuerdn + ")");
    }
    // String used in SQL so strip it
    final String dn =
        CertTools.stringToBCDNString(StringUtil.strip(subjectdn));
    final String issuerDN =
        CertTools.stringToBCDNString(StringUtil.strip(issuerdn));
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Looking for users with subjectdn: "
              + dn
              + ", issuerdn : "
              + issuerDN);
    }

    final TypedQuery<UserData> query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN AND"
                + " a.caId=:caId",
            UserData.class);
    query.setParameter("subjectDN", dn);
    query.setParameter("caId", issuerDN.hashCode());
    final List<UserData> dataList = query.getResultList();
    if (dataList.size() == 0) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Cannot find user with subjectdn: "
                + dn
                + ", issuerdn : "
                + issuerDN);
      }
    }
    final List<EndEntityInformation> result =
        new ArrayList<EndEntityInformation>();
    for (UserData data : dataList) {
      result.add(convertUserDataToEndEntityInformation(admin, data, null));
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<findUserBySubjectAndIssuerDN(" + subjectdn + ", " + issuerDN + ")");
    }
    return result;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public EndEntityInformation findUser(final String username) {
    try {
      return findUser(
          new AlwaysAllowLocalAuthenticationToken(
              new UsernamePrincipal("Internal search for End Entity")),
          username);
    } catch (AuthorizationDeniedException e) {
      throw new IllegalStateException(
          "Always allow token was denied authorization.", e);
    }
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public EndEntityInformation findUser(
      final AuthenticationToken admin, final String username)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findUser(" + username + ")");
    }
    final UserData data = findByUsername(username);
    if (data == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Cannot find user with username='" + username + "'");
      }
    }
    final EndEntityInformation ret =
        convertUserDataToEndEntityInformation(admin, data, username);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<findUser("
              + username
              + "): "
              + (ret == null ? "null" : ret.getDN()));
    }
    return ret;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public UserData findByUsername(final String username) {
    if (username == null) {
      return null;
    }
    return entityManager.find(UserData.class, username);
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<EndEntityInformation> findUserByEmail(
      final AuthenticationToken admin, final String email)
      throws AuthorizationDeniedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findUserByEmail(" + email + ")");
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Looking for user with email: " + email);
    }

    final TypedQuery<UserData> query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE a.subjectEmail=:subjectEmail",
            UserData.class);
    query.setParameter("subjectEmail", email);
    final List<UserData> result = query.getResultList();
    if (result.size() == 0) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Cannot find user with Email='" + email + "'");
      }
    }
    final List<EndEntityInformation> returnval =
        new ArrayList<EndEntityInformation>();
    for (final UserData data : result) {
      if (((GlobalConfiguration)
              globalConfigurationSession.getCachedConfiguration(
                  GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
          .getEnableEndEntityProfileLimitations()) {
        // Check if administrator is authorized to view user.
        if (!authorizedToEndEntityProfile(
            admin,
            data.getEndEntityProfileId(),
            AccessRulesConstants.VIEW_END_ENTITY)) {
          continue;
        }
      }
      if (!authorizedToCA(admin, data.getCaId())) {
        continue;
      }
      returnval.add(convertUserDataToEndEntityInformation(admin, data, null));
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findUserByEmail(" + email + ")");
    }
    return returnval;
  }

  /**
   * @param admin Admin
   * @param data Data
   * @param requestedUsername User
   * @return the userdata value object if admin is authorized. Does not leak
   *     username if auth fails.
   * @throws AuthorizationDeniedException if the admin was not authorized to the
   *     end entity profile or issuing CA
   */
  private EndEntityInformation convertUserDataToEndEntityInformation(
      final AuthenticationToken admin,
      final UserData data,
      final String requestedUsername)
      throws AuthorizationDeniedException {
    if (data != null) {
      if (((GlobalConfiguration)
              globalConfigurationSession.getCachedConfiguration(
                  GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
          .getEnableEndEntityProfileLimitations()) {
        // Check if administrator is authorized to view user.
        if (!authorizedToEndEntityProfile(
            admin,
            data.getEndEntityProfileId(),
            AccessRulesConstants.VIEW_END_ENTITY)) {
          if (requestedUsername == null) {
            final String msg =
                INTRES.getLocalizedMessage(
                    "ra.errorauthprofile",
                    Integer.valueOf(data.getEndEntityProfileId()),
                    admin.toString());
            throw new AuthorizationDeniedException(msg);
          } else {
            final String msg =
                INTRES.getLocalizedMessage(
                    "ra.errorauthprofileexist",
                    Integer.valueOf(data.getEndEntityProfileId()),
                    requestedUsername,
                    admin.toString());
            throw new AuthorizationDeniedException(msg);
          }
        }
      }
      if (!authorizedToCA(admin, data.getCaId())) {
        if (requestedUsername == null) {
          final String msg =
              INTRES.getLocalizedMessage(
                  "ra.errorauthca",
                  Integer.valueOf(data.getCaId()),
                  admin.toString());
          throw new AuthorizationDeniedException(msg);
        } else {
          final String msg =
              INTRES.getLocalizedMessage(
                  "ra.errorauthcaexist",
                  Integer.valueOf(data.getCaId()),
                  requestedUsername,
                  admin.toString());
          throw new AuthorizationDeniedException(msg);
        }
      }
      return data.toEndEntityInformation();
    }
    return null;
  }

  private boolean authorizedToEndEntityProfile(
      final AuthenticationToken admin,
      final int profileid,
      final String rights) {
    boolean returnval = false;
    if (profileid == EndEntityConstants.EMPTY_END_ENTITY_PROFILE
        && (rights.equals(AccessRulesConstants.CREATE_END_ENTITY)
            || rights.equals(AccessRulesConstants.EDIT_END_ENTITY))) {
      if (authorizationSession.isAuthorizedNoLogging(
          admin, StandardRules.ROLE_ROOT.resource())) {
        returnval = true;
      } else {
        LOG.info(
            "Admin "
                + admin.toString()
                + " was not authorized to resource "
                + StandardRules.ROLE_ROOT);
      }
    } else {
      returnval =
          authorizationSession.isAuthorizedNoLogging(
              admin,
              AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights,
              AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    }
    return returnval;
  }

  private boolean authorizedToCA(
      final AuthenticationToken admin, final int caid) {
    boolean returnval = false;
    returnval =
        authorizationSession.isAuthorizedNoLogging(
            admin, StandardRules.CAACCESS.resource() + caid);
    if (!returnval) {
      LOG.info(
          "Admin "
              + admin.toString()
              + " not authorized to resource "
              + StandardRules.CAACCESS.resource()
              + caid);
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public Collection<EndEntityInformation> findAllUsersByStatus(
      final AuthenticationToken admin, final int status) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findAllUsersByStatus(" + status + ")");
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Looking for users with status: " + status);
    }
    Query query = new Query(Query.TYPE_USERQUERY);
    query.add(
        UserMatch.MATCH_WITH_STATUS,
        BasicMatch.MATCH_TYPE_EQUALS,
        Integer.toString(status));
    Collection<EndEntityInformation> returnval = null;
    try {
      returnval =
          query(
              admin,
              query,
              null,
              null,
              0,
              AccessRulesConstants.VIEW_END_ENTITY);
    } catch (IllegalQueryException e) {
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("found " + returnval.size() + " user(s) with status=" + status);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findAllUsersByStatus(" + status + ")");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public Collection<EndEntityInformation> findAllUsersByCaId(
      final AuthenticationToken admin, final int caid) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findAllUsersByCaId(" + caid + ")");
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Looking for users with caid: " + caid);
    }
    Query query = new Query(Query.TYPE_USERQUERY);
    query.add(
        UserMatch.MATCH_WITH_CA,
        BasicMatch.MATCH_TYPE_EQUALS,
        Integer.toString(caid));
    Collection<EndEntityInformation> returnval = null;
    try {
      returnval =
          query(
              admin,
              query,
              null,
              null,
              0,
              AccessRulesConstants.VIEW_END_ENTITY);
    } catch (IllegalQueryException e) {
      // Ignore ??
      LOG.debug("Illegal query", e);
      returnval = new ArrayList<EndEntityInformation>();
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("found " + returnval.size() + " user(s) with caid=" + caid);
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findAllUsersByCaId(" + caid + ")");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public long countByCaId(final int caId) {
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT COUNT(a) FROM UserData a WHERE a.caId=:caId");
    query.setParameter("caId", caId);
    return ((Long) query.getSingleResult())
        .longValue(); // Always returns a result
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public long countByCertificateProfileId(final int certificateProfileId) {
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT COUNT(a) FROM UserData a WHERE"
                + " a.certificateProfileId=:certificateProfileId");
    query.setParameter("certificateProfileId", certificateProfileId);
    return ((Long) query.getSingleResult())
        .longValue(); // Always returns a result
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public long countByHardTokenIssuerId(final int hardTokenIssuerId) {
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT COUNT(a) FROM UserData a WHERE"
                + " a.hardTokenIssuerId=:hardTokenIssuerId");
    query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
    return ((Long) query.getSingleResult())
        .longValue(); // Always returns a result
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public long countByHardTokenProfileId(final int hardTokenProfileId) {
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT COUNT(a) FROM UserData a WHERE a.tokenType=:tokenType");
    query.setParameter("tokenType", hardTokenProfileId);
    return ((Long) query.getSingleResult())
        .longValue(); // Always returns a result
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public long countNewOrKeyrecByHardTokenIssuerId(final int hardTokenIssuerId) {
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT COUNT(a) FROM UserData a WHERE"
                + " a.hardTokenIssuerId=:hardTokenIssuerId AND"
                + " a.tokenType>=:tokenType AND (a.status=:status1 OR"
                + " a.status=:status2)");
    query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
    query.setParameter("tokenType", SecConst.TOKEN_HARD_DEFAULT);
    query.setParameter("status1", EndEntityConstants.STATUS_NEW);
    query.setParameter("status2", EndEntityConstants.STATUS_KEYRECOVERY);
    return ((Long) query.getSingleResult())
        .longValue(); // Always returns a result
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<EndEntityInformation> findAllBatchUsersByStatusWithLimit(
      final int status) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findAllUsersByStatusWithLimit()");
    }
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE a.status=:status AND"
                + " (clearPassword IS NOT NULL)");
    query.setParameter("status", status);
    query.setMaxResults(
        getGlobalCesecoreConfiguration().getMaximumQueryCount());
    @SuppressWarnings("unchecked")
    final List<UserData> userDataList = query.getResultList();
    final List<EndEntityInformation> returnval =
        new ArrayList<EndEntityInformation>(userDataList.size());
    for (UserData ud : userDataList) {
      EndEntityInformation endEntityInformation = ud.toEndEntityInformation();
      if (endEntityInformation.getPassword() != null
          && endEntityInformation.getPassword().length() > 0) {
        returnval.add(endEntityInformation);
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findAllUsersByStatusWithLimit()");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public Collection<EndEntityInformation> query(
      final AuthenticationToken admin,
      final Query query,
      final String caauthorizationstr,
      final String endentityprofilestr,
      final int numberofrows,
      final String endentityAccessRule)
      throws IllegalQueryException {
    boolean authorizedtoanyprofile = true;
    final String caauthorizationstring = StringUtil.strip(caauthorizationstr);
    final String endentityprofilestring =
        StringUtil.strip(endentityprofilestr);
    final ArrayList<EndEntityInformation> returnval =
        new ArrayList<EndEntityInformation>();
    int fetchsize = getGlobalCesecoreConfiguration().getMaximumQueryCount();

    if (numberofrows != 0) {
      fetchsize = numberofrows;
    }

    // Check if query is legal.
    if (query != null && !query.isLegalQuery()) {
      throw new IllegalQueryException();
    }

    String sqlquery = "";
    if (query != null) {
      sqlquery += query.getQueryString();
    }

    final GlobalConfiguration globalconfiguration = getGlobalConfiguration();
    String caauthstring = caauthorizationstring;
    String endentityauth = endentityprofilestring;
    RAAuthorization raauthorization = null;
    if (caauthorizationstring == null || endentityprofilestring == null) {
      raauthorization =
          new RAAuthorization(
              admin,
              globalConfigurationSession,
              authorizationSession,
              caSession,
              endEntityProfileSession);
      caauthstring = raauthorization.getCAAuthorizationString();
      if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
        endentityauth =
            raauthorization.getEndEntityProfileAuthorizationString(
                true, endentityAccessRule);
      } else {
        endentityauth = "";
      }
    }
    if (!StringUtils.isBlank(caauthstring)) {
      if (StringUtils.isBlank(sqlquery)) {
        sqlquery += caauthstring;
      } else {
        sqlquery = "(" + sqlquery + ") AND " + caauthstring;
      }
    }
    if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
      if (endentityauth == null || StringUtils.isBlank(endentityauth)) {
        authorizedtoanyprofile = false;
      } else {
        if (StringUtils.isEmpty(sqlquery)) {
          sqlquery += endentityauth;
        } else {
          sqlquery = "(" + sqlquery + ") AND " + endentityauth;
        }
      }
    }
    // Finally order the return values
    sqlquery += " ORDER BY " + USERDATA_CREATED_COL + " DESC";
    if (LOG.isDebugEnabled()) {
      LOG.debug("generated query: " + sqlquery);
    }
    if (authorizedtoanyprofile) {
      final javax.persistence.Query dbQuery =
          entityManager.createQuery(
              "SELECT a FROM UserData a WHERE " + sqlquery);
      if (fetchsize > 0) {
        dbQuery.setMaxResults(fetchsize);
      }
      @SuppressWarnings("unchecked")
      final List<UserData> userDataList = dbQuery.getResultList();
      for (UserData userData : userDataList) {
        returnval.add(userData.toEndEntityInformation());
      }
    } else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("authorizedtoanyprofile=false");
      }
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<query(): " + returnval.size());
    }
    return returnval;
  }

  private GlobalCesecoreConfiguration getGlobalCesecoreConfiguration() {
    return (GlobalCesecoreConfiguration)
        globalConfigurationSession.getCachedConfiguration(
            GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
  }

  /**
   * Gets the Global Configuration from ra admin session bean.
   *
   * @return Config
   */
  private GlobalConfiguration getGlobalConfiguration() {
    return (GlobalConfiguration)
        globalConfigurationSession.getCachedConfiguration(
            GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public Collection<EndEntityInformation> findAllUsersWithLimit(
      final AuthenticationToken admin) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findAllUsersWithLimit()");
    }
    Collection<EndEntityInformation> returnval = null;
    try {
      returnval =
          query(
              admin, null, null, null, 0, AccessRulesConstants.VIEW_END_ENTITY);
    } catch (IllegalQueryException e) {
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findAllUsersWithLimit()");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<EndEntityInformation> findAllUsersByCaIdNoAuth(final int caid) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findAllUsersByCaIdNoAuth()");
    }
    final TypedQuery<UserData> query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE a.caId=:caId", UserData.class);
    query.setParameter("caId", caid);
    final List<UserData> userDataList = query.getResultList();
    final List<EndEntityInformation> returnval =
        new ArrayList<EndEntityInformation>(userDataList.size());
    for (UserData ud : userDataList) {
      returnval.add(ud.toEndEntityInformation());
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findAllUsersByCaIdNoAuth()");
    }
    return returnval;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<UserData> findByEndEntityProfileId(final int endentityprofileid) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findByEndEntityProfileId(" + endentityprofileid + ")");
    }
    final TypedQuery<UserData> query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE"
                + " a.endEntityProfileId=:endEntityProfileId",
            UserData.class);
    query.setParameter("endEntityProfileId", endentityprofileid);
    List<UserData> found = query.getResultList();
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<findByEndEntityProfileId("
              + endentityprofileid
              + "), found: "
              + found.size());
    }
    return found;
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public List<String> findByCertificateProfileId(
      final int certificateprofileid) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">checkForCertificateProfileId(" + certificateprofileid + ")");
    }
    final javax.persistence.Query query =
        entityManager.createQuery(
            "SELECT a FROM UserData a WHERE"
                + " a.certificateProfileId=:certificateProfileId");
    query.setParameter("certificateProfileId", certificateprofileid);

    List<String> result = new ArrayList<String>();
    for (Object userDataObject : query.getResultList()) {
      result.add(((UserData) userDataObject).getUsername());
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "<checkForCertificateProfileId("
              + certificateprofileid
              + "): "
              + result.size());
    }
    return result;
  }

  @Override
  public CertificateWrapper getCertificate(
      final AuthenticationToken authenticationToken,
      final String certSNinHex,
      final String issuerDN)
      throws AuthorizationDeniedException, CADoesntExistsException,
          EjbcaException {
    final String bcString = CertTools.stringToBCDNString(issuerDN);
    final int caId = bcString.hashCode();
    caSession.verifyExistenceOfCA(caId);
    final String[] rules = {
      StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate",
      StandardRules.CAACCESS.resource() + caId
    };
    if (!authorizationSession.isAuthorizedNoLogging(
        authenticationToken, rules)) {
      final String msg =
          INTRES.getLocalizedMessage(
              "authorization.notauthorizedtoresource",
              Arrays.toString(rules),
              null);
      throw new AuthorizationDeniedException(msg);
    }
    final Certificate result =
        certificateStoreSession.findCertificateByIssuerAndSerno(
            issuerDN, new BigInteger(certSNinHex, 16));
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Found certificate for issuer '"
              + issuerDN
              + "' and SN "
              + certSNinHex
              + " for admin "
              + authenticationToken.getUniqueId());
    }
    return EJBUtil.wrap(result);
  }

  @Override
  public Collection<CertificateWrapper> findCertificatesByUsername(
      final AuthenticationToken authenticationToken,
      final String username,
      final boolean onlyValid,
      final long now)
      throws AuthorizationDeniedException, CertificateEncodingException {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Find certificates by username requested by "
              + authenticationToken.getUniqueId());
    }
    // Check authorization on current CA and profiles and view_end_entity by
    // looking up the end entity.
    if (findUser(authenticationToken, username) == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            INTRES.getLocalizedMessage("ra.errorentitynotexist", username));
      }
    }
    // Even if there is no end entity, it might be the case that we don't store
    // UserData, so we still need to check CertificateData.
    Collection<CertificateWrapper> searchResults;
    if (onlyValid) {
      // We will filter out not yet valid certificates later on, but we as the
      // database to not return any expired certificates
      searchResults =
          EJBUtil.wrapCertCollection(
              certificateStoreSession
                  .findCertificatesByUsernameAndStatusAfterExpireDate(
                      username, CertificateConstants.CERT_ACTIVE, now));
    } else {
      searchResults =
          certificateStoreSession.findCertificatesByUsername(username);
    }
    // Assume the user may have certificates from more than one CA.
    Certificate certificate = null;
    int caId = -1;
    Boolean authorized = null;
    final Map<Integer, Boolean> authorizationCache = new HashMap<>();
    final List<CertificateWrapper> result = new ArrayList<>();
    for (Object searchResult : searchResults) {
      certificate = ((CertificateWrapper) searchResult).getCertificate();
      caId = CertTools.getIssuerDN(certificate).hashCode();
      authorized = authorizationCache.get(caId);
      if (authorized == null) {
        authorized =
            authorizationSession.isAuthorizedNoLogging(
                authenticationToken, StandardRules.CAACCESS.resource() + caId);
        authorizationCache.put(caId, authorized);
      }
      if (authorized.booleanValue()) {
        result.add((CertificateWrapper) searchResult);
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Found "
              + result.size()
              + " certificate(s) by username requested by "
              + authenticationToken.getUniqueId());
    }
    return result;
  }
}
