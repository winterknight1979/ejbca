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

package org.ejbca.ui.web.admin.rainterface;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.roles.Role;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBUtil;
import org.cesecore.util.FileTools;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringUtil;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserNotification;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 *
 * @version $Id: RAInterfaceBean.java 34101 2019-12-17 13:59:55Z samuellb $
 */
public class RAInterfaceBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Param. */
  private static final Logger LOG = Logger.getLogger(RAInterfaceBean.class);
  /** Internal localization of logs and errors. */
  private static final InternalEjbcaResources INTRES =
      InternalEjbcaResources.getInstance();
  /** Param. */

  public static final String[] TOKENTEXTS = SecConst.TOKENTEXTS;
  /** Param. */
  public static final int[] TOKENIDS = SecConst.TOKENIDS;

  /** Param. */
  private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();

  /** Param. */
  private AuthorizationSessionLocal authorizationSession;
  /** Param. */
  private CaSessionLocal caSession;
  /** Param. */
  private CertificateProfileSession certificateProfileSession;
  /** Param. */
  private CertificateStoreSession certificatesession;
  /** Param. */
  private EndEntityAccessSessionLocal endEntityAccessSession;
  /** Param. */
  private EndEntityManagementSessionLocal endEntityManagementSession;
  /** Param. */
  private EndEntityProfileSessionLocal endEntityProfileSession;
  /** Param. */
  private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** Param. */
  private HardTokenSessionLocal hardtokensession;
  /** Param. */
  private KeyRecoverySession keyrecoverysession;
  /** Param. */
  private UserDataSourceSession userdatasourcesession;

  /** Param. */
  private final UsersView usersView;
  /** Param. */
  private CertificateView[] certificates;
  /** Param. */
  private final AddedUserMemory addedusermemory;
  /** Param. */
  private AuthenticationToken administrator;
  /** Param. */
  private EjbcaWebBean ejbcawebbean;
  /** Param. */
  private RAAuthorization raauthorization;
  /** Param. */
  private boolean initialized = false;

  /** Param. */
  private String[] printerNames = null;
  /** Param. */
  private String importedProfileName = null;

  /** Param. */
  private EndEntityProfile temporaryEndEntityProfile = null;
  /** Param. */
  private UserNotification temporaryNotification = null;

  /** Creates new RaInterfaceBean. */
  public RAInterfaceBean() {
    usersView = new UsersView();
    addedusermemory = new AddedUserMemory();
  }

  /**
   * @param request req
   * @param anejbcawebbean bean
   */
  public void initialize(
      final HttpServletRequest request, final EjbcaWebBean anejbcawebbean) {
    LOG.trace(">initialize()");
    if (!initialized) {
      if (request.getAttribute("javax.servlet.request.X509Certificate")
          != null) {
        administrator = anejbcawebbean.getAdminObject();
      } else {
        administrator =
            new PublicAccessAuthenticationToken(request.getRemoteAddr(), true);
      }
      this.ejbcawebbean = anejbcawebbean;
      endEntityManagementSession =
          ejbLocalHelper.getEndEntityManagementSession();
      certificatesession = ejbLocalHelper.getCertificateStoreSession();
      caSession = ejbLocalHelper.getCaSession();
      authorizationSession = ejbLocalHelper.getAuthorizationSession();
      endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
      hardtokensession = ejbLocalHelper.getHardTokenSession();
      keyrecoverysession = ejbLocalHelper.getKeyRecoverySession();
      userdatasourcesession = ejbLocalHelper.getUserDataSourceSession();
      certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
      this.endEntityAccessSession = ejbLocalHelper.getEndEntityAccessSession();
      globalConfigurationSession =
          ejbLocalHelper.getGlobalConfigurationSession();
      raauthorization =
          new RAAuthorization(
              administrator,
              globalConfigurationSession,
              authorizationSession,
              caSession,
              endEntityProfileSession);
      initialized = true;
    } else {
      LOG.debug("=initialize(): already initialized");
    }
    LOG.trace("<initialize()");
  }

  private GlobalConfiguration getGlobalConfiguration() {
    return (GlobalConfiguration)
        globalConfigurationSession.getCachedConfiguration(
            GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
  }

  /**
   * Adds a user to the database, the string array must be in format defined in
   * class UserView.
   *
   * @param userdata Data
   * @throws WaitingForApprovalException fail
   * @throws EndEntityProfileValidationException fail
   * @throws AuthorizationDeniedException fail
   * @throws CADoesntExistsException fail
   * @throws EndEntityExistsException fail
   * @return added user as EndEntityInformation
   * @throws CertificateSerialNumberException if SubjectDN serial number already
   *     exists.
   * @throws ApprovalException if an approval already exists for this request.
   * @throws CustomFieldException if the end entity was not validated by a
   *     locally defined field validator
   * @throws IllegalNameException if the Subject DN failed constraints
   */
  public EndEntityInformation addUser(final UserView userdata)
      throws EndEntityExistsException, CADoesntExistsException,
          AuthorizationDeniedException, EndEntityProfileValidationException,
          WaitingForApprovalException, IllegalNameException,
          CustomFieldException, ApprovalException,
          CertificateSerialNumberException {
    LOG.trace(">addUser()");
    if (userdata.getEndEntityProfileId() != 0) {
      EndEntityInformation uservo =
          new EndEntityInformation(
              userdata.getUsername(),
              userdata.getSubjectDN(),
              userdata.getCAId(),
              userdata.getSubjectAltName(),
              userdata.getEmail(),
              EndEntityConstants.STATUS_NEW,
              userdata.getType(),
              userdata.getEndEntityProfileId(),
              userdata.getCertificateProfileId(),
              null,
              null,
              userdata.getTokenType(),
              userdata.getHardTokenIssuerId(),
              null);
      EndEntityProfile endEntityProfile =
          getEndEntityProfile(userdata.getEndEntityProfileId());
      if (StringUtils.isEmpty(userdata.getPassword())
          && endEntityProfile.isPasswordPreDefined()) {
        uservo.setPassword(endEntityProfile.getPredefinedPassword());
      } else {
        uservo.setPassword(userdata.getPassword());
      }
      uservo.setExtendedInformation(userdata.getExtendedInformation());
      uservo.setCardNumber(userdata.getCardNumber());
      endEntityManagementSession.addUser(
          administrator, uservo, userdata.getClearTextPassword());
      addedusermemory.addUser(userdata);
      return uservo;
    } else {
      LOG.debug("=addUser(): profile id not set, user not created");
    }
    LOG.trace("<addUser()");
    return null;
  }

  /**
   * Removes a number of users from the database.
   *
   * @param usernames an array of usernames to delete.
   * @return false if administrator wasn't authorized to delete all of given
   *     users.
   * @throws NoSuchEndEntityException Fail
   * @throws CouldNotRemoveEndEntityException if the user could not be deleted.
   */
  public boolean deleteUsers(final String[] usernames)
      throws NoSuchEndEntityException, CouldNotRemoveEndEntityException {
    LOG.trace(">deleteUsers()");
    boolean success = true;
    for (String username : usernames) {
      try {
        endEntityManagementSession.deleteUser(administrator, username);
        addedusermemory.removeUser(username);
      } catch (AuthorizationDeniedException e) {
        success = false;
      }
    }
    LOG.trace("<deleteUsers(): " + success);
    return success;
  }

  /**
   * Changes the status of a number of users from the database.
   *
   * @param usernames an array of usernames to change.
   * @param status gives the status to apply to users, should be one of
   *     UserDataRemote.STATUS constants.
   * @return false if administrator wasn't authorized to change all of the given
   *     users.
   * @throws ApprovalException Approval
   * @throws NoSuchEndEntityException Fail
   * @throws WaitingForApprovalException fail
   */
  public boolean setUserStatuses(final String[] usernames, final String status)
      throws ApprovalException, NoSuchEndEntityException,
          WaitingForApprovalException {
    LOG.trace(">setUserStatuses()");
    boolean success = true;
    int intstatus = 0;
    try {
      intstatus = Integer.parseInt(status);
    } catch (Exception e) {
    }
    for (int i = 0; i < usernames.length; i++) {
      try {
        endEntityManagementSession.setUserStatus(
            administrator, usernames[i], intstatus);
      } catch (AuthorizationDeniedException e) {
        success = false;
      }
    }
    LOG.trace("<setUserStatuses(): " + success);
    return success;
  }

  /**
   * Revokes the given user.
   *
   * @param username username of user to revoke.
   * @param reason reason(s) of revocation.
   * @throws AuthorizationDeniedException Fail
   * @throws NoSuchEndEntityException Fail
   * @throws ApprovalException Fail
   * @throws WaitingForApprovalException Fail
   * @throws AlreadyRevokedException Fail
   */
  public void revokeUser(final String username, final int reason)
      throws AuthorizationDeniedException, NoSuchEndEntityException,
          ApprovalException, WaitingForApprovalException,
          AlreadyRevokedException {
    LOG.trace(">revokeUser()");
    endEntityManagementSession.revokeUser(administrator, username, reason);
    LOG.trace("<revokeUser()");
  }

  /**
   * @param username User
   * @param reason Reason
   * @throws AuthorizationDeniedException Fail
   * @throws ApprovalException Fail
   * @throws WaitingForApprovalException Fail
   * @throws NoSuchEndEntityException Fail
   * @throws CouldNotRemoveEndEntityException Fail
   */
  public void revokeAndDeleteUser(final String username, final int reason)
      throws AuthorizationDeniedException, ApprovalException,
          WaitingForApprovalException, NoSuchEndEntityException,
          CouldNotRemoveEndEntityException {
    LOG.trace(">revokeUser()");
    endEntityManagementSession.revokeAndDeleteUser(
        administrator, username, reason);
    LOG.trace("<revokeUser()");
  }

  /**
   * Revokes the certificate with certificate serno.
   *
   * @param serno serial number of certificate to revoke.
   * @param issuerdn the issuerdn of certificate to revoke.
   * @param username User
   * @param reason reason(s) of revocation.
   * @return false if administrator wasn't authorized to revoke the given
   *     certificate.
   * @throws ApprovalException Fail
   * @throws WaitingForApprovalException Fail
   */
  public boolean revokeCert(
      final BigInteger serno,
      final String issuerdn,
      final String username,
      final int reason)
      throws ApprovalException, WaitingForApprovalException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">revokeCert(): " + username + ", " + reason);
    }
    boolean success = false;
    try {
      endEntityManagementSession.revokeCert(
          administrator, serno, issuerdn, reason);
      success = true;
    } catch (AuthorizationDeniedException e) {
    } catch (NoSuchEndEntityException e) {
    } catch (AlreadyRevokedException e) {
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<revokeCert(): " + success);
    }
    return success;
  }

  /**
   * Reactivates the certificate with certificate serno.
   *
   * @param serno serial number of certificate to reactivate.
   * @param issuerdn the issuerdn of certificate to reactivate.
   * @param username the username joined to the certificate.
   * @return false if administrator wasn't authorized to unrevoke the given
   *     certificate.
   * @throws ApprovalException Approval
   * @throws WaitingForApprovalException fail
   */
  public boolean unrevokeCert(
      final BigInteger serno, final String issuerdn, final String username)
      throws ApprovalException, WaitingForApprovalException {
    // Method needed because it is used as an ApprovalOveradableClassName
    return revokeCert(serno, issuerdn, username, RevokedCertInfo.NOT_REVOKED);
  }

  /**
   * @param currentUsername User
   * @param newUsername User
   * @return bool
   * @throws AuthorizationDeniedException fail
   * @throws EndEntityExistsException fail
   */
  public boolean renameUser(
      final String currentUsername, final String newUsername)
      throws AuthorizationDeniedException, EndEntityExistsException {
    return endEntityManagementSession.renameEndEntity(
        administrator, currentUsername, newUsername);
  }

  /**
   * Changes the userdata.
   *
   * @param userdata the UserView object with the desired changes
   * @param newUsername the new username if it should be changed
   * @throws CADoesntExistsException if CA with ID in userdata does not exist
   * @throws AuthorizationDeniedException if admin is not authorized to CA
   * @throws EndEntityProfileValidationException if End Entity doesn't match
   *     profile
   * @throws WaitingForApprovalException if the request requires approval
   * @throws IllegalNameException if the Subject DN failed constraints
   * @throws CertificateSerialNumberException if SubjectDN serial number already
   *     exists.
   * @throws ApprovalException if an approval already is waiting for specified
   *     action
   * @throws NoSuchEndEntityException if the end entity could not be found.
   * @throws CustomFieldException if the end entity was not validated by a
   *     locally defined field validator
   */
  public void changeUserData(final UserView userdata, final String newUsername)
      throws CADoesntExistsException, AuthorizationDeniedException,
          EndEntityProfileValidationException, WaitingForApprovalException,
          ApprovalException, CertificateSerialNumberException,
          IllegalNameException, NoSuchEndEntityException, CustomFieldException {
    LOG.trace(">changeUserData()");
    addedusermemory.changeUser(userdata);
    if (userdata.getPassword() != null
        && userdata.getPassword().trim().equals("")) {
      userdata.setPassword(null);
    }
    EndEntityInformation uservo =
        new EndEntityInformation(
            userdata.getUsername(),
            userdata.getSubjectDN(),
            userdata.getCAId(),
            userdata.getSubjectAltName(),
            userdata.getEmail(),
            userdata.getStatus(),
            userdata.getType(),
            userdata.getEndEntityProfileId(),
            userdata.getCertificateProfileId(),
            null,
            null,
            userdata.getTokenType(),
            userdata.getHardTokenIssuerId(),
            null);
    uservo.setPassword(userdata.getPassword());
    uservo.setExtendedInformation(userdata.getExtendedInformation());
    uservo.setCardNumber(userdata.getCardNumber());
    if (userdata.getUsername().equals(newUsername)) {
      endEntityManagementSession.changeUser(
          administrator, uservo, userdata.getClearTextPassword());
    } else {
      endEntityManagementSession.changeUser(
          administrator, uservo, userdata.getClearTextPassword(), newUsername);
    }
    LOG.trace("<changeUserData()");
  }

  /**
   * Method to filter out a user by it's username.
   *
   * @param username User
   * @return View
   */
  public UserView[] filterByUsername(final String username) {
    LOG.trace(">filterByUserName()");
    EndEntityInformation[] userarray = new EndEntityInformation[1];
    EndEntityInformation user = null;
    try {
      user = endEntityAccessSession.findUser(administrator, username);
    } catch (AuthorizationDeniedException e) {
    }
    if (user != null) {
      userarray[0] = user;
      usersView.setUsers(userarray, caSession.getCAIdToNameMap());
    } else {
      usersView.setUsers(
          (EndEntityInformation[]) null, caSession.getCAIdToNameMap());
    }
    LOG.trace("<filterByUserName()");
    return usersView.getUsers(0, 1);
  }

  /**
   * Method used to check if user exists.
   *
   * @param username User
   * @return View
   * @throws Exception fail
   */
  public boolean userExist(final String username) throws Exception {
    return endEntityManagementSession.existsUser(username);
  }

  /**
   * Method to retrieve a user from the database without inserting it into users
   * data, used by 'viewuser.jsp' and page.
   *
   * @param username User
   * @return View
   * @throws Exception fail
   */
  public UserView findUser(final String username) throws Exception {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">findUser(" + username + ")");
    }
    EndEntityInformation user =
        endEntityAccessSession.findUser(administrator, username);
    UserView userview = null;
    if (user != null) {
      userview = new UserView(user, caSession.getCAIdToNameMap());
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<findUser(" + username + "): " + userview);
    }
    return userview;
  }

  /**
   * Method to retrieve a user from the database without inserting it into users
   * data, used by 'edituser.jsp' and page.
   *
   * @param username User
   * @return View
   * @throws AuthorizationDeniedException fail
   */
  public UserView findUserForEdit(final String username)
      throws AuthorizationDeniedException {
    UserView userview = null;
    EndEntityInformation user =
        endEntityAccessSession.findUser(administrator, username);
    if (user != null) {
      if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
        if (!endEntityAuthorization(
            administrator,
            user.getEndEntityProfileId(),
            AccessRulesConstants.EDIT_END_ENTITY,
            false)) {
          throw new AuthorizationDeniedException(
              "Not authorized to edit user.");
        }
      }
      userview = new UserView(user, caSession.getCAIdToNameMap());
    }
    return userview;
  }

  /**
   * Method to find all users in database.
   *
   * @param index Index
   * @param size Size
   * @return View
   */
  public UserView[] findAllUsers(final int index, final int size) {
    usersView.setUsers(
        endEntityAccessSession.findAllUsersWithLimit(administrator),
        caSession.getCAIdToNameMap());
    return usersView.getUsers(index, size);
  }

  /**
   * Method to find all users in database.
   *
   * @param tokensn SN
   * @param index Index
   * @param size Size
   * @return View
   */
  public UserView[] filterByTokenSN(
      final String tokensn, final int index, final int size) {
    UserView[] returnval = null;
    ArrayList<EndEntityInformation> userlist = new ArrayList<>();
    Collection<String> usernames =
        hardtokensession.matchHardTokenByTokenSerialNumber(tokensn);
    Iterator<String> iter = usernames.iterator();
    while (iter.hasNext()) {
      EndEntityInformation user = null;
      try {
        user = endEntityAccessSession.findUser(administrator, iter.next());
      } catch (AuthorizationDeniedException e) {
      }
      if (user != null) {
        userlist.add(user);
      }
    }
    usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    returnval = usersView.getUsers(index, size);
    return returnval;
  }

  /**
   * Method that fetches a certificate by serialnumber and returns the user(s),
   * else a null value if no certificate/user exists.
   *
   * @param serialnumber SN
   * @param index Index
   * @param size Size
   * @return Views
   * @throws NumberFormatException fail
   */
  public UserView[] filterByCertificateSerialNumber(
      final String serialnumber, final int index, final int size)
      throws NumberFormatException {
    final BigInteger serno =
        new BigInteger(StringUtil.stripWhitespace(serialnumber), 16);
    final List<CertificateDataWrapper> cdws =
        certificatesession.getCertificateDataBySerno(serno);
    final List<EndEntityInformation> userlist = new ArrayList<>();
    for (final CertificateDataWrapper next : cdws) {
      final CertificateData certdata = next.getCertificateData();
      try {
        final String username = certdata.getUsername();
        if (username != null) {
          final EndEntityInformation user =
              endEntityAccessSession.findUser(administrator, username);
          if (user != null) {
            userlist.add(user);
          }
        }
        if (userlist.isEmpty()) {
          // Perhaps it's such an old installation that we don't have username
          // in the CertificateData table (has it even ever been like that?, I
          // don't think so)
          final List<EndEntityInformation> users =
              endEntityAccessSession.findUserBySubjectAndIssuerDN(
                  administrator,
                  certdata.getSubjectDnNeverNull(),
                  certdata.getIssuerDN());
          userlist.addAll(users);
        }
      } catch (AuthorizationDeniedException e) {
      }
    }
    usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    return usersView.getUsers(index, size);
  }

  /**
   * Method that lists all users with certificate's that expires within given
   * days.
   *
   * @param days Days
   * @param index Index
   * @param size Size
   * @return Views
   * @throws NumberFormatException Fail
   */
  public UserView[] filterByExpiringCertificates(
      final String days, final int index, final int size)
      throws NumberFormatException {
    ArrayList<EndEntityInformation> userlist = new ArrayList<>();
    UserView[] returnval = null;
    long d = Long.parseLong(days);
    Date finddate = new Date();
    final long oneday = 86400000;
    long millis = (d * oneday); // One day in milliseconds.
    finddate.setTime(finddate.getTime() + millis);
    Collection<String> usernames =
        certificatesession.findUsernamesByExpireTimeWithLimit(finddate);
    if (!usernames.isEmpty()) {
      Iterator<String> i = usernames.iterator();
      while (i.hasNext() && userlist.size() <= getMaximumQueryRowCount() + 1) {
        EndEntityInformation user = null;
        try {
          user = endEntityAccessSession.findUser(administrator, i.next());
          if (user != null) {
            userlist.add(user);
          }
        } catch (AuthorizationDeniedException e) {
        }
      }
      usersView.setUsers(userlist, caSession.getCAIdToNameMap());
      returnval = usersView.getUsers(index, size);
    }
    return returnval;
  }

  /**
   * @param query Query
   * @param index Index
   * @param size Size
   * @param endentityAccessRule Rule
   * @return View
   * @throws IllegalQueryException fail
   */
  public UserView[] filterByQuery(
      final Query query,
      final int index,
      final int size,
      final String endentityAccessRule)
      throws IllegalQueryException {
    Collection<EndEntityInformation> userlist =
        endEntityAccessSession.query(
            administrator,
            query,
            raauthorization.getCAAuthorizationString(),
            raauthorization.getEndEntityProfileAuthorizationString(
                true, endentityAccessRule),
            0,
            endentityAccessRule);
    usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    return usersView.getUsers(index, size);
  }

  /**
   * @return size
   */
  public int getResultSize() {
    return usersView.size();
  }

  /**
   * @param username user
   * @return bool
   * @throws AuthorizationDeniedException fail
   */
  public boolean isAuthorizedToViewUserHistory(final String username)
      throws AuthorizationDeniedException {
    EndEntityInformation user =
        endEntityAccessSession.findUser(administrator, username);
    return endEntityAuthorization(
        administrator,
        user.getEndEntityProfileId(),
        AccessRulesConstants.VIEW_END_ENTITY_HISTORY,
        false);
  }

  /**
   * @param username User
   * @return Boiol
   * @throws AuthorizationDeniedException Fail
   */
  public boolean isAuthorizedToEditUser(final String username)
      throws AuthorizationDeniedException {
    EndEntityInformation user =
        endEntityAccessSession.findUser(administrator, username);
    return endEntityAuthorization(
        administrator,
        user.getEndEntityProfileId(),
        AccessRulesConstants.EDIT_END_ENTITY,
        false);
  }

  /**
   * Method to resort filtered user data.
   *
   * @param sortby Sort
   * @param sortorder order
   */
  public void sortUserData(final int sortby, final int sortorder) {
    usersView.sortBy(sortby, sortorder);
  }

  /**
   * Method to return the users between index and size, if userdata is smaller
   * than size, a smaller array is returned.
   *
   * @param index Index
   * @param size Size
   * @return View
   */
  public UserView[] getUsers(final int index, final int size) {
    return usersView.getUsers(index, size);
  }

  /** Method that clears the userview memory. */
  public void clearUsers() {
    usersView.clear();
  }

  /**
   * @param index Index
   * @param size Size
   * @return Bool
   */
  public boolean nextButton(final int index, final int size) {
    return index + size < usersView.size();
  }
/**
   * @param index Index
   * @return Bool
   */
  public boolean previousButton(final int index) {
    return index > 0;
  }

  // Method dealing with added user memory.
  /**
   * A method to get the last added users in adduser.jsp.
   *
   * @param size Size
   * @return Views
   * @see org.ejbca.ui.web.admin.rainterface.AddedUserMemory
   */
  public UserView[] getAddedUsers(final int size) {
    return addedusermemory.getUsers(size);
  }

  // Methods dealing with profiles.
  /**
   * @param endentityAccessRule Rule
   * @return Names
   */
  public TreeMap<String, String> getAuthorizedEndEntityProfileNames(
      final String endentityAccessRule) {
    return raauthorization.getAuthorizedEndEntityProfileNames(
        endentityAccessRule);
  }

  /**
   * @return CA
   */
  public List<String> getAuthorizedEndEntityProfileIdsWithMissingCAs() {
    return raauthorization.getViewAuthorizedEndEntityProfilesWithMissingCAs();
  }

  /**
   * Returns the profile name from id proxied.
   *
   * @param profileid ID
   * @return Name
   */
  public String getEndEntityProfileName(final int profileid) {
    return endEntityProfileSession.getEndEntityProfileName(profileid);
  }

  /**
   * @param profilename the name of the sought profile
   * @return the ID of the sought profile
   * @throws EndEntityProfileNotFoundException if no such profile exists
   */
  public int getEndEntityProfileId(final String profilename)
      throws EndEntityProfileNotFoundException {
    return endEntityProfileSession.getEndEntityProfileId(profilename);
  }

  /**
   * @param sourceid ID
   * @return Name
   */
  public String getUserDataSourceName(final int sourceid) {
    return this.userdatasourcesession.getUserDataSourceName(
        administrator, sourceid);
  }

  /**
   * @param sourcename name
   * @return ID
   */
  public int getUserDataSourceId(final String sourcename) {
    return this.userdatasourcesession.getUserDataSourceId(
        administrator, sourcename);
  }

  /**
   * @param name name
   * @return prof
   */
  public EndEntityProfile getEndEntityProfile(final String name) {
    return endEntityProfileSession.getEndEntityProfile(name);
  }

  /**
   * @param id ID
   * @return prof
   */
  public EndEntityProfile getEndEntityProfile(final int id) {
    return endEntityProfileSession.getEndEntityProfile(id);
  }

  /**
   * @param name name
   * @throws EndEntityProfileExistsException fail
   * @throws AuthorizationDeniedException fail
   */
  public void addEndEntityProfile(final String name)
      throws EndEntityProfileExistsException, AuthorizationDeniedException {
    EndEntityProfile profile = new EndEntityProfile();
    String availablecas =
        StringUtils.join(
            caSession.getAuthorizedCaIds(administrator),
            EndEntityProfile.SPLITCHAR);
    profile.setValue(EndEntityProfile.AVAILCAS, 0, availablecas);
    profile.setRequired(EndEntityProfile.AVAILCAS, 0, true);
    endEntityProfileSession.addEndEntityProfile(administrator, name, profile);
  }

  /**
   * @param name name
   * @param profile profile
   * @throws AuthorizationDeniedException fail
   * @throws EndEntityProfileNotFoundException fail
   */
  public void changeEndEntityProfile(
      final String name, final EndEntityProfile profile)
      throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
    endEntityProfileSession.changeEndEntityProfile(
        administrator, name, profile);
  }

  /**
   * Tries to remove an End Entity Profile. Returns an array of messages
   * containing information about what is preventing the removal, or empty
   * strings if the removal was successful.
   *
   * @param name the name of the profile to be removed
   * @return an array of strings containing information about the EEs and
   *     administrator roles using the EEP
   * @throws AuthorizationDeniedException if the admin is not authorized to
   *     remove the EEP
   * @throws EndEntityProfileNotFoundException if no such end entity profile was
   *     found
   */
  public String[] removeEndEntityProfile(final String name)
      throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
    String[] messageArray = {"", "", ""};
    int profileId = endEntityProfileSession.getEndEntityProfileId(name);
    List<UserData> users =
        endEntityAccessSession.findByEndEntityProfileId(profileId);
    if (users.size() > 0) {
      messageArray[0] = "used";
    }
    // Only return the users the admin is authorized to view to prevent
    // information leaks
    List<String> authorizedUsers = new ArrayList<>();
    for (UserData user : users) {
      if (caSession.authorizedToCANoLogging(administrator, user.getCaId())
          && authorizationSession.isAuthorizedNoLogging(
              administrator, AccessRulesConstants.REGULAR_VIEWENDENTITY)) {
        authorizedUsers.add(user.getUsername());
      }
    }
    // Only return the End Entities that the admin is authorized to (empty
    // string if none)
    messageArray[1] = StringUtils.join(authorizedUsers, ", ");
    List<String> usedRules = getRulesWithEndEntityProfile(profileId);
    if (usedRules.size() > 0) {
      messageArray[0] = "used";
    }
    if (authorizationSession.isAuthorizedNoLogging(
        administrator, StandardRules.VIEWROLES.resource())) {
      // Only return the used administrator roles if the admin is authorized to
      // view them to prevent information leaks
      messageArray[2] = StringUtils.join(usedRules, ", ");
    }
    // Remove profile if it's not in use
    if (messageArray[0].isEmpty()) {
      endEntityProfileSession.removeEndEntityProfile(administrator, name);
    }
    return messageArray;
  }

  /**
   * @param profileId ID
   * @return a list of role names where the End Entity Profile's ID is
   *     explicitly defined in the role's access rules
   */
  private List<String> getRulesWithEndEntityProfile(final int profileId) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(">getRulesWithEndEntityProfile(" + profileId + ")");
    }
    final List<String> rolenames = new ArrayList<>();
    final Pattern idInRulename =
        Pattern.compile(
            "^"
                + AccessRulesConstants.ENDENTITYPROFILEPREFIX
                + "(-?[0-9]+)/.*$");
    for (final Role role : ejbLocalHelper.getRoleDataSession().getAllRoles()) {
      for (final String explicitResource : role.getAccessRules().keySet()) {
        final Matcher matcher = idInRulename.matcher(explicitResource);
        if (matcher.find()
            && String.valueOf(profileId).equals(matcher.group(1))) {
          rolenames.add(role.getRoleNameFull());
          break;
        }
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "End entity profile with id "
              + profileId
              + " is present in roles: "
              + StringUtils.join(rolenames, ", "));
    }
    if (LOG.isTraceEnabled()) {
      LOG.trace("<getRulesWithEndEntityProfile(" + profileId + ")");
    }
    return rolenames;
  }

  /**
   * @param oldname old
   * @param newname new
   * @throws EndEntityProfileExistsException fail
   * @throws AuthorizationDeniedException fail
   */
  public void renameEndEntityProfile(final String oldname, final String newname)
      throws EndEntityProfileExistsException, AuthorizationDeniedException {
    endEntityProfileSession.renameEndEntityProfile(
        administrator, oldname, newname);
  }

  /**
   * @param userNotification notif
   */
  public void setTemporaryEndEntityProfileNotification(
      final UserNotification userNotification) {
    temporaryNotification = userNotification;
  }

  /**
   * @return notif
   */
  public UserNotification getTemporaryEndEntityProfileNotification() {
    return temporaryNotification;
  }

  /**
   * @param originalname Name
   * @param newname NAme
   * @throws EndEntityProfileExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void cloneEndEntityProfile(
      final String originalname, final String newname)
      throws EndEntityProfileExistsException, AuthorizationDeniedException {
    endEntityProfileSession.cloneEndEntityProfile(
        administrator, originalname, newname);
  }

  /**
   * @param username User
   */
  public void loadCertificates(final String username) {
    loadTokenCertificates(
        certificatesession.getCertificateDataByUsername(username, false, null));
  }

  /**
   * @param tokensn SN
   */
  public void loadTokenCertificates(final String tokensn) {
    loadTokenCertificates(
        hardtokensession.getCertificateDatasFromHardToken(tokensn));
  }

  /**
   * @param cdws wrappers
   */
  private void loadTokenCertificates(final List<CertificateDataWrapper> cdws) {
    final int max = 50;
    if (!cdws.isEmpty()) {
      if (cdws.size() <= max) {
        Collections.sort(cdws);
      } else {
        LOG.debug("User has more than 50 certificates, we will not sort them");
      }
      certificates = new CertificateView[cdws.size()];
      for (int i = 0; i < certificates.length; i++) {
        certificates[i] = new CertificateView(cdws.get(i));
      }
    } else {
      certificates = null;
    }
  }

  /**
   * @param tokensn SN
   * @param username Name
   * @param reason Reason
   * @return Certs
   * @throws ApprovalException Fail
   * @throws WaitingForApprovalException Fail
   * @throws AlreadyRevokedException Fail
   */
  public boolean revokeTokenCertificates(
      final String tokensn, final String username, final int reason)
      throws ApprovalException, WaitingForApprovalException,
          AlreadyRevokedException {
    boolean success = true;
    ApprovalException lastAppException = null;
    WaitingForApprovalException lastWaitException = null;
    AlreadyRevokedException lastRevokedException = null;
    Collection<Certificate> certs =
        hardtokensession.findCertificatesInHardToken(tokensn);
    Iterator<Certificate> i = certs.iterator();
    // Extract and revoke collection
    while (i.hasNext()) {
      Certificate cert = i.next();
      try {
        endEntityManagementSession.revokeCert(
            administrator,
            CertTools.getSerialNumber(cert),
            CertTools.getIssuerDN(cert),
            reason);
        // Ignore errors if some were successful
      } catch (ApprovalException e) {
        lastAppException = e;
      } catch (WaitingForApprovalException e) {
        lastWaitException = e;
      } catch (AlreadyRevokedException e) {
        lastRevokedException = e;
      } catch (AuthorizationDeniedException e) {
        success = false;
      } catch (NoSuchEndEntityException e) {
        success = false;
      }
    }
    if (lastWaitException != null) {
      throw lastWaitException;
    }
    if (lastAppException != null) {
      throw lastAppException;
    }
    if (lastRevokedException != null) {
      throw lastRevokedException;
    }
    return success;
  }

  /**
   * @param tokensn SN
   * @param username User
   * @return Fail
   */
  public boolean isAllTokenCertificatesRevoked(
      final String tokensn, final String username) {
    Collection<Certificate> certs =
        hardtokensession.findCertificatesInHardToken(tokensn);
    boolean allrevoked = true;
    if (!certs.isEmpty()) {
      Iterator<Certificate> j = certs.iterator();
      while (j.hasNext()) {
        Certificate cert = j.next();
        boolean isrevoked =
            certificatesession.isRevoked(
                CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        if (!isrevoked) {
          allrevoked = false;
        }
      }
    }
    return allrevoked;
  }

  /**
   * @param cacerts Certs
   */
  public void loadCACertificates(final CertificateView[] cacerts) {
    certificates = cacerts;
  }

  /**
   * @param serno SN
   * @param caId ID
   * @throws AuthorizationDeniedException Fail
   */
  public void loadCertificates(final BigInteger serno, final int caId)
      throws AuthorizationDeniedException {
    loadCertificates(
        serno, caSession.getCAInfo(administrator, caId).getSubjectDN());
  }

  /**
   * @param serno SN
   * @param issuerdn DN
   * @throws AuthorizationDeniedException Fail
   */
  public void loadCertificates(final BigInteger serno, final String issuerdn)
      throws AuthorizationDeniedException {
    if (!authorizationSession.isAuthorizedNoLogging(
        administrator, AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
      final String msg =
          INTRES.getLocalizedMessage(
              "authorization.notauthorizedtoresource",
              AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
              "Not authorized to view certificate.");
      throw new AuthorizationDeniedException(msg);
    }
    final CertificateDataWrapper cdw =
        certificatesession.getCertificateDataByIssuerAndSerno(issuerdn, serno);
    if (cdw != null) {
      final String username = cdw.getCertificateData().getUsername();
      if (endEntityAccessSession.findUser(administrator, username) != null) {
        final int endentityprofileid =
            endEntityAccessSession
                .findUser(administrator, username)
                .getEndEntityProfileId();
        endEntityAuthorization(
            administrator,
            endentityprofileid,
            AccessRulesConstants.VIEW_END_ENTITY,
            true);
      }
      certificates = new CertificateView[] {new CertificateView(cdw)};
    } else {
      certificates = null;
    }
  }

  /** @return the maximum size of the result from SQL select queries */
  public int getMaximumQueryRowCount() {
    GlobalCesecoreConfiguration globalConfiguration =
        (GlobalCesecoreConfiguration)
            globalConfigurationSession.getCachedConfiguration(
                GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
    return globalConfiguration.getMaximumQueryCount();
  }

  /**
   * @return num
   */
  public int getNumberOfCertificates() {
    int returnval = 0;
    if (certificates != null) {
      returnval = certificates.length;
    }
    return returnval;
  }


  /**
   * @param index index
   * @return view
   */
  public CertificateView getCertificate(final int index) {
    CertificateView returnval = null;
    if (certificates != null) {
      returnval = certificates[index];
    }
    return returnval;
  }

  /**
   * @return bool
   */
  public boolean authorizedToEditEndEntityProfiles() {
    return authorizationSession.isAuthorizedNoLogging(
        administrator, AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES);
  }

  /**
   * @param profileid ID
   * @return Bool
   */
  public boolean authorizedToEditUser(final int profileid) {
    return endEntityAuthorization(
        administrator, profileid, AccessRulesConstants.EDIT_END_ENTITY, false);
  }

  /**
   * @param profileid ID
   * @return bool
   */
  public boolean authorizedToViewHistory(final int profileid) {
    return endEntityAuthorization(
        administrator,
        profileid,
        AccessRulesConstants.VIEW_END_ENTITY_HISTORY,
        false);
  }

  /**
   * @param username name
   * @return bool
   * @throws AuthorizationDeniedException fail
   */
  public boolean authorizedToViewHardToken(final String username)
      throws AuthorizationDeniedException {
    int profileid =
        endEntityAccessSession
            .findUser(administrator, username)
            .getEndEntityProfileId();
    if (!endEntityAuthorization(
        administrator,
        profileid,
        AccessRulesConstants.HARDTOKEN_RIGHTS,
        false)) {
      throw new AuthorizationDeniedException();
    }
    if (!WebConfiguration.getHardTokenDiplaySensitiveInfo()) {
      return false;
    }
    return endEntityAuthorization(
        administrator,
        profileid,
        AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS,
        false);
  }

  /**
   * @param profileid ID
   * @return bool
   */
  public boolean authorizedToViewHardToken(final int profileid) {
    return endEntityAuthorization(
        administrator, profileid, AccessRulesConstants.HARDTOKEN_RIGHTS, false);
  }

  /**
   * @param username name
   * @return bool
   * @throws AuthorizationDeniedException fail
   */
  public boolean authorizedToRevokeCert(final String username)
      throws AuthorizationDeniedException {
    boolean returnval = false;
    EndEntityInformation data =
        endEntityAccessSession.findUser(administrator, username);
    if (data == null) {
      return false;
    }
    int profileid = data.getEndEntityProfileId();
    if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
      returnval =
          endEntityAuthorization(
              administrator,
              profileid,
              AccessRulesConstants.REVOKE_END_ENTITY,
              false);
    } else {
      returnval = true;
    }
    return returnval;
  }

  /**
   * @param cert Cert
   * @param username Name
   * @return bool
   * @throws AuthorizationDeniedException fail
   */
  public boolean keyRecoveryPossible(
      final Certificate cert, final String username)
      throws AuthorizationDeniedException {
    boolean returnval = true;
    returnval =
        authorizationSession.isAuthorizedNoLogging(
            administrator, AccessRulesConstants.REGULAR_KEYRECOVERY);
    if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
      EndEntityInformation data =
          endEntityAccessSession.findUser(administrator, username);
      if (data != null) {
        int profileid = data.getEndEntityProfileId();
        returnval =
            endEntityAuthorization(
                administrator,
                profileid,
                AccessRulesConstants.KEYRECOVERY_RIGHTS,
                false);
      } else {
        returnval = false;
      }
    }
    return returnval
        && keyrecoverysession.existsKeys(EJBUtil.wrap(cert))
        && !keyrecoverysession.isUserMarked(username);
  }

  /**
   * @param username Name
   * @param cert Cert
   * @throws AuthorizationDeniedException Fail
   * @throws ApprovalException Fail
   * @throws WaitingForApprovalException Fail
   * @throws CADoesntExistsException Fail
   */
  public void markForRecovery(final String username, final Certificate cert)
      throws AuthorizationDeniedException, ApprovalException,
          WaitingForApprovalException, CADoesntExistsException {
    boolean authorized = true;
    int endEntityProfileId =
        endEntityAccessSession
            .findUser(administrator, username)
            .getEndEntityProfileId();
    if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
      authorized =
          endEntityAuthorization(
              administrator,
              endEntityProfileId,
              AccessRulesConstants.KEYRECOVERY_RIGHTS,
              false);
    }
    if (authorized) {
      endEntityManagementSession.prepareForKeyRecovery(
          administrator, username, endEntityProfileId, cert);
    }
  }

  /**
   * @return Names
   */
  public String[] getCertificateProfileNames() {
    String[] dummy = {""};
    Collection<String> certprofilenames =
        ejbcawebbean.getAuthorizedEndEntityCertificateProfileNames().keySet();
    if (certprofilenames == null) {
      return new String[0];
    }
    return certprofilenames.toArray(dummy);
  }

  /**
   * @param certificateprofilename Name
   * @return ID
   */
  public int getCertificateProfileId(final String certificateprofilename) {
    return certificateProfileSession.getCertificateProfileId(
        certificateprofilename);
  }

  /**
   * @param certificateprofileid ID
   * @return Nmae
   */
  public String getCertificateProfileName(final int certificateprofileid) {
    return certificateProfileSession.getCertificateProfileName(
        certificateprofileid);
  }

  /**
   * @param parameter Param
   * @return Bool
   */
  public boolean getEndEntityParameter(final String parameter) {
    if (parameter == null) {
      return false;
    }
    return parameter.equals(EndEntityProfile.TRUE);
  }

  /**
   * Help function used to check end entity profile authorization.
   *
   * @param admin Admin
   * @param profileid ID
   * @param rights Rights
   * @param alog Log
   * @return Auth
   */
  public boolean endEntityAuthorization(
      final AuthenticationToken admin,
      final int profileid,
      final String rights,
      final boolean alog) {
    boolean returnval = false;
    if (alog) {
      returnval =
          authorizationSession.isAuthorized(
              admin,
              AccessRulesConstants.ENDENTITYPROFILEPREFIX
                  + Integer.toString(profileid)
                  + rights,
              AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    } else {
      returnval =
          authorizationSession.isAuthorizedNoLogging(
              admin,
              AccessRulesConstants.ENDENTITYPROFILEPREFIX
                  + Integer.toString(profileid)
                  + rights,
              AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    }
    return returnval;
  }

  /**
   * Help function used by edit end entity pages used to temporary save a
   * profile so things can be canceled later.
   *
   * @return Profile
   */
  public EndEntityProfile getTemporaryEndEntityProfile() {
    return this.temporaryEndEntityProfile;
  }

  /**
   * @param profile profile
   */
  public void setTemporaryEndEntityProfile(final EndEntityProfile profile) {
    this.temporaryEndEntityProfile = profile;
  }

  /**
   * @return session
   */
  UserDataSourceSession getUserDataSourceSession() {
    return userdatasourcesession;
  }

  /**
   * @return printers
   */
  public String[] listPrinters() {
    if (printerNames == null) {
      printerNames = org.ejbca.util.PrinterManager.listPrinters();
    }
    return printerNames;
  }

  /**
   * @param certificateData Cert
   * @return SN
   */
  public String getFormatedCertSN(final CertificateView certificateData) {

    String serialnumber = certificateData.getSerialNumber();
    if (StringUtils.equals(certificateData.getType(), "X.509")) {
      if ((serialnumber.length() % 2) != 0) {
        serialnumber = "0" + serialnumber;
      }

      final int max = 7;
      int octetChar = serialnumber.charAt(0) - '0';
      if (octetChar > max) {
        serialnumber = "00" + serialnumber;
      }
    }
    return serialnumber;
  }

  /**
   * Handle the combinations of AnyCA and default CA to get the correct
   * available CAs line.
   *
   * @param availableCasArray an array of CA Ids
   * @param defaultCa the CA Id of the selected default CA
   * @return the ;-seperated list of CA Ids
   */
  public String getAvailableCasString(
      final String[] availableCasArray, final String defaultCa) {
    final List<String> availableCasList = Arrays.asList(availableCasArray);
    final StringBuilder sb = new StringBuilder();
    if (availableCasList.contains(String.valueOf(SecConst.ALLCAS))
        || availableCasList.contains(defaultCa)) {
      // If the AnyCA or the default CA is selected we will just keep list of
      // selected CAs as is
      // (the admin might want to use AnyCA with additional selections for
      // awkward access control)
      for (final String current : availableCasList) {
        if (sb.length() > 0) {
          sb.append(EndEntityProfile.SPLITCHAR);
        }
        sb.append(current);
      }
    } else {
      // If AnyCA isn't selected and the not the default either we need to add
      // the default CA to the list of available CAs
      sb.append(defaultCa);
      for (final String current : availableCasList) {
        sb.append(EndEntityProfile.SPLITCHAR);
        sb.append(current);
      }
    }
    return sb.toString();
  }

  /**
   * Method that calculates the available CAs to an end entity. Used in add/edit
   * end entity pages. It calculates a set of available CAs as an intersection
   * of: - The administrator's authorized CAs, the end entity profile's
   * available CAs and the certificate profile's available CAs.
   *
   * @param endentityprofileid the EE profile of the end entity
   * @param endentityAccessRule Rule
   * @return a HashMap of CertificateProfileIds mapped to Lists if CA IDs. It
   *     returns a set of available CAs per end entity profile.
   */
  public Map<Integer, List<Integer>> getCasAvailableToEndEntity(
      final int endentityprofileid, final String endentityAccessRule) {
    final Map<Integer, List<Integer>> ret = new HashMap<>();
    // Create a TreeMap to get a sorted list.
    final TreeMap<CAInfo, Integer> sortedMap =
        new TreeMap<>(
            new Comparator<CAInfo>() {
              @Override
              public int compare(final CAInfo o1, final CAInfo o2) {
                return o1.getName().compareToIgnoreCase(o2.getName());
              }
            });
    // 1. Retrieve a list of all CA's the current user is authorized to
    for (CAInfo caInfo
        : caSession.getAuthorizedAndNonExternalCaInfos(administrator)) {
      sortedMap.put(caInfo, caInfo.getCAId());
    }
    final Collection<Integer> authorizedCas = sortedMap.values();
    // 2. Retrieve the list of CA's available to the end entity profile
    final EndEntityProfile endentityprofile =
        endEntityProfileSession.getEndEntityProfile(endentityprofileid);
    final List<Integer> casDefineInEndEntityProfile =
        new ArrayList<>(endentityprofile.getAvailableCAs());
    boolean allCasDefineInEndEntityProfile = false;
    if (casDefineInEndEntityProfile.contains(
        Integer.valueOf(SecConst.ALLCAS))) {
      allCasDefineInEndEntityProfile = true;
    }
    // 3. Next retrieve all certificate profiles defined in the end entity
    // profile
    for (final Integer certificateProfileId
        : endentityprofile.getAvailableCertificateProfileIds()) {
      final CertificateProfile certprofile =
          certificateProfileSession.getCertificateProfile(
              certificateProfileId.intValue());
      // 4. Retrieve all CAs defined in the current certificate profile
      final Collection<Integer> casDefinedInCertificateProfile;
      if (certprofile != null) {
        casDefinedInCertificateProfile = certprofile.getAvailableCAs();
      } else {
        casDefinedInCertificateProfile = new ArrayList<>();
      }
      // First make a clone of the full list of available CAs
      final List<Integer> authorizedCasClone = new ArrayList<>(authorizedCas);
      if (!casDefinedInCertificateProfile.contains(
          Integer.valueOf(CertificateProfile.ANYCA))) {
        // If ANYCA wasn't defined among the list from the cert profile, only
        // keep the intersection
        authorizedCasClone.retainAll(casDefinedInCertificateProfile);
      }
      if (!allCasDefineInEndEntityProfile) {
        // If ALL wasn't defined in the EE profile, only keep the intersection
        authorizedCasClone.retainAll(casDefineInEndEntityProfile);
      }
      ret.put(certificateProfileId, authorizedCasClone);
    }
    return ret;
  }

  // -------------------------------------------------------
  //         Import/Export  profiles related code
  // -------------------------------------------------------
  /**
   * @param request req
   * @param requestMap Map
   * @return Buffer
   * @throws IOException Fail
   * @throws FileUploadException Fail
   */
  public byte[] getfileBuffer(
      final HttpServletRequest request, final Map<String, String> requestMap)
      throws IOException, FileUploadException {
    final int siz = 60000;
    return getFileBuffer(request, requestMap, siz);
  }

  /**
   * @param request Req
   * @param requestMap Map
   * @param maxSize Max
   * @return Buffer
   * @throws IOException Fail
   * @throws FileUploadException Fail
   */
  public byte[] getFileBuffer(
      final HttpServletRequest request,
      final Map<String, String> requestMap,
      final int maxSize)
      throws IOException, FileUploadException {
    byte[] fileBuffer = null;
    if (ServletFileUpload.isMultipartContent(request)) {
      final DiskFileItemFactory diskFileItemFactory = new DiskFileItemFactory();
      diskFileItemFactory.setSizeThreshold(
          maxSize); // it makes no sense to write to a temporary file
      ServletFileUpload upload = new ServletFileUpload(diskFileItemFactory);
      upload.setSizeMax(maxSize);
      upload.setFileSizeMax(maxSize);
      final List<FileItem> items = upload.parseRequest(request);
      for (final FileItem item : items) {
        if (item.isFormField()) {
          final String fieldName = item.getFieldName();
          final String currentValue = requestMap.get(fieldName);
          if (currentValue != null) {
            requestMap.put(
                fieldName, currentValue + ";" + item.getString("UTF8"));
          } else {
            requestMap.put(fieldName, item.getString("UTF8"));
          }
        } else {
          importedProfileName = item.getName();
          final InputStream file = item.getInputStream();
          byte[] fileBufferTmp = FileTools.readInputStreamtoBuffer(file);
          if (fileBuffer == null && fileBufferTmp.length > 0) {
            fileBuffer = fileBufferTmp;
          }
        }
      }
    } else {
      final Set<String> keySet = request.getParameterMap().keySet();
      for (final String key : keySet) {
        requestMap.put(key, request.getParameter(key));
      }
    }

    return fileBuffer;
  }

  /**
   * @param filebuffer buffer
   * @return profiles
   */
  public String importProfilesFromZip(final byte[] filebuffer) {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">importProfiles(): "
              + importedProfileName
              + " - "
              + filebuffer.length
              + " bytes");
    }

    String retmsg = "";
    String faultXMLmsg = "";

    if (StringUtils.isEmpty(importedProfileName) || filebuffer.length == 0) {
      retmsg = "Error: No input file";
      LOG.error(retmsg);
      return retmsg;
    }

    int importedFiles = 0;
    int ignoredFiles = 0;
    int nrOfFiles = 0;
    try (ZipInputStream zis =
        new ZipInputStream(new ByteArrayInputStream(filebuffer))) {
      ZipEntry ze = zis.getNextEntry();
      if (ze == null) {
        // Print import message if the file header corresponds to an empty zip
        // archive
        if (Arrays.equals(
            Arrays.copyOfRange(filebuffer, 0, 4), new byte[] {80, 75, 5, 6})) {
          retmsg =
              getSuccessImportMessage(
                  importedProfileName, nrOfFiles, importedFiles, ignoredFiles);
          LOG.info(retmsg);
        } else {
          retmsg =
              "Error: Expected a zip file. '"
                  + importedProfileName
                  + "' is not a  zip file.";
          LOG.error(retmsg);
        }
        return retmsg;
      }

      do {
        nrOfFiles++;
        String filename = ze.getName();
        if (LOG.isDebugEnabled()) {
          LOG.debug("Importing file: " + filename);
        }

        if (ignoreFile(filename)) {
          ignoredFiles++;
          continue;
        }

        String profilename;
        filename = URLDecoder.decode(filename, "UTF-8");

        int index1 = filename.indexOf("_");
        int index2 = filename.lastIndexOf("-");
        int index3 = filename.lastIndexOf(".xml");
        profilename = filename.substring(index1 + 1, index2);
        int profileid = 0;
        try {
          profileid = Integer.parseInt(filename.substring(index2 + 1, index3));
        } catch (NumberFormatException e) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "NumberFormatException parsing certificate profile id: "
                    + e.getMessage());
          }
          ignoredFiles++;
          continue;
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Extracted profile name '"
                  + profilename
                  + "' and profile ID '"
                  + profileid
                  + "'");
        }

        if (ignoreProfile(filename, profilename, profileid)) {
          ignoredFiles++;
          continue;
        }

        if (endEntityProfileSession.getEndEntityProfile(profileid) != null) {
          int newprofileid =
              endEntityProfileSession.findFreeEndEntityProfileId();
          LOG.warn(
              "Entity profileid '"
                  + profileid
                  + "' already exist in database. Using "
                  + newprofileid
                  + " instead.");
          profileid = newprofileid;
        }
        final int siz = 102400; // 100k
        byte[] filebytes = new byte[siz];
        int i = 0;
        while ((zis.available() == 1) && (i < filebytes.length)) {
          filebytes[i++] = (byte) zis.read();
        }

        EndEntityProfile eprofile =
            getEEProfileFromByteArray(profilename, filebytes);
        if (eprofile == null) {
          String msg =
              "Faulty XML file '"
                  + filename
                  + "'. Failed to read End Entity Profile.";
          LOG.info(msg + " Ignoring file.");
          ignoredFiles++;
          faultXMLmsg += filename + ", ";
          continue;
        }

        endEntityProfileSession.addEndEntityProfile(
            administrator, profilename, eprofile);
        importedFiles++;
        LOG.info("Added EndEntity profile: " + profilename);
        ze = zis.getNextEntry();
      } while (ze != null);
      zis.closeEntry();
    } catch (UnsupportedEncodingException e) {
      retmsg = "Error: UTF-8 was not a known character encoding.";
      LOG.error(retmsg, e);
      return retmsg;
    } catch (IOException e) {
      LOG.error(e);
      retmsg = "Error: " + e.getLocalizedMessage();
      return retmsg;
    } catch (AuthorizationDeniedException e) {
      LOG.error(e);
      retmsg = "Error: " + e.getLocalizedMessage();
      return retmsg;
    } catch (EndEntityProfileExistsException e) {
      LOG.error(e);
      retmsg = "Error: " + e.getLocalizedMessage();
      return retmsg;
    }

    if (StringUtils.isNotEmpty(faultXMLmsg)) {
      faultXMLmsg = faultXMLmsg.substring(0, faultXMLmsg.length() - 2);
      retmsg =
          "Faulty XML files: "
              + faultXMLmsg
              + ". "
              + importedFiles
              + " profiles were imported.";
    } else {
      retmsg =
          getSuccessImportMessage(
              importedProfileName, nrOfFiles, importedFiles, ignoredFiles);
    }
    LOG.info(retmsg);

    return retmsg;
  }

  private String getSuccessImportMessage(
      final String fileName,
      final int nrOfFiles,
      final int importedFiles,
      final int ignoredFiles) {
    return importedProfileName
        + " contained "
        + nrOfFiles
        + " files. "
        + importedFiles
        + " EndEntity Profiles were imported and "
        + ignoredFiles
        + " files  were ignored.";
  }

  /**
   * @param defaulthardtokenissuer Issuer
   * @param values Values
   * @return issuers
   */
  public String getAvailableHardTokenIssuers(
      final String defaulthardtokenissuer, final String[] values) {
    String availablehardtokenissuers = defaulthardtokenissuer;
    if (values != null) {
      for (int i = 0; i < values.length; i++) {
        if (!values[i].equals(defaulthardtokenissuer)) {
          availablehardtokenissuers += EndEntityProfile.SPLITCHAR + values[i];
        }
      }
    }
    return availablehardtokenissuers;
  }

  /**
   * @param defaulttokentype def
   * @param values vals
   * @return types
   */
  public String getAvailableTokenTypes(
      final String defaulttokentype, final String[] values) {
    String availabletokentypes = defaulttokentype;
    if (values != null) {
      for (int i = 0; i < values.length; i++) {
        if (!values[i].equals(defaulttokentype)) {
          availabletokentypes += EndEntityProfile.SPLITCHAR + values[i];
        }
      }
    }
    return availabletokentypes;
  }

  /**
   * Handle the combinations of available cert profiles and default cert profile
   * to get the correct available cert profiles line.
   *
   * @param defaultcertprof the Id of the selected default cert profile
   * @param values an array of cert profile Ids
   * @return the ;-seperated list of cert profile Ids
   */
  public String getAvailableCertProfiles(
      final String defaultcertprof, final String[] values) {
    String availablecertprofiles = defaultcertprof;
    if (values != null) {
      for (int i = 0; i < values.length; i++) {
        if (!values[i].equals(defaultcertprof)) {
          availablecertprofiles += EndEntityProfile.SPLITCHAR + values[i];
        }
      }
    }
    return availablecertprofiles;
  }

  /**
   * @param validationRegex regex
   * @return val
   */
  public LinkedHashMap<String, Serializable> getValidationFromRegexp(
      final String validationRegex) {
    // We must accept an empty value in case the user has Javascript turned
    // off and has to update the page before the text field appears
    final String regex = StringUtils.defaultString(validationRegex);
    LinkedHashMap<String, Serializable> validation = new LinkedHashMap<>();
    validation.put(RegexFieldValidator.class.getName(), regex);
    return validation;
  }
  /**
   * @param sender sender
   * @param rcpt recp
   * @param subject subj
   * @param msg message
   * @param val value
   * @return notif
   */
  public UserNotification getNotificationForDelete(
      final String sender,
      final String rcpt,
      final String subject,
      final String msg,
      final String[] val) {
    String events = null;
    if (val != null) {
      for (String v : val) {
        if (events == null) {
          events = v;
        } else {
          events = events + ";" + v;
        }
      }
    }
    return new UserNotification(sender, rcpt, subject, msg, events);
  }

  /**
   * @param sender sender
   * @param orcpt recp
   * @param subject subj
   * @param msg message
   * @param val value
   * @return notif
   */
  public UserNotification getNotificationForAdd(
      final String sender,
      final String orcpt,
      final String subject,
      final String msg,
      final String[] val) {
    String rcpt = orcpt;
    UserNotification not = new UserNotification();
    not.setNotificationSender(sender);
    not.setNotificationSubject(subject);
    not.setNotificationMessage(msg);
    if ((rcpt == null) || (rcpt.length() == 0)) {
      // Default value if nothing is entered is users email address
      rcpt = UserNotification.RCPT_USER;
    }
    not.setNotificationRecipient(rcpt);
    String events = null;
    for (String v : val) {
      if (events == null) {
        events = v;
      } else {
        events = events + ";" + v;
      }
    }
    not.setNotificationEvents(events);
    return not;
  }

  private EndEntityProfile getEEProfileFromByteArray(
      final String profilename, final byte[] profileBytes) {
    ByteArrayInputStream is = new ByteArrayInputStream(profileBytes);
    EndEntityProfile eprofile = new EndEntityProfile();
    try {
      final SecureXMLDecoder decoder = new SecureXMLDecoder(is);

      // Add end entity profile
      Object data = null;
      try {
        data = decoder.readObject();
      } catch (IOException e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Error parsing certificate profile data: " + e.getMessage());
        }
        return null;
      } finally {
        decoder.close();
      }
      eprofile.loadData(data);

      // Translate cert profile ids that have changed after import
      String availableCertProfiles = "";
      String defaultCertProfile =
          eprofile.getValue(EndEntityProfile.DEFAULTCERTPROFILE, 0);
      for (String currentCertProfile
          : eprofile.getAvailableCertificateProfileIdsAsStrings()) {
        Integer currentCertProfileId = Integer.parseInt(currentCertProfile);

        if (certificateProfileSession.getCertificateProfile(
                    currentCertProfileId)
                != null
            || CertificateProfileConstants.isFixedCertificateProfile(
                currentCertProfileId)) {
          availableCertProfiles +=
              (availableCertProfiles.equals("") ? "" : ";")
                  + currentCertProfile;
        } else {
          LOG.warn(
              "End Entity Profile '"
                  + profilename
                  + "' references certificate profile "
                  + currentCertProfile
                  + " that does not exist.");
          if (currentCertProfile.equals(defaultCertProfile)) {
            defaultCertProfile = "";
          }
        }
      }
      if (availableCertProfiles.equals("")) {
        LOG.warn(
            "End Entity Profile only references certificate profile(s) that"
                + " does not exist. Using ENDUSER profile.");
        availableCertProfiles =
            "1"; // At least make sure the default profile is available
      }
      if (defaultCertProfile.equals("")) {
        defaultCertProfile =
            availableCertProfiles
                .split(";")[
                0]; // Use first available profile from list as default if
                    // original default was missing
      }
      eprofile.setValue(
          EndEntityProfile.AVAILCERTPROFILES, 0, availableCertProfiles);
      eprofile.setValue(
          EndEntityProfile.DEFAULTCERTPROFILE, 0, defaultCertProfile);
      // Remove any unknown CA and break if none is left
      String defaultCA = eprofile.getValue(EndEntityProfile.DEFAULTCA, 0);
      String availableCAs = eprofile.getValue(EndEntityProfile.AVAILCAS, 0);
      List<String> cas = Arrays.asList(availableCAs.split(";"));
      availableCAs = "";
      for (String currentCA : cas) {
        Integer currentCAInt = Integer.parseInt(currentCA);
        // The constant ALLCAS will not be searched for among available CAs
        if (currentCAInt.intValue() != SecConst.ALLCAS) {
          if (caSession.existsCa(currentCAInt)) {
            availableCAs +=
                (availableCAs.equals("") ? "" : ";")
                    + currentCA; // No Exception means CA exists
          } else {
            LOG.warn(
                "CA with id "
                    + currentCA
                    + " was not found and will not be used in end entity"
                    + " profile '"
                    + profilename
                    + "'.");
            if (defaultCA.equals(currentCA)) {
              defaultCA = "";
            }
          }
        }
      }
      if (availableCAs.equals("")) {
        LOG.error(
            "No CAs left in end entity profile '"
                + profilename
                + "'. Using ALLCAs.");
        availableCAs = Integer.toString(SecConst.ALLCAS);
      }
      if (defaultCA.equals("")) {
        defaultCA = availableCAs.split(";")[0]; // Use first available
        LOG.warn(
            "Changing default CA in end entity profile '"
                + profilename
                + "' to "
                + defaultCA
                + ".");
      }
      eprofile.setValue(EndEntityProfile.AVAILCAS, 0, availableCAs);
      eprofile.setDefaultCA(Integer.parseInt(defaultCA));
    } finally {
      try {
        is.close();
      } catch (IOException e) {
        throw new IllegalStateException(
            "Unknown IOException was caught when closing stream", e);
      }
    }
    return eprofile;
  }

  private boolean ignoreFile(final String filename) {
    final int len = 4;
    if (filename.lastIndexOf(".xml") != (filename.length() - len)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(filename + " is not an XML file. IGNORED");
      }
      return true;
    }

    if (filename.indexOf("_") < 0
        || filename.lastIndexOf("-") < 0
        || (filename.indexOf("entityprofile_") < 0)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            filename
                + " is not in the expected format. The file name should look"
                + " like: entityprofile_<profile name>-<profile id>.xml."
                + " IGNORED");
      }
      return true;
    }
    return false;
  }

  private boolean ignoreProfile(
      final String filename, final String profilename, final int profileid) {
    // We don't add the fixed profiles, EJBCA handles those automagically
    if (profileid == EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
      LOG.info(filename + " contains a fixed profile. IGNORED");
      return true;
    }

    // Check if the profiles already exist, and change the name and id if
    // already taken
    if (endEntityProfileSession.getEndEntityProfile(profilename) != null) {
      LOG.info(
          "Entity profile '"
              + profilename
              + "' already exist in database. IGNORED");
      return true;
    }

    return false;
  }
}
