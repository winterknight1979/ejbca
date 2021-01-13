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

package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;

/**
 * A java bean handling the interface between EJBCA hard token module and JSP
 * pages.
 *
 * @version $Id: HardTokenInterfaceBean.java 27816 2018-01-09 16:19:36Z samuellb
 *     $
 */
public class HardTokenInterfaceBean implements Serializable {

  private static final long serialVersionUID = -3930279705572942527L;
  /** Param. */
  private HardTokenSession hardtokensession;
  /** Param. */
  private KeyRecoverySession keyrecoverysession;
  /** Param. */
  private HardTokenBatchJobSession hardtokenbatchsession;
  /** Param. */
  private RoleSessionLocal roleSession;
  /** Param. */
  private AuthenticationToken admin;
  /** Param. */
  private boolean initialized = false;
  /** Param. */
  private HardTokenView[] result;

  /** Param. */
  @SuppressWarnings("deprecation")
  private HardTokenProfileDataHandler hardtokenprofiledatahandler;

  /** Creates new LogInterfaceBean. */
  public HardTokenInterfaceBean() { }

  /**
   * Method that initialized the bean.
   *
   * @param request is a reference to the http request.
   * @param ejbcawebbean Bean
   * @throws Exception Fail
   */
  @SuppressWarnings("deprecation")
  public void initialize(
      final HttpServletRequest request, final EjbcaWebBean ejbcawebbean)
      throws Exception {
    if (!initialized) {
      admin = ejbcawebbean.getAdminObject();
      EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
      hardtokensession = ejbLocalHelper.getHardTokenSession();
      hardtokenbatchsession = ejbLocalHelper.getHardTokenBatchJobSession();
      AuthorizationSessionLocal authorizationSession =
          ejbLocalHelper.getAuthorizationSession();
      EndEntityManagementSessionLocal endEntityManagementSession =
          ejbLocalHelper.getEndEntityManagementSession();
      CertificateProfileSession certificateProfileSession =
          ejbLocalHelper.getCertificateProfileSession();
      keyrecoverysession = ejbLocalHelper.getKeyRecoverySession();
      CaSessionLocal caSession = ejbLocalHelper.getCaSession();
      roleSession = new EjbLocalHelper().getRoleSession();
      initialized = true;
      this.hardtokenprofiledatahandler =
          new HardTokenProfileDataHandler(
              admin,
              hardtokensession,
              certificateProfileSession,
              authorizationSession,
              endEntityManagementSession,
              caSession);
    }
  }

  /**
   * Returns the first found hard token for the given username.
   *
   * @param username User
   * @param includePUK PUK
   * @return View
   */
  public HardTokenView getHardTokenViewWithUsername(
      final String username, final boolean includePUK) {
    this.result = null;
    Collection<HardTokenInformation> res =
        hardtokensession.getHardTokens(admin, username, includePUK);
    Iterator<HardTokenInformation> iter = res.iterator();
    if (res.size() > 0) {
      this.result = new HardTokenView[res.size()];
      for (int i = 0; iter.hasNext(); i++) {
        this.result[i] = new HardTokenView(iter.next());
      }
      if (this.result != null && this.result.length > 0) {
        return this.result[0];
      }
    }
    return null;
  }

  /**
   * @param username User
   * @param index Idx
   * @param includePUK Bool
   * @return View
   */
  public HardTokenView getHardTokenViewWithIndex(
      final String username, final int index, final boolean includePUK) {
    HardTokenView returnval = null;
    if (result == null) {
      getHardTokenViewWithUsername(username, includePUK);
    }
    if (result != null) {
      if (index < result.length) {
        returnval = result[index];
      }
    }
    return returnval;
  }

  /**
   * @return Cache
   */
  public int getHardTokensInCache() {
    int returnval = 0;
    if (result != null) {
      returnval = result.length;
    }
    return returnval;
  }

  /**
   * @param tokensn SN
   * @param includePUK bool
   * @return View
   * @throws AuthorizationDeniedException Fail
   */
  public HardTokenView getHardTokenView(
      final String tokensn, final boolean includePUK)
      throws AuthorizationDeniedException {
    HardTokenView returnval = null;
    this.result = null;
    HardTokenInformation token =
        hardtokensession.getHardToken(admin, tokensn, includePUK);
    if (token != null) {
      returnval = new HardTokenView(token);
    }
    return returnval;
  }

  /**
   * @return Aliases
   */
  public String[] getHardTokenIssuerAliases() {
    return hardtokensession
        .getHardTokenIssuers(admin)
        .keySet()
        .toArray(new String[0]);
  }

  /**
   * Returns the alias from id.
   *
   * @param id ID
   * @return Alias
   */
  public String getHardTokenIssuerAlias(final int id) {
    return hardtokensession.getHardTokenIssuerAlias(id);
  }

  /**
   * @param alias ALias
   * @return ID
   */
  public int getHardTokenIssuerId(final String alias) {
    return hardtokensession.getHardTokenIssuerId(alias);
  }

  /**
   * @param alias Alias
   * @return Info
   */
  public HardTokenIssuerInformation getHardTokenIssuerInformation(
      final String alias) {
    return hardtokensession.getHardTokenIssuerInformation(alias);
  }

  /**
   * @param id ID
   * @return INdo
   */
  public HardTokenIssuerInformation getHardTokenIssuerInformation(
      final int id) {
    return hardtokensession.getHardTokenIssuerInformation(id);
  }

  /**
   * @return MAp
   */
  public Map<Integer, String> getRoleIdToNameMap() {
    final HashMap<Integer, String> roleIdToNameMap = new HashMap<>();
    for (final Role role : roleSession.getAuthorizedRoles(admin)) {
      roleIdToNameMap.put(role.getRoleId(), role.getRoleNameFull());
    }
    return roleIdToNameMap;
  }

  /**
   * @param profileId ID
   * @return Name
   */
  public String getHardTokenProfileName(final int profileId) {
    return hardtokensession.getHardTokenProfileName(profileId);
  }

  /**
   * @return Roles
   */
  public List<Role> getHardTokenIssuingRoles() {
    return roleSession.getAuthorizedRolesWithAccessToResource(
        admin, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS);
  }

  /**
   * @param alias Alias
   * @param roleId ID
   * @throws HardTokenIssuerExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void addHardTokenIssuer(final String alias, final int roleId)
      throws HardTokenIssuerExistsException, AuthorizationDeniedException {
    for (final Role role : getHardTokenIssuingRoles()) {
      if (role.getRoleId() == roleId) {
        if (!hardtokensession.addHardTokenIssuer(
            admin, alias, roleId, new HardTokenIssuer())) {
          throw new HardTokenIssuerExistsException();
        }
      }
    }
  }

  /**
   * @param alias Alias
   * @param hardtokenissuer Issuer
   * @throws HardTokenIssuerDoesntExistsException Fail
   * @throws AuthorizationDeniedException FAil
   */

  public void changeHardTokenIssuer(
      final String alias, final HardTokenIssuer hardtokenissuer)
      throws HardTokenIssuerDoesntExistsException,
          AuthorizationDeniedException {
    if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, alias)) {
      if (!hardtokensession.changeHardTokenIssuer(
          admin, alias, hardtokenissuer)) {
        throw new HardTokenIssuerDoesntExistsException();
      }
    }
  }

  /**
   * Returns false if profile is used by any user or in authorization rules.
   *
   * @param alias Alias
   * @return Issuer
   * @throws AuthorizationDeniedException Fail
   */
  public boolean removeHardTokenIssuer(final String alias)
      throws AuthorizationDeniedException {
    boolean issuerused = false;
    if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, alias)) {
      int issuerid = hardtokensession.getHardTokenIssuerId(alias);
      // Check if any users or authorization rule use the profile.
      issuerused = hardtokenbatchsession.checkForHardTokenIssuerId(issuerid);
      if (!issuerused) {
        hardtokensession.removeHardTokenIssuer(admin, alias);
      }
    }
    return !issuerused;
  }

  /**
   * @param oldalias old
   * @param newalias new
   * @param newRoleId ID
   * @throws HardTokenIssuerExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void renameHardTokenIssuer(
      final String oldalias, final String newalias, final int newRoleId)
      throws HardTokenIssuerExistsException, AuthorizationDeniedException {
    if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, oldalias)) {
      if (!hardtokensession.renameHardTokenIssuer(
          admin, oldalias, newalias, newRoleId)) {
        throw new HardTokenIssuerExistsException();
      }
    }
  }

  /**
   * @param oldalias old
   * @param newalias new
   * @param newRoleId ID
   * @throws HardTokenIssuerExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void cloneHardTokenIssuer(
      final String oldalias, final String newalias, final int newRoleId)
      throws HardTokenIssuerExistsException, AuthorizationDeniedException {
    if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, oldalias)) {
      if (!hardtokensession.cloneHardTokenIssuer(
          admin, oldalias, newalias, newRoleId)) {
        throw new HardTokenIssuerExistsException();
      }
    }
  }

  /**
   * Method that checks if a token is key recoverable and also check if the
   * administrator is authorized to the action.
   *
   * @param tokensn SN
   * @param username Iser
   * @param rabean Bean
   * @return bool
   * @throws Exception fail
   */
  public boolean isTokenKeyRecoverable(
      final String tokensn, final String username, final RAInterfaceBean rabean)
      throws Exception {
    boolean retval = false;
    X509Certificate keyRecCert = null;
    for (final Certificate cert
        : hardtokensession.findCertificatesInHardToken(tokensn)) {
      final X509Certificate x509cert = (X509Certificate) cert;
      if (keyrecoverysession.existsKeys(EJBTools.wrap(x509cert))) {
        keyRecCert = x509cert;
      }
    }
    if (keyRecCert != null) {
      retval = rabean.keyRecoveryPossible(keyRecCert, username);
    }
    return retval;
  }

  /**
   * @param tokensn Token
   * @param username User
   * @param rabean Bean
   * @throws Exception Fail
   */
  public void markTokenForKeyRecovery(
      final String tokensn, final String username, final RAInterfaceBean rabean)
      throws Exception {
    for (final Certificate cert
        : hardtokensession.findCertificatesInHardToken(tokensn)) {
      final X509Certificate x509cert = (X509Certificate) cert;
      if (keyrecoverysession.existsKeys(EJBTools.wrap(x509cert))) {
        rabean.markForRecovery(username, x509cert);
      }
    }
  }

  /**
   * @return Handler
   */
  @SuppressWarnings("deprecation")
  public HardTokenProfileDataHandler getHardTokenProfileDataHandler() {
    return hardtokenprofiledatahandler;
  }
}
