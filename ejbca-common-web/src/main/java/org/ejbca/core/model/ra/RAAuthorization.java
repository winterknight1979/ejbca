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

package org.ejbca.core.model.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * A class that looks up the which CA:s or end entity profiles the administrator
 * is authorized to view.
 *
 * @version $Id: RAAuthorization.java 28563 2018-03-27 14:16:48Z mikekushner $
 */
public class RAAuthorization implements Serializable {

  private static final long serialVersionUID = -3195162814492440326L;
  /** Param. */
  private String authendentityprofilestring = null;
  /** Param. */
  private TreeMap<String, String> authprofilenames = null;
  /** Param. */
  private List<String> authprofileswithmissingcas = null;
  /** Param. */
  private final AuthenticationToken admin;
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession;
  /** Param. */
  private final GlobalConfigurationSession globalConfigurationSession;
  /** Param. */
  private final CaSession caSession;
  /** Param. */
  private final EndEntityProfileSession endEntityProfileSession;

  /**
   * Creates a new instance of RAAuthorization.
   *
   * @param anadmin Admin
   * @param aglobalConfigurationSession session
   * @param anauthorizationSession auth session
   * @param acaSession CA sessiom
   * @param anendEntityProfileSession profile session
   */
  public RAAuthorization(
      final AuthenticationToken anadmin,
      final GlobalConfigurationSession aglobalConfigurationSession,
      final AuthorizationSessionLocal anauthorizationSession,
      final CaSession acaSession,
      final EndEntityProfileSession anendEntityProfileSession) {
    this.admin = anadmin;
    this.globalConfigurationSession = aglobalConfigurationSession;
    this.authorizationSession = anauthorizationSession;
    this.caSession = acaSession;
    this.endEntityProfileSession = anendEntityProfileSession;
  }

  private boolean isAuthorizedNoLogging(
      final AuthenticationToken authenticationToken,
      final String... resources) {
    return authorizationSession.isAuthorizedNoLogging(admin, resources);
  }

  /**
   * Method that checks the administrators CA privileges and returns a string
   * that should be used in where clause of userdata SQL queries.
   *
   * @return a string of administrators CA privileges that should be used in the
   *     where clause of SQL queries.
   */
  public String getCAAuthorizationString() {
    String authcastring = "";
    final List<Integer> authorizedCaIds = caSession.getAuthorizedCaIds(admin);
    if (authorizedCaIds.isEmpty()) {
      // Setup a condition that can never be true if there are no authorized CAs
      authcastring = "(0=1)";
    } else {
      for (final Integer caId : caSession.getAuthorizedCaIds(admin)) {
        if (authcastring.equals("")) {
          authcastring = " cAId = " + caId.toString();
        } else {
          authcastring = authcastring + " OR cAId = " + caId.toString();
        }
      }
      if (!authcastring.isEmpty()) {
        authcastring = "( " + authcastring + " )";
      }
    }
    return authcastring;
  }

  /**
   * @param endentityAccessRule Rule
   * @return a string of end entity profile privileges that should be used in
   *     the where clause of SQL queries, or null if no authorized end entity
   *     profiles exist.
   * @throws AuthorizationDeniedException if the current requester isn't
   *     authorized to query for approvals
   */
  public String getEndEntityProfileAuthorizationString(
      final String endentityAccessRule) throws AuthorizationDeniedException {
    boolean authorizedToApproveCAActions =
        false; // i.e approvals with endentityprofile
               // ApprovalDataVO.ANY_ENDENTITYPROFILE
    boolean authorizedToApproveRAActions =
        false; // i.e approvals with endentityprofile not
               // ApprovalDataVO.ANY_ENDENTITYPROFILE

    authorizedToApproveCAActions =
        isAuthorizedNoLogging(
            admin, AccessRulesConstants.REGULAR_APPROVECAACTION);

    authorizedToApproveRAActions =
        isAuthorizedNoLogging(
            admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY);

    if (!authorizedToApproveCAActions && !authorizedToApproveRAActions) {
      throw new AuthorizationDeniedException(
          "Not authorized to query for approvals: "
              + authorizedToApproveCAActions
              + ", "
              + authorizedToApproveRAActions);
    }

    String endentityauth = null;
    GlobalConfiguration globalconfiguration =
        (GlobalConfiguration)
            globalConfigurationSession.getCachedConfiguration(
                GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
      endentityauth =
          getEndEntityProfileAuthorizationString(true, endentityAccessRule);
      if (authorizedToApproveCAActions && authorizedToApproveRAActions) {
        endentityauth =
            getEndEntityProfileAuthorizationString(true, endentityAccessRule);
        if (endentityauth != null) {
          endentityauth =
              "("
                  + getEndEntityProfileAuthorizationString(
                      false, endentityAccessRule)
                  + " OR endEntityProfileId="
                  + ApprovalDataVO.ANY_ENDENTITYPROFILE
                  + " ) ";
        }
      } else if (authorizedToApproveCAActions) {
        endentityauth =
            " endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE;
      } else if (authorizedToApproveRAActions) {
        endentityauth =
            getEndEntityProfileAuthorizationString(true, endentityAccessRule);
      }
    }
    return endentityauth == null ? endentityauth : endentityauth.trim();
  }

  /**
   * Method that checks the administrators end entity profile privileges and
   * returns a string that should be used in where clause of userdata SQL
   * queries.
   *
   * @param includeparanteses bool
   * @param endentityAccessRule Rle
   * @return a string of end entity profile privileges that should be used in
   *     the where clause of SQL queries, or null if no authorized end entity
   *     profiles exist.
   */
  public String getEndEntityProfileAuthorizationString(
      final boolean includeparanteses, final String endentityAccessRule) {
    if (authendentityprofilestring == null) {
      final List<Integer> profileIds =
          new ArrayList<Integer>(
              endEntityProfileSession.getAuthorizedEndEntityProfileIds(
                  admin, endentityAccessRule));
      if (!endentityAccessRule.startsWith(
          AccessRulesConstants.VIEW_END_ENTITY)) {
        // Additionally require view access to all the profiles
        for (final Integer profileid : new ArrayList<Integer>(profileIds)) {
          if (!isAuthorizedNoLogging(
              admin,
              AccessRulesConstants.ENDENTITYPROFILEPREFIX
                  + profileid
                  + AccessRulesConstants.VIEW_END_ENTITY)) {
            profileIds.remove(profileid);
          }
        }
      }
      for (final int profileId : profileIds) {
        if (authendentityprofilestring == null) {
          authendentityprofilestring = " endEntityProfileId = " + profileId;
        } else {
          authendentityprofilestring =
              authendentityprofilestring
                  + " OR endEntityProfileId = "
                  + profileId;
        }
      }
      if (authendentityprofilestring != null && includeparanteses) {
        authendentityprofilestring = "( " + authendentityprofilestring + " )";
      }
    }
    return authendentityprofilestring;
  }

  /**
   * @param endentityAccessRule Rule
   * @return Map of names
   */
  public TreeMap<String, String> getAuthorizedEndEntityProfileNames(
      final String endentityAccessRule) {
    if (authprofilenames == null) {
      authprofilenames =
          new TreeMap<String, String>(
              new Comparator<String>() {
                @Override
                public int compare(final String o1, final String o2) {
                  int result = o1.compareToIgnoreCase(o2);
                  if (result == 0) {
                    result = o1.compareTo(o2);
                  }
                  return result;
                }
              });
      final Map<Integer, String> idtonamemap =
          endEntityProfileSession.getEndEntityProfileIdToNameMap();
      for (final Integer id
          : endEntityProfileSession.getAuthorizedEndEntityProfileIds(
              admin, endentityAccessRule)) {
        authprofilenames.put(idtonamemap.get(id), String.valueOf(id));
      }
    }
    return authprofilenames;
  }

  /**
   * @return Profiles
   */
  public List<String> getViewAuthorizedEndEntityProfilesWithMissingCAs() {
    if (authprofileswithmissingcas == null) {
      authprofileswithmissingcas = new ArrayList<String>();
      final List<Integer> entries =
          endEntityProfileSession
              .getAuthorizedEndEntityProfileIdsWithMissingCAs(admin);
      for (final Integer entry : entries) {
        authprofileswithmissingcas.add(String.valueOf(entry));
      }
    }
    return authprofileswithmissingcas;
  }

  /** Clear. */
  public void clear() {
    authendentityprofilestring = null;
    authprofilenames = null;
    authprofileswithmissingcas = null;
  }
}
