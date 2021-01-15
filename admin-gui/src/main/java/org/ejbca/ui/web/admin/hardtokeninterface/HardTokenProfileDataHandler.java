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
import java.util.HashMap;
import java.util.HashSet;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.util.Base64PutHashMap;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;

/**
 * A class handling the hardtoken profile data.
 *
 * @version $Id: HardTokenProfileDataHandler.java 28844 2018-05-04 08:31:02Z
 *     samuellb $
 */
@Deprecated
public class HardTokenProfileDataHandler implements Serializable {

  private static final long serialVersionUID = -2864964753767713852L;

  /** Param. */
  private final HardTokenSession hardtokensession;
  /** Param. */
  private final AuthorizationSessionLocal authorizationSession;
  /** Param. */
  private final CertificateProfileSession certificateProfileSession;
  /** Param. */
  private final EndEntityManagementSessionLocal endEntityManagementSession;
  /** Param. */
  private final CaSession caSession;
  /** Param. */
  private final AuthenticationToken administrator;

  /**
   * Creates a new instance of HardTokenProfileDataHandler.
   *
   * @param anadministrator Admin
   * @param ahardtokensession Session
   * @param acertificatesession Session
   * @param anauthorizationSession Session
   * @param anendEntityManagementSession Session
   * @param acaSession Session
   */
  public HardTokenProfileDataHandler(
      final AuthenticationToken anadministrator,
      final HardTokenSession ahardtokensession,
      final CertificateProfileSession acertificatesession,
      final AuthorizationSessionLocal anauthorizationSession,
      final EndEntityManagementSessionLocal anendEntityManagementSession,
      final CaSession acaSession) {
    this.hardtokensession = ahardtokensession;
    this.authorizationSession = anauthorizationSession;
    this.certificateProfileSession = acertificatesession;
    this.endEntityManagementSession = anendEntityManagementSession;
    this.caSession = acaSession;
    this.administrator = anadministrator;
  }

  /**
   * Method to add a hard token profile.
   *
   * @param name NAme
   * @param profile Peofile
   * @return false, if the profile have a bad XML encoding.
   * @throws HardTokenProfileExistsException if profile already exists
   * @throws AuthorizationDeniedException fail
   */
  public boolean addHardTokenProfile(
      final String name, final HardTokenProfile profile)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    boolean success = false;
    if (authorizedToProfile(profile, true)) {
      if (checkXMLEncoding(profile)) {
        hardtokensession.addHardTokenProfile(administrator, name, profile);
        success = true;
      }

    } else {
      throw new AuthorizationDeniedException(
          "Not authorized to add hard token profile");
    }
    return success;
  }

  /**
   * Method to change a hard token profile.
   *
   * @param name Name
   * @param profile Profile
   * @return false, if the profile have a bad XML encoding.
   * @throws AuthorizationDeniedException fail
   */
  public boolean changeHardTokenProfile(
      final String name, final HardTokenProfile profile)
      throws AuthorizationDeniedException {
    boolean success = false;
    if (authorizedToProfile(profile, true)) {
      if (checkXMLEncoding(profile)) {
        hardtokensession.changeHardTokenProfile(administrator, name, profile);
        success = true;
      }
    } else {
      throw new AuthorizationDeniedException(
          "Not authorized to edit hard token profile");
    }
    return success;
  }

  /**
   * Method to remove a hard token profile, returns true if deletion failed.
   *
   * @param name Name
   * @return Ptofile
   * @throws AuthorizationDeniedException fail
   */
  public boolean removeHardTokenProfile(final String name)
      throws AuthorizationDeniedException {
    boolean returnval = true;

    int profileid = getHardTokenProfileId(name);

    if (endEntityManagementSession.checkForHardTokenProfileId(profileid)) {
      return true;
    }
    if (hardtokensession.existsHardTokenProfileInHardTokenIssuer(profileid)) {
      return true;
    }
    if (authorizedToProfileName(name, true)) {
      hardtokensession.removeHardTokenProfile(administrator, name);
      returnval = false;
    } else {
      throw new AuthorizationDeniedException(
          "Not authorized to remove hard token profile");
    }
    return returnval;
  }

  /**
   * Metod to rename a hard token profile.
   *
   * @param oldname Name
   * @param newname Profile
   * @throws HardTokenProfileExistsException FGail
   * @throws AuthorizationDeniedException Fail
   */
  public void renameHardTokenProfile(final String oldname, final String newname)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    if (authorizedToProfileName(oldname, true)) {
      hardtokensession.renameHardTokenProfile(administrator, oldname, newname);
    } else {
      throw new AuthorizationDeniedException(
          "Not authorized to rename hard token profile");
    }
  }

  /**
   * @param originalname Old
   * @param newname New
   * @throws HardTokenProfileExistsException Fail
   * @throws AuthorizationDeniedException Fail
   */
  public void cloneHardTokenProfile(
      final String originalname, final String newname)
      throws HardTokenProfileExistsException, AuthorizationDeniedException {
    if (authorizedToProfileName(originalname, false)) {
      hardtokensession.cloneHardTokenProfile(
          administrator, originalname, newname);
    } else {
      throw new AuthorizationDeniedException(
          "Not authorized to clone hard token profile");
    }
  }

  /**
   * Method to get a reference to a Hard Token profile.
   *
   * @param id ID
   * @return Profile
   * @throws AuthorizationDeniedException Fail
   */
  public HardTokenProfile getHardTokenProfile(final int id)
      throws AuthorizationDeniedException {
    if (!authorizedToProfileId(id, false)) {
      throw new AuthorizationDeniedException(
          "Not authorized to hard token profile");
    }
    return hardtokensession.getHardTokenProfile(id);
  }

  /**
   * @param profilename NAme
   * @return Profile
   * @throws AuthorizationDeniedException Fail
   */
  public HardTokenProfile getHardTokenProfile(final String profilename)
      throws AuthorizationDeniedException {
    if (!authorizedToProfileName(profilename, false)) {
      throw new AuthorizationDeniedException(
          "Not authorized to hard token profile");
    }
    return hardtokensession.getHardTokenProfile(profilename);
  }

  /**
   * @param profilename Name
   * @return ID
   */
  public int getHardTokenProfileId(final String profilename) {
    return hardtokensession.getHardTokenProfileId(profilename);
  }

  /**
   * Help function that checks if administrator is authorized to edit profile
   * with given name.
   *
   * @param profilename Profile
   * @param editcheck Check
   * @return Bool
   */
  private boolean authorizedToProfileName(
      final String profilename, final boolean editcheck) {
    HardTokenProfile profile =
        hardtokensession.getHardTokenProfile(profilename);
    return authorizedToProfile(profile, editcheck);
  }

  /**
   * Help function that checks if administrator is authorized to edit profile
   * with given name.
   *
   * @param profileid Profile
   * @param editcheck Check
   * @return bool
   */
  private boolean authorizedToProfileId(
      final int profileid, final boolean editcheck) {
    HardTokenProfile profile = hardtokensession.getHardTokenProfile(profileid);
    return authorizedToProfile(profile, editcheck);
  }

  /**
   * Help function that checks if administrator is authorized to edit profile.
   *
   * @param profile Profile
   * @param editcheck Check
   * @return Bool
   */
  private boolean authorizedToProfile(
      final HardTokenProfile profile, final boolean editcheck) {
    boolean returnval = false;
    if (authorizationSession.isAuthorizedNoLogging(
        administrator, StandardRules.ROLE_ROOT.resource())) {
      returnval = true; // yes authorized to everything
    } else {
      if (editcheck
          && authorizationSession.isAuthorizedNoLogging(
              administrator,
              AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES)) {
        HashSet<Integer> authorizedcaids =
            new HashSet<>(caSession.getAuthorizedCaIds(administrator));
        HashSet<Integer> authorizedcertprofiles =
            new HashSet<>(
                certificateProfileSession.getAuthorizedCertificateProfileIds(
                    administrator, CertificateConstants.CERTTYPE_HARDTOKEN));
        // It should be possible to indicate that a certificate should not be
        // generated by not specifying a cert profile for this key.
        authorizedcertprofiles.add(
            Integer.valueOf(
                CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
        if (profile instanceof EIDProfile) {
          if (authorizedcertprofiles.containsAll(
                  ((EIDProfile) profile).getAllCertificateProfileIds())
              && authorizedcaids.containsAll(
                  ((EIDProfile) profile).getAllCAIds())) {
            returnval = true;
          }
        } else {
          // Implement for other profile types
        }
      }
    }
    return returnval;
  }

  /**
   * Method that test to XML encode and decode a profile.
   *
   * @param profile Profile
   * @return false if something went wrong in the encoding process.
   */
  @SuppressWarnings({"unchecked", "rawtypes"})
  private boolean checkXMLEncoding(final HardTokenProfile profile) {
    boolean success = false;
    try {

      java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

      // We must base64 encode string for UTF safety
      HashMap<?, ?> a = new Base64PutHashMap();
      a.putAll((HashMap) profile.saveData());
      java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
      encoder.writeObject(a);
      encoder.close();
      String data = baos.toString("UTF8");
      java.beans.XMLDecoder decoder =
          new java.beans.XMLDecoder(
              new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
      decoder.readObject();
      decoder.close();

      success = true;
    } catch (Exception e) {
      success = false;
    }

    return success;
  }
}
