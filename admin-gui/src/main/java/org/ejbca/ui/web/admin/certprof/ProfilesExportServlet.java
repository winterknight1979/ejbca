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

package org.ejbca.ui.web.admin.certprof;

import java.beans.XMLEncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.cainterface.BaseAdminServlet;
import org.ejbca.ui.web.admin.cainterface.exception.AdminWebAuthenticationException;

/**
 * Servlet used to export certificate profiles and end entity profiles in a
 * downloadable zip file.<br>
 * The servlet is called with method GET or POST and syntax <code>
 * profileType=&lt;type&gt;</code>.
 *
 * <p>The following types are supported:<br>
 *
 * <ul>
 *   <li>cp - Certificate Profiles
 *   <li>eep - End Entity Profiles
 * </ul>
 *
 * @version $Id: ProfilesExportServlet.java 34154 2019-12-23 13:38:17Z samuellb
 *     $
 */
public class ProfilesExportServlet extends BaseAdminServlet {

  private static final long serialVersionUID = -8091852234056712787L;
  /** Param. */
  private static final Logger LOG =
      Logger.getLogger(ProfilesExportServlet.class);

  /** Param. */
  @EJB private AuthorizationSessionLocal authorizationSession;
  /** Param. */
  @EJB private CertificateProfileSessionLocal certificateProfileSession;
  /** Param. */
  @EJB private EndEntityProfileSessionLocal endEntityProfileSession;
  /** Param. */
  @EJB private KeyValidatorSessionLocal keyValidatorSession;
  /** Param. */
  @EJB private GlobalConfigurationSessionLocal globalConfigurationSession;
  /** Param. */
  @EJB private WebAuthenticationProviderSessionLocal authenticationSession;

  @Override
  public void init(final ServletConfig config) throws ServletException {
    super.init(config);
  }

  @Override
  public void doPost(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    LOG.trace(">doPost()");
    doGet(request, response);
    LOG.trace("<doPost()");
  }

  @Override
  public void doGet(
      final HttpServletRequest request, final HttpServletResponse response)
      throws IOException, ServletException {
    LOG.trace(">doGet()");
    final AuthenticationToken admin;
    try {
      admin =
          authenticateAdmin(
              request, response, AccessRulesConstants.ROLE_ADMINISTRATOR);
    } catch (AdminWebAuthenticationException authExc) {
      // TODO: localize this.
      LOG.info("Authentication failed", authExc);
      response.sendError(
          HttpServletResponse.SC_FORBIDDEN, "Authentication failed");
      return;
    }

    final String type = request.getParameter("profileType");
    final boolean exportCertificateProfiles =
        StringUtils.equalsIgnoreCase(type, "cp");
    final boolean exportEndEntityProfiles =
        StringUtils.equalsIgnoreCase(type, "eep");

    String zipfilename = null;
    int exportedprofiles = 0;
    int totalprofiles = 0;
    int missingprofiles = 0;
    ByteArrayOutputStream zbaos = new ByteArrayOutputStream();
    ZipOutputStream zos = new ZipOutputStream(zbaos);

    if (exportCertificateProfiles) {
      zipfilename = "certprofiles.zip";

      final List<Integer> certificateProfileTypes = new ArrayList<>();
      certificateProfileTypes.add(CertificateConstants.CERTTYPE_ENDENTITY);
      if (authorizationSession.isAuthorizedNoLogging(
          admin, StandardRules.ROLE_ROOT.resource())) {
        // Only root users may use CA profiles
        certificateProfileTypes.add(CertificateConstants.CERTTYPE_ROOTCA);
        certificateProfileTypes.add(CertificateConstants.CERTTYPE_SUBCA);
      }
      GlobalConfiguration globaConfiguration =
          (GlobalConfiguration)
              globalConfigurationSession.getCachedConfiguration(
                  GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
      if (globaConfiguration.getIssueHardwareTokens()) {
        certificateProfileTypes.add(CertificateConstants.CERTTYPE_HARDTOKEN);
      }

      Collection<Integer> certprofids = new LinkedHashSet<>();
      for (Integer certificateProfileType : certificateProfileTypes) {
        certprofids.addAll(
            certificateProfileSession.getAuthorizedCertificateProfileIds(
                admin, certificateProfileType));
      }

      totalprofiles = certprofids.size();
      LOG.info("Exporting non-fixed certificate profiles");
      for (int profileid : certprofids) {
        if (profileid
            == CertificateProfileConstants
                .CERTPROFILE_NO_PROFILE) { // Certificate profile not found i
                                           // database.
          LOG.error(
              "Couldn't find certificate profile '"
                  + profileid
                  + "' in database.");
        } else if (CertificateProfileConstants.isFixedCertificateProfile(
            profileid)) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Skipping export fixed certificate profile with id '"
                    + profileid
                    + "'.");
          }
        } else {
          String profilename =
              certificateProfileSession.getCertificateProfileName(profileid);
          CertificateProfile profile =
              certificateProfileSession.getCertificateProfile(profileid);
          if (profile == null) {
            missingprofiles++;
            LOG.error(
                "Couldn't find certificate profile '"
                    + profilename
                    + "'-"
                    + profileid
                    + " in database.");
          } else {
            String profilenameEncoded;
            try {
              profilenameEncoded = URLEncoder.encode(profilename, "UTF-8");
            } catch (UnsupportedEncodingException e) {
              throw new IllegalStateException(
                  "UTF-8 was not a known encoding", e);
            }

            byte[] ba = getProfileBytes(profile);
            String filename =
                "certprofile_" + profilenameEncoded + "-" + profileid + ".xml";
            ZipEntry ze = new ZipEntry(filename);
            zos.putNextEntry(ze);
            zos.write(ba);
            zos.closeEntry();
            exportedprofiles++;
          }
        }
      }

    } else if (exportEndEntityProfiles) {

      zipfilename = "entityprofiles.zip";

      Collection<Integer> endentityprofids =
          endEntityProfileSession.getAuthorizedEndEntityProfileIds(
              admin, AccessRulesConstants.VIEW_END_ENTITY);
      totalprofiles = endentityprofids.size();
      LOG.info("Exporting non-fixed end entity profiles");
      for (int profileid : endentityprofids) {
        if (profileid
            == EndEntityConstants
                .NO_END_ENTITY_PROFILE) { // Entity profile not found i
                                          // database.
          missingprofiles++;
          LOG.error(
              "Error : Couldn't find entity profile '"
                  + profileid
                  + "' in database.");
        } else if (profileid == EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
          if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Skipping export fixed end entity profile with id '"
                    + profileid
                    + "'.");
          }
        } else {
          String profilename =
              endEntityProfileSession.getEndEntityProfileName(profileid);
          EndEntityProfile profile =
              endEntityProfileSession.getEndEntityProfile(profileid);
          if (profile == null) {
            LOG.error(
                "Error : Couldn't find entity profile '"
                    + profilename
                    + "'-"
                    + profileid
                    + " in database.");
          } else {
            String profilenameEncoded;
            try {
              profilenameEncoded = URLEncoder.encode(profilename, "UTF-8");
            } catch (UnsupportedEncodingException e) {
              throw new IllegalStateException(
                  "UTF-8 was not a known encoding", e);
            }

            byte[] ba = getProfileBytes(profile);
            String filename =
                "entityprofile_"
                    + profilenameEncoded
                    + "-"
                    + profileid
                    + ".xml";
            ZipEntry ze = new ZipEntry(filename);
            zos.putNextEntry(ze);
            zos.write(ba);
            zos.closeEntry();

            exportedprofiles++;
          }
        }
      }
    }
    zos.close();

    final byte[] zipfile = zbaos.toByteArray();
    zbaos.close();

    LOG.info(
        "Found "
            + totalprofiles
            + " profiles. "
            + exportedprofiles
            + " profiles were exported to "
            + zipfilename
            + " and "
            + missingprofiles
            + " were not found in the database.");

    response.setContentType("application/octet-stream");
    response.setHeader(
        "Content-disposition",
        " attachment; filename=\""
            + StringTools.stripFilename(zipfilename)
            + "\"");
    response.getOutputStream().write(zipfile);
    response.flushBuffer();

    LOG.trace("<doGet()");
  } // doGet

  private byte[] getProfileBytes(final UpgradeableDataHashMap profile) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (XMLEncoder encoder = new XMLEncoder(baos)) {
      encoder.writeObject(profile.saveData());
      encoder.close();
      return baos.toByteArray();
    }
  }
}
