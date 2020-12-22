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

package org.ejbca.core.protocol.cmp.authentication;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSession;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;

/**
 * Verifies a CMP message using a suitable authentication module.
 *
 * <p>The authentication modules are specified as properties in the
 * CmpConfiguration.
 *
 * @version $Id: VerifyPKIMessage.java 25797 2017-05-04 15:52:00Z jeklund $
 */
public class VerifyPKIMessage {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(VerifyPKIMessage.class);

  /** Param. */
  private final CAInfo caInfo;
  /** Param. */
  private String errorMessage = null;
  /** Param. */
  private final String confAlias;
  /** Param. */
  private final CmpConfiguration cmpConfiguration;
  /** Param. */
  private final AuthenticationToken authenticationToken;
  /** Param. */
  private final CaSession caSession;
  /** Param. */
  private final EndEntityAccessSession endEntityAccessSession;
  /** Param. */
  private final CertificateStoreSession certificateStoreSession;
  /** Param. */
  private final AuthorizationSession authorizationSession;
  /** Param. */
  private final EndEntityProfileSession endEntityProfileSession;
  /** Param. */
  private final CertificateProfileSession certificateProfileSession;
  /** Param. */
  private final WebAuthenticationProviderSessionLocal
      authenticationProviderSession;
  /** Param. */
  private final EndEntityManagementSession endEntityManagementSession;

  /**
   * @param cainfo CA
   * @param aconfAlias Condif
   * @param anadmin Alias
   * @param acaSession Session
   * @param anendEntityAccessSession Access
   * @param acertificateStoreSession Store
   * @param anauthorizationSession Auth
   * @param anendEntityProfileSession Profile
   * @param acertificateProfileSession Cert
   * @param anauthenticationProviderSession Provider
   * @param anendEntityManagementSession Management
   * @param acmpConfiguration Config
   */
  public VerifyPKIMessage(
      final CAInfo cainfo,
      final String aconfAlias,
      final AuthenticationToken anadmin,
      final CaSession acaSession,
      final EndEntityAccessSession anendEntityAccessSession,
      final CertificateStoreSession acertificateStoreSession,
      final AuthorizationSession anauthorizationSession,
      final EndEntityProfileSession anendEntityProfileSession,
      final CertificateProfileSession acertificateProfileSession,
      final WebAuthenticationProviderSessionLocal
              anauthenticationProviderSession,
      final EndEntityManagementSession anendEntityManagementSession,
      final CmpConfiguration acmpConfiguration) {
    this.caInfo = cainfo;
    this.confAlias = aconfAlias;
    this.authenticationToken = anadmin;
    this.caSession = acaSession;
    this.endEntityAccessSession = anendEntityAccessSession;
    this.certificateStoreSession = acertificateStoreSession;
    this.authorizationSession = anauthorizationSession;
    this.endEntityProfileSession = anendEntityProfileSession;
    this.certificateProfileSession = acertificateProfileSession;
    this.authenticationProviderSession = anauthenticationProviderSession;
    this.endEntityManagementSession = anendEntityManagementSession;
    this.cmpConfiguration = acmpConfiguration;
  }

  /**
   * Returns the error message resulted in failing to verify the PKIMessage. The
   * error message is set in the getUsedAuthenticationModule() method.
   *
   * @return the error message as String. Null if the verification succeeded.
   */
  public String getErrorMessage() {
    return this.errorMessage;
  }

  /**
   * Verifies the authenticity of the PKIMessage.
   *
   * @param pkiMessage PKIMessage to verify
   * @param username that the PKIMessage should match or null
   * @param authenticated if the CMP message has already been authenticated in
   *     another way or not
   * @return The authentication module that succeeded in authenticating msg.
   *     Null if message authentication failed using all configured
   *     authentication modules.
   */
  public ICMPAuthenticationModule getUsedAuthenticationModule(
      final PKIMessage pkiMessage,
      final String username,
      final boolean authenticated) {
    final String authModules =
        this.cmpConfiguration.getAuthenticationModule(this.confAlias);
    final String authparameters =
        this.cmpConfiguration.getAuthenticationParameters(this.confAlias);
    final String[] modules = authModules.split(";");
    final String[] params = authparameters.split(";");
    if (modules.length != params.length) {
      LOG.error(
          "The number of authentication modules does not match the number of"
              + " authentication parameters. "
              + modules.length
              + " modules - "
              + params.length
              + " paramters");
      this.errorMessage = "CMP module configuration error.";
      return null;
    }
    boolean raMode = this.cmpConfiguration.getRAMode(this.confAlias);
    for (int i = 0; i < modules.length; i++) {
      final String moduleName = modules[i].trim();
      final String moduleParameter = params[i].trim();
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Trying to verify the message using CMP authentication module '"
                + moduleName
                + "' with parameter '"
                + moduleParameter
                + "'");
      }
      final ICMPAuthenticationModule module =
          getAuthModule(
              raMode, moduleName, moduleParameter, pkiMessage, authenticated);
      if (module != null) {
        if (module.verifyOrExtract(pkiMessage, username)) {
          LOG.info(
              "PKIMessage was successfully authenticated using "
                  + module.getName());
          return module;
        } else {
          if (module.getErrorMessage() != null) {
            errorMessage = module.getErrorMessage();
          }
        }
      }
    }
    if (this.errorMessage == null) {
      this.errorMessage =
          "Failed to authentication PKIMessage using authentication modules: "
              + authModules;
    }
    return null;
  }

  /**
   * @param raMode Mode
   * @param module Module
   * @param parameter Param
   * @param pkiMessage PKI
   * @param authenticated Auth
   * @return The requested authentication module or null if no such module is
   *     implemented.
   */
  private ICMPAuthenticationModule getAuthModule(
      final boolean raMode,
      final String module,
      final String parameter,
      final PKIMessage pkiMessage,
      final boolean authenticated) {
    switch (module) {
      case CmpConfiguration.AUTHMODULE_HMAC:
        return new HMACAuthenticationModule(
            authenticationToken,
            parameter,
            confAlias,
            cmpConfiguration,
            caInfo,
            endEntityAccessSession);
      case CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE:
        return new EndEntityCertificateAuthenticationModule(
            authenticationToken,
            parameter,
            confAlias,
            cmpConfiguration,
            authenticated,
            caSession,
            certificateStoreSession,
            authorizationSession,
            endEntityProfileSession,
            certificateProfileSession,
            endEntityAccessSession,
            authenticationProviderSession,
            endEntityManagementSession);
      case CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD:
        if (raMode) {
          this.errorMessage =
              "The authentication module '"
                  + module
                  + "' cannot be used in RA mode";
          break;
        }
        return new RegTokenPasswordExtractor();
      case CmpConfiguration.AUTHMODULE_DN_PART_PWD:
        if (raMode) {
          this.errorMessage =
              "The authentication module '"
                  + module
                  + "' cannot be used in RA mode";
          break;
        }
        return new DnPartPasswordExtractor(parameter);
      default:
        this.errorMessage = "Unrecognized authentication module: " + module;
    }
    LOG.info(this.errorMessage);
    return null;
  }
}
