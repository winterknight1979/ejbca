/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import java.io.Serializable;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificatetransparency.CTAuditLogCallback;
import org.cesecore.certificates.certificatetransparency.CTSubmissionConfigParams;
import org.cesecore.keys.validation.CertificateValidationDomainService;

/**
 * Contains parameters and callbacks which is needed during certificate
 * generation in X509CA, e.g. by the CT extension. This can be used to access
 * session beans from this class, for instance the global configuration or audit
 * logging.
 *
 * @apiNote Since instances of this class may reference session beans, you must
 *     ensure that instances of this interface are only used temporarily, e.g.
 *     as functions arguments, and never as e.g. instance variables of
 *     non-temporary classes.
 * @apiNote Since it might not be possible to obtain the parameters, all methods
 *     that accept objects of this class should also accept a null value, or
 *     null values inside the CertificateGenerationParams object.
 * @see CTAuditLogCallback
 * @version $Id: CertificateGenerationParams.java 27524 2017-12-12 09:48:23Z
 *     bastianf $
 */
public final class CertificateGenerationParams implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Params. */
  private CTSubmissionConfigParams ctSubmissionConfigParams;
  /** Callback. */
  private CTAuditLogCallback ctAuditLogCallback;
  /** Token. */
  private AuthenticationToken authenticationToken;
  /** Domain service. */
  private CertificateValidationDomainService certificateValidationDomainService;

  /**
   * Sets CT parameters that are not specific to the certificate profile, for
   * example list of available CT logs.
   *
   * @param aCtSubmissionConfigParams parameters
   */
  public void setCTSubmissionConfigParams(
      final CTSubmissionConfigParams aCtSubmissionConfigParams) {
    this.ctSubmissionConfigParams = aCtSubmissionConfigParams;
  }

  /**
   * Set the a callback to be called after CT log submission. This method is
   * called automatically from CertificateCreateSession when generating a
   * certificate.
   *
   * @param aCtAuditLogCallback callback
   */
  public void setCTAuditLogCallback(
          final CTAuditLogCallback aCtAuditLogCallback) {
    this.ctAuditLogCallback = aCtAuditLogCallback;
  }

  /* Package internal methods are called from X509CA */

  CTSubmissionConfigParams getCTSubmissionConfigParams() { // NOPMD: PP
    return ctSubmissionConfigParams;
  }

  CTAuditLogCallback getCTAuditLogCallback() { // NOPMD: PP
    return ctAuditLogCallback;
  }

  /**
   * Gets the validation domain service reference.
   *
   * @return the domain service reference.
   */
  public CertificateValidationDomainService
      getCertificateValidationDomainService() {
    return certificateValidationDomainService;
  }

  /**
   * Sets the validation domain service reference.
   *
   * @param aCertificateValidationDomainService the domain service reference.
   */
  public void setCertificateValidationDomainService(
    final CertificateValidationDomainService
        aCertificateValidationDomainService) {
    this.certificateValidationDomainService =
        aCertificateValidationDomainService;
  }

  /**
   * Gets the authentication token.
   *
   * @return the token.
   */
  public AuthenticationToken getAuthenticationToken() {
    return authenticationToken;
  }

  /**
   * Sets the authentication token.
   *
   * @param aAuthenticationToken the token.
   */
  public void setAuthenticationToken(
          final AuthenticationToken aAuthenticationToken) {
    this.authenticationToken = aAuthenticationToken;
  }
}
