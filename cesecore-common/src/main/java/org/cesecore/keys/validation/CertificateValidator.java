/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

import org.cesecore.certificates.ca.CA;
import org.cesecore.util.ui.DynamicUiModelAware;

/**
 * Base interface for certificate validators. All certificate validators must implement this interface.
 *
 * @version $Id: CertificateValidator.java 28140 2018-01-30 12:40:30Z andresjakobs $
 *
 */
public interface CertificateValidator extends Validator, ValidityAwareValidator, DynamicUiModelAware {

    /** List of accepted date formats for notBefore and notAfter filter. */
    static final String[] DATE_FORMAT = new String[] { "yyyy-MM-dd HH:mm:ssZZ", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd" };

    /**
     * Method that validates the public key.
     *
     * @param ca the issuing CA.
     * @param externalScriptsWhitelist
     * @param certifcate the certificate to validate.
     * @param whitelist a whitelist containing all scripts permitted to be executed
     * @return the error messages or an empty list if the certificate was validated successfully.
     * @throws ValidatorNotApplicableException when this validator is not applicable for the input, for example CVC certificate instead of X.509 or other type
     * @throws ValidationException if the certificate could not be validated by the external command (exit code > 0).
     * @throws CertificateException if one of the certificates could not be parsed.
     */
    List<String> validate(CA ca, Certificate certificate, ExternalScriptsWhitelist whitelist)
            throws ValidatorNotApplicableException, ValidationException, CertificateException;
}
