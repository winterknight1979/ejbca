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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * @version $Id: CertificateRequestSession.java 25833 2017-05-10 16:19:27Z samuellb $
 */
public interface CertificateRequestSession {

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request, base64 encoded binary request, in the format specified in the reqType parameter
	 * @param reqType is one of SecConst.CERT_REQ_TYPE_..
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 * @throws CADoesntExistsException fai;
	 * @throws AuthorizationDeniedException  fail
	 * @throws NotFoundException fail
	 * @throws InvalidKeyException fail
	 * @throws NoSuchAlgorithmException fail 
	 * @throws InvalidKeySpecException fail
	 * @throws NoSuchProviderException fail
	 * @throws SignatureException fail
	 * @throws IOException fail
	 * @throws CertificateException fail 
	 * @throws EndEntityProfileValidationException fail 
	 * @throws ApprovalException fail
	 * @throws EjbcaException fail
	 * @throws CesecoreException fail
	 * @throws CertificateExtensionException if the request contained invalid extensions
	 */
    public byte[] processCertReq(AuthenticationToken admin, EndEntityInformation userdata, String req, int reqType, String hardTokenSN, int responseType) throws CADoesntExistsException,
            AuthorizationDeniedException, NotFoundException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
            SignatureException, IOException, CertificateException, EndEntityProfileValidationException,
            ApprovalException, EjbcaException, CesecoreException, CertificateExtensionException;

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * Username and password in userdata and req message must match.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request
	 * @param responseClass the class of the response message that should be returned back
     * @return a response message of the type specified in responseClass 
	 * @throws EndEntityExistsException fail
	 * @throws AuthorizationDeniedException fail
	 * @throws EndEntityProfileValidationException fail
	 * @throws EjbcaException fail
	 * @throws CesecoreException fail
	 * @throws CertificateExtensionException (rollback) if an error exists in the exensions specified in the request
	 */
    public ResponseMessage processCertReq(AuthenticationToken admin, EndEntityInformation userdata, RequestMessage req, Class<? extends CertificateResponseMessage> responseClass) throws EndEntityExistsException,
            AuthorizationDeniedException, EndEntityProfileValidationException, EjbcaException, CesecoreException, CertificateExtensionException;

	/**
	 * Edits or adds a user and generates a keystore for that user in a single transaction.
     * Used from EjbcaWS.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a keystore
	 * @param hardTokenSN is the hard token to associate this or null
     * @param keyspec name of ECDSA key or length of RSA and DSA keys  
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @return an encoded keystore of the type specified in responseType 
	 * @throws EndEntityProfileValidationException fail
	 * @throws AuthorizationDeniedException fail
	 * @throws CustomFieldException fail
	 * @throws CADoesntExistsException fail
	 * @throws EndEntityExistsException fail
	 * @throws ApprovalException fail
	 * @throws IllegalNameException if the Subject DN failed constraints
	 * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
	 * @throws NoSuchAlgorithmException fail
	 * @throws InvalidKeySpecException fail
	 * @throws CertificateException fail
	 * @throws InvalidAlgorithmParameterException fail
	 * @throws KeyStoreException fail
	 * @throws NoSuchEndEntityException if the end entity was not found
     */
    public byte[] processSoftTokenReq(AuthenticationToken admin, EndEntityInformation userdata, String hardTokenSN, String keyspec, String keyalg,
            boolean createJKS) throws ApprovalException, EndEntityExistsException, CADoesntExistsException, CertificateSerialNumberException,
            IllegalNameException, CustomFieldException, AuthorizationDeniedException, EndEntityProfileValidationException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException, NoSuchEndEntityException;
}
