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
package org.cesecore.certificates.certificate;

import java.util.Date;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Local interface for {@link NoConflictCertificateStoreSession}.
 * 
 * @version $Id: NoConflictCertificateStoreSessionLocal.java 28717 2018-04-13 16:51:16Z samuellb $
 */
@Local
public interface NoConflictCertificateStoreSessionLocal extends NoConflictCertificateStoreSession {

    /** @see CertificateStoreSessionLocal#setRevokeStatus */
    boolean setRevokeStatus(AuthenticationToken admin, CertificateDataWrapper cdw, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException;
    
    /** @see CertificateStoreSessionLocal#getCertificateData(String) */
    public CertificateDataWrapper getCertificateData(final String fingerprint);
}
