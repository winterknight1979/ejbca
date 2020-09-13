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

import javax.ejb.Remote;

/**
 * Remote interface for {@link NoConflictCertificateStoreSession}.
 * 
 * @version $Id: NoConflictCertificateStoreSessionRemote.java 28700 2018-04-13 06:47:48Z samuellb $
 */
@Remote
public interface NoConflictCertificateStoreSessionRemote extends NoConflictCertificateStoreSession {

}
