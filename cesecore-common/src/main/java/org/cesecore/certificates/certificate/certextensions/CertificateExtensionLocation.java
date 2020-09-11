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
package org.cesecore.certificates.certificate.certextensions;

/**
 * @version $Id: CertificateExtensionLocation.java 27581 2017-12-19 08:40:07Z samuellb $
 */
public enum CertificateExtensionLocation {
    /** Certificate extension located in a plain certificate */
    CERT,
    /** Certificate extension located in a link certificate */
    LINKCERT,
    /** Certificate extension located in a Certificate Signing Requests */
    CSR;
}
