/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.exception;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * Exception used in order to catch the error that we're trying to create a certificate that already exists.
 * 
 * @version $Id: CertificateSerialNumberException.java 26057 2017-06-22 08:08:34Z anatom $
 */
public class CertificateSerialNumberException extends CesecoreException {

    private static final long serialVersionUID = -2969078756967846634L;

    public CertificateSerialNumberException(String message) {
        super(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, message);
    }

    public CertificateSerialNumberException(Exception e) {
        super(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e);
    }

}
