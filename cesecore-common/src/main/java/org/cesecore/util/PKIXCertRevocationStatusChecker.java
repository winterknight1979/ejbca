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
package org.cesecore.util;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.util.Collection;
import java.util.Set;

public class PKIXCertRevocationStatusChecker extends PKIXCertPathChecker {

	@Override
	public void init(boolean forward) throws CertPathValidatorException {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isForwardCheckingSupported() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Set<String> getSupportedExtensions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
		// TODO Auto-generated method stub

	}

}
