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
package org.ejbca.core.ejb.authentication.cli;

import java.util.Arrays;
import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * @version $Id: CliUserAccessMatchValue.java 25615 2017-03-24 18:44:19Z samuellb $
 *
 */
public enum CliUserAccessMatchValue implements AccessMatchValue {
    USERNAME(0);

    private final int numericValue;

    private CliUserAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public boolean isDefaultValue() {
        return numericValue == USERNAME.numericValue;
    }

    @Override
    public String getTokenType() {
        return CliAuthenticationTokenMetaData.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
    }

    @Override
    public List<AccessMatchType> getAvailableAccessMatchTypes() {
        // Always use case sensitive match for usernames
        return Arrays.asList(AccessMatchType.TYPE_EQUALCASE);
    }

    @Override
    public String normalizeMatchValue(final String value) {
        return value != null ? value.trim() : null;
    }
}
