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
package org.cesecore.authentication.tokens;

import java.util.Arrays;
import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * Meta data definition and ServiceLoader marker for {@link
 * org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken}.
 *
 * @version
 *     $Id: AlwaysAllowLocalAuthenticationTokenMetaData.java
 *     25615 2017-03-24 18:44:19Z samuellb $
 */
public class AlwaysAllowLocalAuthenticationTokenMetaData
    extends AuthenticationTokenMetaDataBase {
    /** Type. */
    private static String tokenType = "AlwaysAllowLocalAuthenticationToken";

    private enum InternalMatchValue implements AccessMatchValue {
        /** Instance. */
        INSTANCE(0),
        /** Default. */
        DEFAULT(Integer.MAX_VALUE);

        /** Value. */
        private final int numericValue;

        InternalMatchValue(final int aNumericValue) {
            this.numericValue = aNumericValue;
        }

        @Override
        public int getNumericValue() {
            return numericValue;
        }

        @Override
        public String getTokenType() {
            return tokenType;
        }

        @Override
        public boolean isIssuedByCa() {
            return false;
        }

        @Override
        public boolean isDefaultValue() {
            return numericValue == DEFAULT.numericValue;
        }

        @Override
        public List<AccessMatchType> getAvailableAccessMatchTypes() {
            return Arrays.asList();
        }

        @Override
        public String normalizeMatchValue(final String value) {
            return null; // does not have a value
        }
    }

    /**
     * Basic constructor.
     */
    public AlwaysAllowLocalAuthenticationTokenMetaData() {
        super(tokenType, Arrays.asList(InternalMatchValue.values()), false);
    }
}
