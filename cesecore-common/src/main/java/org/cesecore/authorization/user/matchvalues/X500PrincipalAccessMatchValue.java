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
package org.cesecore.authorization.user.matchvalues;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.user.AccessMatchType;

/**
 * Match with constants. Observe that these constants are also used as a
 * priority indicator for access rules. The higher values the higher priority.
 *
 * @version $Id: X500PrincipalAccessMatchValue.java 25615 2017-03-24 18:44:19Z
 *          samuellb $
 *
 */
public enum X500PrincipalAccessMatchValue implements AccessMatchValue {
     /** None. */
    @Deprecated // Will never match anything which makes it rather useless keep
                // around long
                // term. (Deprecated in 6.8.0.)
    NONE(0),
    /** Country. */
    WITH_COUNTRY(1),
    /** Domain. */
    WITH_DOMAINCOMPONENT(2),
    /** State. */
    WITH_STATEORPROVINCE(3),
    /** Locality. */
    WITH_LOCALITY(4),
    /** Org. */
    WITH_ORGANIZATION(5),
    /** Unit. */
    WITH_ORGANIZATIONALUNIT(6),
    /** Title. */
    WITH_TITLE(7),
    /** Common name. */
    WITH_COMMONNAME(8),
    /** UID. */
    WITH_UID(9),
    /** DN serial. */
    WITH_DNSERIALNUMBER(10),
    /** Serial. */
    WITH_SERIALNUMBER(11),
    /** Email. */
    WITH_DNEMAILADDRESS(12),
    /** RFC 822 Email. */
    WITH_RFC822NAME(13),
    /** UPN. */
    WITH_UPN(14),
    /** Full DN. */
    WITH_FULLDN(15);

    /** Value. */
    private final int numericValue;

    /**
     * Constryctor.
     * @param aNumericValue Value
     */
    X500PrincipalAccessMatchValue(final int aNumericValue) {
        this.numericValue = aNumericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public boolean isDefaultValue() {
        return numericValue == WITH_SERIALNUMBER.numericValue;
    }

    @Override
    public String getTokenType() {
        return X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return true;
    }

    @Override
    public List<AccessMatchType> getAvailableAccessMatchTypes() {
        return Arrays.asList(AccessMatchType.TYPE_EQUALCASE);
    }

    @Override
    public String normalizeMatchValue(final String value) {
        if (value == null) {
            return null;
        } else if (this == WITH_SERIALNUMBER) {
            return value.trim().toUpperCase(Locale.ROOT)
                    .replaceAll("^0+([0-9A-F]+)$", "$1");
        } else {
            return value; // no normalization
        }
    }
}
