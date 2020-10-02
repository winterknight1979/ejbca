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

package org.cesecore.authorization.access;

/**
 * Enum adapted from the constants in AccessTreeNode in EJBCA.
 * Represents the state of an accessTree node.
 *
 * @version $Id: AccessTreeState.java 17625 2013-09-20 07:12:06Z netmackan $
 *
 */

public enum AccessTreeState {
    /** Unknown. */
    STATE_UNKNOWN(1),
    /** Accept at top level. */
    STATE_ACCEPT(2),
    /** Accept at any level. */
    STATE_ACCEPT_RECURSIVE(3),
    /** Decline. */
    STATE_DECLINE(4);

    /** Constructor.
     *
     * @param aLegacyNumber number
     */
    AccessTreeState(final int aLegacyNumber) {
        this.legacyNumber = aLegacyNumber;
    }

    /** @return legacyNumber. */
    public int getLegacyNumber() {
        return legacyNumber;
    }

    /** Legacy number. */
    private int legacyNumber;
}
