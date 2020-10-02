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
package org.cesecore.authorization.rules;

import java.util.HashMap;
import java.util.Map;

/**
 * @version $Id: AccessRuleState.java 17625 2013-09-20 07:12:06Z netmackan $
 *
 */
public enum AccessRuleState {
    /** Rule is not used. */
    RULE_NOTUSED("UNUSED", 0),
    /** Rule was accepted. */
    RULE_ACCEPT("ACCEPT", 1),
    /** Rule was declined. */
    RULE_DECLINE("DECLINE", 2);

    /**
     * Constructor.
     * @param aName Name
     * @param aDatabaseValue ID
     */
    AccessRuleState(final String aName, final int aDatabaseValue) {
        this.name = aName;
        this.databaseValue = aDatabaseValue;
    }

    /**
     * @return Name
     */
    public String getName() {
        return name;
    }

    /**
     * @return ID
     */
    public int getDatabaseValue() {
        return databaseValue;
    }

    /**
     * Get state of rule by ID.
     * @param value ID
     * @return State
     */
    public static AccessRuleState matchDatabaseValue(final Integer value) {
        return databaseValueToRuleMap.get(value);
    }

    /**
     * Get state of rule name.
     * @param name Name
     * @return State
     */
    public static AccessRuleState matchName(final String name) {
        return nameToRuleMap.get(name);
    }

    /** Rule name. */
    private String name;
    /** Rule ID. */
    private int databaseValue;
    /** Map of rule ID's to rules. */
    private static Map<Integer, AccessRuleState> databaseValueToRuleMap
        = new HashMap<Integer, AccessRuleState>();
    /** Map of rule names to rules. */
    private static Map<String, AccessRuleState> nameToRuleMap
        = new HashMap<String, AccessRuleState>();

    static {
        for (AccessRuleState state : AccessRuleState.values()) {
            databaseValueToRuleMap.put(state.getDatabaseValue(), state);
            nameToRuleMap.put(state.getName(), state);
        }
    }

}
