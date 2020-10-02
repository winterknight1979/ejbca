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
package org.cesecore.authorization.control;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @version $Id: AuditLogRules.java 25428 2017-03-09 14:45:59Z jeklund $
 *
 */
public enum AuditLogRules {
    /** Base. */
    BASE("/secureaudit"),
    /** Configure. */
    CONFIGURE(BASE.resource() + "/management/manage"),
    /** Export. */
    EXPORT_LOGS(BASE.resource() + "/auditor/export"),
    /** View. */
    VIEW(BASE.resource() + "/auditor/select"),
    /** Verify. */
    VERIFY(BASE.resource() + "/auditor/verify"),
    /** Log. */
    LOG(BASE.resource() + "/log"),
    /** Custom log. */
    LOG_CUSTOM(BASE.resource() + "/log_custom_events");

    /** Resource. */
    private final String resource;
    /** All resources. */
    private static final Map<String, String> ALL_RESOURCES = new HashMap<>();

    static {
        for (AuditLogRules rule : AuditLogRules.values()) {
            ALL_RESOURCES.put(rule.resource(), rule.resource());
        }
    }

    /**
     * Constructor.
     * @param aResource Resource
     */
    AuditLogRules(final String aResource) {
        this.resource = aResource;
    }

    /** @return resource */
    public String resource() {
        return this.resource;
    }

    @Override
    public String toString() {
        return this.resource;
    }

    /** @return Map of all resources */
    public static Map<String, String> getAllResources() {
        return Collections.unmodifiableMap(ALL_RESOURCES);
    }
}
