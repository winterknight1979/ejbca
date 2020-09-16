/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.acme;

/**
 * @version $Id: AcmeChallengeStatus.java 29587 2018-08-07 15:25:52Z mikekushner $
 *
 */
public enum AcmeChallengeStatus {
    PENDING,
    PROCESSING,
    VALID;

    public String getJsonValue() { return this.name().toLowerCase(); }
    public static AcmeChallengeStatus fromJsonValue(final String status) { return AcmeChallengeStatus.valueOf(status.toUpperCase()); }
}
