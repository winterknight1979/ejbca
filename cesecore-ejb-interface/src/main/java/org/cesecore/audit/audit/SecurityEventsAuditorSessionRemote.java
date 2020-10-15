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
package org.cesecore.audit.audit;

import javax.ejb.Remote;

/**
 * Remote interface for the SecurityEventsAuditor
 *
 * @see SecurityEventsAuditorSession
 * @version $Id: SecurityEventsAuditorSessionRemote.java 17625 2013-09-20
 *     07:12:06Z netmackan $
 */
@Remote
public interface SecurityEventsAuditorSessionRemote
    extends SecurityEventsAuditorSession {}
