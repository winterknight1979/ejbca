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
package org.ejbca.core.ejb.approval;

import javax.ejb.Remote;

/**
 * Session to access approval profiles remotely
 * @version $Id: ApprovalProfileSessionRemote.java 23336 2016-05-02 20:25:49Z aveen4711 $
 */
@Remote
public interface ApprovalProfileSessionRemote extends ApprovalProfileSession {

}
