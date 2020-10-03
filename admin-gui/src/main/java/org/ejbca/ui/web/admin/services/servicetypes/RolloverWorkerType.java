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
package org.ejbca.ui.web.admin.services.servicetypes;

import org.ejbca.core.model.services.workers.RolloverWorker;

/**
 * Class managing the view of the Rollover Worker
 *
 * @version $Id: RolloverWorkerType.java 21190 2015-04-30 16:53:25Z samuellb $
 */
public class RolloverWorkerType extends BaseEmailNotifyingWorkerType {
	private static final long serialVersionUID = 1L;

	public static final String NAME = "ROLLOVERWORKER";

	public RolloverWorkerType(){
		super(NAME, "rolloverworker.jsp", RolloverWorker.class.getName());
	}
}
