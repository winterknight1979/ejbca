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
package org.ejbca.core.model.services.intervals;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.BaseInterval;
import org.ejbca.core.model.services.IInterval;

/**
 * Dummy class used for demonstration and test puporses Only implement one
 * method.
 *
 * @version $Id: DummyInterval.java 22139 2015-11-03 10:41:56Z mikekushner $
 */
public class DummyInterval extends BaseInterval {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(DummyInterval.class);
  /** @see org.ejbca.core.model.services.IInterval#getTimeToExecution() */
  @Override
  public long getTimeToExecution() {
    LOG.trace(">DummyInterval.performAction");
    return IInterval.DONT_EXECUTE;
  }
}
