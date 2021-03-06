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

package org.ejbca.util;

/**
 * This class ignores all input.
 *
 * @version $Id: DummyPatternLogger.java 22139 2015-11-03 10:41:56Z mikekushner
 *     $
 */
public class DummyPatternLogger implements IPatternLogger {
@Override
  public void flush() {
    /* nothing done */
  }
@Override
  public void paramPut(final String key, final byte[] value) {
    /* nothing done */
  }
@Override
  public void paramPut(final String key, final String value) {
    /* nothing done */
  }
@Override
  public void paramPut(final String key, final Integer value) {
    /* nothing done */
  }

  @Override
  public void writeln() {
    /* nothing done */
  }
}
