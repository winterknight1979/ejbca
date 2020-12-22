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
package org.ejbca.ui.cli.infrastructure.parameter.enums;

/**
 * This enum connotes whether a CLI argument (of the form --caname foo) is
 * allowed to stand without its associated switch and be read implicitly.
 * Standalone arguments will be read in the order they're declared, so care must
 * be taken to avoid ambiguity.
 *
 * @version $Id: StandaloneMode.java 20215 2014-11-07 13:36:30Z mikekushner $
 */
public enum StandaloneMode {
      /** Mode. */
  ALLOW(true),
  /** Mode. */
  FORBID(false);

    /** Pram. */
  private final boolean allowStandalone;

  /**
   * @param aallowStandalone bool
   */
  StandaloneMode(final boolean aallowStandalone) {
    this.allowStandalone = aallowStandalone;
  }

  /**
   * @return bool
   */
  public boolean isStandAlone() {
    return allowStandalone;
  }
}
