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

package org.ejbca.util.passgen;

/**
 * LettersAndDigitsPasswordGenerator is a class generating random passwords
 * containing letters or digits.
 *
 * @version $Id: LettersAndDigitsPasswordGenerator.java 22117 2015-10-29
 *     10:53:42Z mikekushner $
 */
public class LettersAndDigitsPasswordGenerator extends BasePasswordGenerator {

    /** Chars. */
  private static final char[] USEDCHARS = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'q', 'Q', 'w', 'W', 'e',
    'E', 'r', 'R', 't', 'T', 'y', 'Y', 'u', 'U', 'i', 'I', 'o', 'O', 'p', 'P',
    'a', 'A', 's', 'S', 'd', 'D', 'f', 'F', 'g', 'G', 'h', 'H', 'j', 'J', 'k',
    'K', 'l', 'L', 'z', 'Z', 'x', 'X', 'c', 'C', 'v', 'V', 'b', 'B', 'n', 'N',
    'm', 'M'
  };

  /** Name. */
  protected static final String NAME = "PWGEN_LETTERDIGIT";

  /**
   * @return name
   */
  public String getName() {
    return NAME;
  }

  /** Constructor. */
  public LettersAndDigitsPasswordGenerator() {
    super(USEDCHARS);
  }
}
