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

import java.security.SecureRandom;
import java.util.Random;

/**
 * BasePasswordGenerator is a base class for generating random passwords.
 * Inheriting classes should overload the constants USEDCHARS, MIN_CHARS and
 * MAX_CHARS.
 *
 * @version $Id: BasePasswordGenerator.java 22117 2015-10-29 10:53:42Z
 *     mikekushner $
 */
public abstract class BasePasswordGenerator implements IPasswordGenerator {

    /** chars. */
  private final char[] usedchars;
  /** Declare the random here so that the seed only have to be generated once.
   * This will save time. */
  private static final Random RAN = new SecureRandom();

  protected BasePasswordGenerator(final char[] theusedchars) {
    this.usedchars = theusedchars;
  }

  /** @see org.ejbca.util.passgen.IPasswordGenerator */
  @Override
  public String getNewPassword(final int minlength, final int maxlength) {
    final int difference = maxlength - minlength;
    // Calculate the length of password
    int passlen = maxlength;
    if (minlength != maxlength) {
      passlen = minlength + BasePasswordGenerator.RAN.nextInt(difference);
    }
    final char[] password = new char[passlen];
    for (int i = 0; i < passlen; i++) {
      password[i] =
          this.usedchars[
              BasePasswordGenerator.RAN.nextInt(this.usedchars.length)];
    }
    return new String(password);
  }

  @Override
  public int getNumerOfDifferentChars() {
    return usedchars.length;
  }
}
