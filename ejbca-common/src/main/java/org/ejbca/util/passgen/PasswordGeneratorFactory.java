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

import java.util.ArrayList;
import java.util.Collection;

/**
 * Factory class creating PasswordGenerators. Usage:
 *
 * <pre>
 *  IPasswordGenerator pwdgen =
 *      PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
 *  String pwd = pwdgen.getNewPassword(12, 16);
 * </pre>
 *
 * @version $Id: PasswordGeneratorFactory.java 22117 2015-10-29 10:53:42Z
 *     mikekushner $
 */
public final class PasswordGeneratorFactory {
    private PasswordGeneratorFactory() { }

      /** Type. */
  public static final String PASSWORDTYPE_DIGITS = DigitPasswordGenerator.NAME;
  /** Type. */
  public static final String PASSWORDTYPE_LETTERSANDDIGITS =
      LettersAndDigitsPasswordGenerator.NAME;
  /** Type. */
  public static final String PASSWORDTYPE_ALLPRINTABLE =
      AllPrintableCharPasswordGenerator.NAME;
  /** Type. */
  public static final String PASSWORDTYPE_NOLOOKALIKELD =
      NoLookALikeLDPasswordGenerator.NAME;
  /** Type. */
  public static final String PASSWORDTYPE_NOSOUNDALIKEENLD =
      NoSoundALikeENLDPasswordGenerator.NAME;
  /** Type. */
  public static final String PASSWORDTYPE_NOTALIKEENLD =
      NoLookOrSoundALikeENLDPasswordGenerator.NAME;

  /** Known generators. */
  static final IPasswordGenerator[] CLASSES = {
    new DigitPasswordGenerator(),
    new LettersAndDigitsPasswordGenerator(),
    new AllPrintableCharPasswordGenerator(),
    new NoLookALikeLDPasswordGenerator(),
    new NoSoundALikeENLDPasswordGenerator(),
    new NoLookOrSoundALikeENLDPasswordGenerator()
  };

  /**
   * Method returning an instance of the specified IPasswordGenerator class.
   *
   * @param type should be on of the PasswordGeneratorFactory constants.
   * @return generator
   */
  public static IPasswordGenerator getInstance(final String type) {
    IPasswordGenerator ret = null;
    for (int i = 0; i < CLASSES.length; i++) {
      if (CLASSES[i].getName().equals(type)) {
        ret = CLASSES[i];
      }
    }
    return ret;
  }

  /**
   * @return available types
   */
  public static Collection<String> getAvailablePasswordTypes() {
    ArrayList<String> al = new ArrayList<String>();
    for (int i = 0; i < CLASSES.length; i++) {
      al.add(CLASSES[i].getName());
    }
    return al;
  }
}
