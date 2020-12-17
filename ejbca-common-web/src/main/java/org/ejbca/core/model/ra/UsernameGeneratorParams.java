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

package org.ejbca.core.model.ra;

import java.util.Arrays;
import java.util.List;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Parameters used in UsernameGenerator.
 *
 * @version $Id: UsernameGeneratorParams.java 22139 2015-11-03 10:41:56Z
 *     mikekushner $
 * @see UsernameGenerator
 */
public class UsernameGeneratorParams {

  /** Create a completely random username. */
  protected static final int MODE_RANDOM = 0;
  /** Use the input as the base username. */
  protected static final int MODE_USERNAME = 1;
  /** Use a part of the DN as pase username. */
  protected static final int MODE_DN = 2;
  /** use a fixed (set as dNGeneratorComponent) username. */
  protected static final int MODE_FIXED = 3;

  /** Param. */
  private static final int LEN = 12;

  /** Param. */
  public static final String RANDOM = "RANDOM";
  /** Param. */
  public static final String USERNAME = "USERNAME";
  /** Param. */
  public static final String DN = "DN";
  /** Param. */
  public static final String FIXED = "FIXED";

  /** Param. */
  private final String[] modes = {"RANDOM", "USERNAME", "DN", "FIXED"};

  // Generator configuration parameters, with good default values
  /** Param. */
  private int mode = MODE_RANDOM;
  /** Param. */
  private int randomNameLength = LEN;
  /** Param. */
  private String randomGeneratorType =
      PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS;
  /** Param. */
  private String dNGeneratorComponent =
      "CN"; // Can be CN, UID, SN etc, or CN;UID;SN
  /** Param. */
  private String prefix = null;
  /** Param. */
  private String postfix = null;
  /** Param. */
  private int randomPrefixLength = LEN;

  /** Default cnstructor. */
  public UsernameGeneratorParams() {
    // all default values
  }

  /**
   * @return gen
   */
  public String getDNGeneratorComponent() {
    return dNGeneratorComponent;
  }

  /**
   * @param ageneratorComponent gen
   */
  public void setDNGeneratorComponent(final String ageneratorComponent) {
    dNGeneratorComponent = ageneratorComponent;
  }

  /**   *
   * @return POSTFIX
   */
  public String getPostfix() {
    return postfix;
  }

  /**
   * @param apostfix postfix
   */
  public void setPostfix(final String apostfix) {
    this.postfix = apostfix;
  }

  /**
   * @return prefix
   */
  public String getPrefix() {
    return prefix;
  }

  /**
   * @param aprefix prefix
   */
  public void setPrefix(final String aprefix) {
    this.prefix = aprefix;
  }

  /**
   * @return type
   */
  public String getRandomGeneratorType() {
    return randomGeneratorType;
  }

  /**
   * @param arandomGeneratorType type
   */
  public void setRandomGeneratorType(final String arandomGeneratorType) {
    this.randomGeneratorType = arandomGeneratorType;
  }

  /**
   * @return length
   */
  public int getRandomNameLength() {
    return randomNameLength;
  }

  /**
   * @param arandomNameLength length
   */
  public void setRandomNameLength(final int arandomNameLength) {
    this.randomNameLength = arandomNameLength;
  }

  /**
   * @return length
   */
  public int getRandomPrefixLength() {
    return randomPrefixLength;
  }

  /**
   * @param arandomPrefixLength length
   */
  public void setRandomPrefixLength(final int arandomPrefixLength) {
    this.randomPrefixLength = arandomPrefixLength;
  }

  /**
   * @return mode
   */
  public int getMode() {
    return mode;
  }
  /**
   * @param amode mode
   */
  public void setMode(final int amode) {
    this.mode = amode;
  }

  /**
   * @param amode mode
   */
  public void setMode(final String amode) {
    final List<String> modeList = Arrays.asList(modes);
    if (!modeList.contains(amode)) {
      throw new IllegalArgumentException("Mode " + amode + " is not supported");
    }
    this.mode = modeList.indexOf(amode);
  }
}
