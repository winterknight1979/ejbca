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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Class used to generate special usernames.
 *
 * <p>Configuration parameters:
 *
 * <p>NameGenerationScheme = "Which generation scheme should be used, RANDOM,
 * USERNAME or DN" RANDOM will generate a random username with length set in
 * 'randomNameLength'.
 *
 * <p>NameGenerationParameters = "Parameters for name generation, for DN it can
 * be CN or UID". If mode is DN, the CN or UID is taken from the DN to be used
 * as username (adding pre- and postfix off-course).
 *
 * <p>NameGenerationPrefix = "Prefix to generated name, a string that can
 * contain the variable ${RANDOM}" exmaple: "Prefix - "
 *
 * <p>NameGenerationPostfix="Postfix to generated name, a string that can
 * contain the variable ${RANDOM}" example: " - Postfix"
 *
 * <p>The variable ${RANDOM} will be replaced by a random value of length set in
 * 'randomPrefixLength'.
 *
 * @version $Id: UsernameGenerator.java 24857 2016-12-07 13:48:26Z mikekushner $
 */
public final class UsernameGenerator {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(UsernameGenerator.class);

  /** Generator configuration parameters, with good default values.*/
  private UsernameGeneratorParams params = null;

  /**
   * @param mode mode
   * @return Instance
   */
  public static UsernameGenerator getInstance(final String mode) {
    return new UsernameGenerator(mode);
  }

  /**
   * @param params Params
   * @return instance
   */
  public static UsernameGenerator getInstance(
      final UsernameGeneratorParams params) {
    return new UsernameGenerator(params);
  }

  private UsernameGenerator(final String mode) {
    this.params = new UsernameGeneratorParams();
    params.setMode(mode);
  }

  private UsernameGenerator(final UsernameGeneratorParams theparams) {
    this.params = theparams;
  }

  /**
   * @return User
   */
  public String generateUsername() {
    String ret = null;
    if (params.getMode() != UsernameGeneratorParams.MODE_RANDOM) {
      throw new IllegalArgumentException(
          "this method can only be used in mode RANDOM");
    }
    ret = getRandomString(params.getRandomNameLength());
    return addPrePostFix(ret);
  }

  /**
   * @param name Name
   * @return User
   */
  public String generateUsername(final String name) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(">generateUsername: " + name);
    }
    String str = name;
    switch (params.getMode()) {
      case UsernameGeneratorParams.MODE_RANDOM:
        str = getRandomString(params.getRandomNameLength());
        break;
      case UsernameGeneratorParams.MODE_DN:
        if (str == null) {
          throw new IllegalArgumentException(
              "Input name can not be null in MODE_DN!");
        }
        String[] parts =
            StringUtils.split(params.getDNGeneratorComponent(), ';');
        for (int i = 0; i < parts.length; i++) {
          str = CertTools.getPartFromDN(name, parts[i]);
          // If this DN component exists, break here.
          if (str != null) {
            break;
          }
        }
        break;
      case UsernameGeneratorParams.MODE_USERNAME:
        if (str == null) {
          throw new IllegalArgumentException(
              "Input name can not be null in MODE_USERNAME!");
        }
        break;
      case UsernameGeneratorParams.MODE_FIXED:
        str = params.getDNGeneratorComponent();
        if (str == null) {
          throw new IllegalArgumentException(
              "DNGeneratorComponent can not be null in MODE_FIXED!");
        }
        break;
      default:
        break;
    }
    String ret = addPrePostFix(str);
    if (LOG.isDebugEnabled()) {
      LOG.debug("<generateUsername, generated username: " + ret);
    }
    return ret;
  }

  private String getRandomString(final int length) {
    IPasswordGenerator gen =
        PasswordGeneratorFactory.getInstance(params.getRandomGeneratorType());
    String ret = gen.getNewPassword(length, length);
    return ret;
  }

  private String addPrePostFix(final String in) {
    String ret = in;
    String pre = getPrefix();
    String post = getPostfix();
    if (pre != null) {
      ret = pre + ret;
    }
    if (post != null) {
      ret = ret + post;
    }
    return ret;
  }

  private String getPostfix() {
    return interpolate(params.getPostfix());
  }

  private String getPrefix() {
    return interpolate(params.getPrefix());
  }

  /** regexp pattern to match ${identifier} patterns. */
  private static final Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   *
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  private String interpolate(final String input) {
    if (input == null) {
      return null;
    }
    final Matcher m = PATTERN.matcher(input);
    final StringBuffer sb = new StringBuffer(input.length());
    while (m.find()) {
      // when the pattern is ${identifier}, group 0 is 'identifier'
      String key = m.group(1);
      String value = null;
      if (StringUtils.equals(key, "RANDOM")) {
        value = getRandomString(params.getRandomPrefixLength());
      }
      // if the pattern does exists, replace it by its value
      // otherwise keep the pattern ( it is group(0) )
      if (value != null) {
        m.appendReplacement(sb, value);
      } else {
        // I'm doing this to avoid the backreference problem as there will be a
        // $
        // if I replace directly with the group 0 (which is also a pattern)
        m.appendReplacement(sb, "");
        String unknown = m.group(0);
        sb.append(unknown);
      }
    }
    m.appendTail(sb);
    return sb.toString();
  }

  /**
   * @return Params
   */
  public UsernameGeneratorParams getParams() {
    return params;
  }

  /**
   * @param theparams params
   */
  public void setParams(final UsernameGeneratorParams theparams) {
    this.params = theparams;
  }
}
