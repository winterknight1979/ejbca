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
package org.ejbca.ui.cli.infrastructure.parameter;

import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Wrapper class for a command parameter.
 *
 * @version $Id: Parameter.java 26057 2017-06-22 08:08:34Z anatom $
 */
public class Parameter {

      /** Param. */
  private final String keyWord;
  /** Param. */
  private final StandaloneMode allowStandAlone;
  /** Param. */
  private final ParameterMode parameterMode;
  /** Param. */
  private final MandatoryMode mandatoryMode;
  /** Param. */
  private final String instruction;
  /** Param. */
  private final String name;
  // Uncommon value set as false if this Parameter shouldn't be listed as part
  // of the man page.
  /** Param. */
  private boolean allowList = true;

  /**
   * Constructor for defining a parameter.
   *
   * @param akeyWord The keyword used to identify this parameter. Commonly
   *     prefixed with a dash ('-')
   * @param aname What this parameter denotes. Used for documentation purposes.
   * @param amandatoryMode Defines whether this parameter is mandatory or not.
   * @param anallowStandAlone true if this parameter can be inputed without its
   *     keyword.
   * @param aparameterMode the type of parameter, if it requires an argument, if
   *     it's a flag, or a password etc
   * @param aninstruction Instructiion
   */
  public Parameter(
      final String akeyWord,
      final String aname,
      final MandatoryMode amandatoryMode,
      final StandaloneMode anallowStandAlone,
      final ParameterMode aparameterMode,
      final String aninstruction) {
    // Perform validation
    if (anallowStandAlone.equals(StandaloneMode.ALLOW)
        && !aparameterMode.equals(ParameterMode.ARGUMENT)) {
      throw new IllegalStateException(
          "A non argument parameter can not be set to standalone.");
    }
    this.keyWord = akeyWord;
    this.allowStandAlone = anallowStandAlone;
    this.parameterMode = aparameterMode;
    this.mandatoryMode = amandatoryMode;
    this.instruction = aninstruction;
    this.name = aname;
  }

  /**
   * @return Name
   */
  public String getName() {
    return name;
  }

  /**
   * @return mode
   */
  public boolean isMandatory() {
    return mandatoryMode.isMandatory();
  }

  /**
   * @return bool
   */
  public boolean isStandAlone() {
    return allowStandAlone.isStandAlone();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((keyWord == null) ? 0 : keyWord.hashCode());
    return result;
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
        return true;
    }
    if (obj == null) {
        return false;
    }
    if (getClass() != obj.getClass()) {
        return false;
    }
    Parameter other = (Parameter) obj;
    if (keyWord == null) {
      if (other.keyWord != null) {
          return false;
      }
    } else if (!keyWord.equals(other.keyWord)) {
        return false;
    }
    return true;
  }

  /**
   * @return mode
   */
  public ParameterMode getParameterMode() {
    return parameterMode;
  }

  /**
   * @return mode
   */
  public StandaloneMode allowStandAlone() {
    return allowStandAlone;
  }

  /** @return the keyWord */
  public String getKeyWord() {
    return keyWord;
  }

  /**
   * @return instruction
   */
  public String getInstruction() {
    return instruction;
  }

  /**
   * Quick factory method for creating flags.
   *
   * @param keyWord Key word
   * @param instruction Instruction
   * @return Parameter
   */
  public static Parameter createFlag(
      final String keyWord, final String instruction) {
    return new Parameter(
        keyWord,
        "",
        MandatoryMode.OPTIONAL,
        StandaloneMode.FORBID,
        ParameterMode.FLAG,
        instruction);
  }

  /**
   * @return bool
   */
  public boolean allowList() {
    return allowList;
  }

  /**
   * @param doallowList bool
   */
  public void setAllowList(final boolean doallowList) {
    this.allowList = doallowList;
  }
}
