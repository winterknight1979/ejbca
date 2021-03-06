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
package org.ejbca.ui.cli.infrastructure.command;

/**
 * Base class for EJBCA commands that don't use the CLI user.
 *
 * @version $Id: EjbcaCommandBase.java 19902 2014-09-30 14:32:24Z anatom $
 */
public abstract class EjbcaCommandBase extends CommandBase {

  @Override
  public String getImplementationName() {
    return "EJBCA CLI";
  }
}
