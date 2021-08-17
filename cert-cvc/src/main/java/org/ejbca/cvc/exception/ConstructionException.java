/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc.exception;

/**
 * Exception indicating that something went wrong while constructing some CVC
 * object.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class ConstructionException extends CvcException {

  private static final long serialVersionUID = 1L;

  /** @see Exception */
  public ConstructionException() {
    super();
  }

  /** @see Exception
   * @param msg msg */
  public ConstructionException(final String msg) {
    super(msg);
  }

  /** @see Exception
   * @param t cause */
  public ConstructionException(final Throwable t) {
    super(t);
  }

  /** @see Exception
   * @param msg msh
   * @param t cause */
  public ConstructionException(final String msg, final Throwable t) {
    super(msg, t);
  }
}
