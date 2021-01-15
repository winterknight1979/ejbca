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
package org.ejbca.ui.web.admin.audit;

/**
 * Comparison operations that can be used when searching the audit log.
 *
 * @version $Id: Condition.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public enum Condition {
      /** param. */
  EQUALS,
  /** param. */
  NOT_EQUALS,
  /** param. */
  STARTS_WITH,
  /** param. */
  ENDS_WITH,
  /** param. */
  CONTAINS,
  /** param. */
  LESS_THAN,
  /** param. */
  GREATER_THAN
}
