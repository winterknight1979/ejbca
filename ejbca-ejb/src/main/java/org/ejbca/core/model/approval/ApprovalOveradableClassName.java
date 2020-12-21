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
package org.ejbca.core.model.approval;

import org.apache.log4j.Logger;

/**
 * Class used in constants for approvalable methods indicating calling
 * classes/methods that don't need to go through approvals.
 *
 * <p>Contains the full classpath and method na,e
 *
 * @author Philip Vendil $Id: ApprovalOveradableClassName.java 19901 2014-09-30
 *     14:29:38Z anatom $
 */
public class ApprovalOveradableClassName {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(ApprovalOveradableClassName.class);

  /** Param. */
  private String className = null;
  /** Param. */
  private String methodName = null;

  /**
   * @param aclassName The full name with packages
   * @param amethodName the method name/ can be null indicating all methods
   */
  public ApprovalOveradableClassName(
      final String aclassName, final String amethodName) {
    super();
    this.className = aclassName;
    this.methodName = amethodName;
  }

  /** @return The full name with packages */
  public String getClassName() {
    return className;
  }

  /**
   * @return name
   */
  public String getMethodName() {
    return methodName;
  }

  /**
   * Method that checks if the current classname / method is in the stacktrace.
   *
   * @param traces Trace
   * @return if the class.method exists in trace
   */
  public boolean isInStackTrace(final StackTraceElement[] traces) {

    boolean retval = false;
    for (int i = 0; i < traces.length; i++) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Compare "
                + className
                + "."
                + methodName
                + " with "
                + traces[i].getClassName()
                + "."
                + traces[i].getMethodName());
      }
      if (traces[i].getClassName().equals(className)) {
        if (methodName != null) {
          retval = traces[i].getMethodName().equals(methodName);
          if (retval) {
            break;
          }
        } else {
          retval = true;
          break;
        }
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("Result " + retval);
    }

    return retval;
  }
}
