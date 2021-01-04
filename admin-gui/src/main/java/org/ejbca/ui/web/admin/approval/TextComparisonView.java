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

package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;

/**
 * Class used to present comparable data with red text for rows that doesn't
 * match.
 *
 * @version $Id: TextComparisonView.java 23688 2016-06-17 10:46:42Z mikekushner
 *     $
 */
public class TextComparisonView implements Serializable {

  private static final long serialVersionUID = 47502248806073893L;
  private final String orgvalue;
  private final String newvalue;

  public TextComparisonView(final String orgvalue, final String newvalue) {
    this.orgvalue = orgvalue;
    this.newvalue = newvalue;
  }

  public String getTextComparisonColor() {
    if (orgvalue != null && !orgvalue.equals(newvalue)) {
      return "alert";
    }

    return "";
  }

  public String getNewvalue() {
    return newvalue;
  }

  public String getOrgvalue() {
    return orgvalue;
  }
}
