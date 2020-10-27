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

import java.io.Serializable;

/**
 * Class used in presenting approval data for the approving administrator
 * Contains a header and a data part and booleans if they should be translated
 * or not.
 *
 * @version $Id: ApprovalDataText.java 23820 2016-07-07 13:53:30Z mikekushner $
 */
public class ApprovalDataText implements Serializable {
  /**
   * Class is also used by the RA. Please keep serialization compatible (do not
   * change the version number)
   */
  private static final long serialVersionUID = 1L;
  /** Header. */
  private final String header;
  /** Data. */
  private final String data;
  /** Bool. */
  private final boolean headerTranslateable;
  /** Bool. */
  private final boolean dataTranslatable;

  /**
   * @param aHeader gead
   * @param theData data
   * @param isHeaderTranslateable bool
   * @param isDataTranslatable vool
   */
  public ApprovalDataText(
      final String aHeader,
      final String theData,
      final boolean isHeaderTranslateable,
      final boolean isDataTranslatable) {
    super();
    this.header = aHeader;
    this.data = theData;
    this.headerTranslateable = isHeaderTranslateable;
    this.dataTranslatable = isDataTranslatable;
  }

  /**
   * @return data
   */
  public String getData() {
    return data;
  }

  /**
   * @return bool
   */
  public boolean isDataTranslatable() {
    return dataTranslatable;
  }

  /**
   * @return header
   */
  public String getHeader() {
    return header;
  }

  /**
   * @return bool
   */
  public boolean isHeaderTranslateable() {
    return headerTranslateable;
  }
}
