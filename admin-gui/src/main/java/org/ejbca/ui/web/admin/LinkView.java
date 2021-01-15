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

package org.ejbca.ui.web.admin;

/**
 * Represents a link to another view. Used by approvals to link from approvals
 * list to certificate views.
 *
 * @version $Id: LinkView.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class LinkView {

      /** Param. */
  private final String uri;
  /** Param. */
  private final String preDescription;
  /** Param. */
  private final String description;
  /** Param. */
  private final String postDescription;

  /**
   * @param aURI URI
   * @param apreDescription Desc
   * @param adescription Desc
   * @param apostDescription Desc
   */
  public LinkView(
      final String aURI,
      final String apreDescription,
      final String adescription,
      final String apostDescription) {
    this.uri = aURI;
    this.preDescription = apreDescription;
    this.description = adescription;
    this.postDescription = apostDescription;
  }

  /**
   * @return URI
   */
  public String getURI() {
    return uri;
  }

  /**
   * @return desc
   */
  public String getPreDescription() {
    return preDescription;
  }

  /**
   * @return desc
   */
  public String getPostDescription() {
    return postDescription;
  }

  /**
   * @return Desc
   */
  public String getDescription() {
    return description;
  }
}
