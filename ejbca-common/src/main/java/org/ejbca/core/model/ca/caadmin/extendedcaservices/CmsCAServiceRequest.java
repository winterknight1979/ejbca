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

package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypeConstants;

/**
 * Class used when requesting CMS related services from a CA.
 *
 * @version $Id: CmsCAServiceRequest.java 19901 2014-09-30 14:29:38Z anatom $
 */
public class CmsCAServiceRequest extends ExtendedCAServiceRequest
    implements Serializable {

    /** Logger. */
  public static final Logger M_LOG =
      Logger.getLogger(CmsCAServiceRequest.class);

  /** config. */
  public static final int MODE_SIGN = 1;
  /** config. */
  public static final int MODE_ENCRYPT = 2;
  /** config. */
  public static final int MODE_DECRYPT = 4;

  /**
   * Determines if a de-serialized file is compatible with this class.
   *
   * <p>Maintainers must change this value if and only if the new version of
   * this class is not compatible with old versions. See Sun docs for <a
   * href=http://java.sun.com/products/jdk/1.1/docs/guide
   * /serialization/spec/version.doc.html> details. </a>
   */
  private static final long serialVersionUID = -762331405718560161L;

  /** Doc. */
  private byte[] doc = null;
  /** Mode. */
  private int mode = 0;

  /**
   * Constructor.
   *
   * @param aDoc the data to process
   * @param aMode one of the MODE_ constants
   */
  public CmsCAServiceRequest(final byte[] aDoc, final int aMode) {
    this.doc = aDoc;
    this.mode = aMode;
  }

  /**
   * @return Doc
   */
  public byte[] getDoc() {
    return doc;
  }

  /**
   * @return Mode
   */
  public int getMode() {
    return mode;
  }

  @Override
  public int getServiceType() {
    return ExtendedCAServiceTypeConstants.TYPE_CMSEXTENDEDSERVICE;
  }
}
