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

package org.ejbca.core.model.hardtoken.types;

import java.io.Serializable;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.model.hardtoken.HardTokenConstants;

/**
 * HardToken is a base class that all HardToken classes is supposed to inherit.
 * It function is to define the data the token is supposed contain.
 *
 * @author TomSelleck
 * @version $Id: HardToken.java 19901 2014-09-30 14:29:38Z anatom $
 */
public abstract class HardToken extends UpgradeableDataHashMap
    implements Serializable, Cloneable {
  private static final long serialVersionUID = 3354480892183271060L;
  // Default Values
  /** Config. */
  public static final float LATEST_VERSION = 0;
  /** Config. */
  public static final String TOKENTYPE = "TOKENTYPE";
  /** Config. */

  public static final String LABEL_REGULARCARD =
      HardTokenConstants.LABEL_REGULARCARD; // "LABEL_REGULARCARD";
  /** Config. */
  public static final String LABEL_TEMPORARYCARD =
      HardTokenConstants.LABEL_TEMPORARYCARD; // "LABEL_TEMPORARYCARD";
  /** Config. */
  public static final String LABEL_PROJECTCARD =
      HardTokenConstants.LABEL_PROJECTCARD; // "LABEL_PROJECTCARD";
  /** Config. */

  public static final String TOKENPROFILE = "TOKENPROFILE";
  /** Config. */
  public static final String LABEL = "LABEL";

  /** Config. */
  protected boolean includePUK = true;

  // Public Constants.

  /* Constants used to define how the stored data
   * should be represented in the web-gui.*/
  /** Config. */
  public static final int INTEGER = 0;
  /** Config. */
  public static final int LONG = 1;
  /** Config. */
  public static final int STRING = 2;
  /** Config. */
  public static final int BOOLEAN = 3;
  /** Config. */
  public static final int DATE = 4;
  /** Config. */
  public static final int EMPTYROW = 5;
  /** Config. */
  public static final String EMPTYROW_FIELD = "EMTPYROW";

  /**
   * @param doincludePUK bool
   */
  public HardToken(final boolean doincludePUK) {
    this.includePUK = doincludePUK;
  }

  // Public Methods
  /**
   * @param field name
   * @return obj
   */
  public Object getField(final String field) {
    return data.get(field);
  }

  /**
   * @param doincludePUK bool
   * @return fields
   */
  public abstract String[] getFields(boolean doincludePUK);

  /**
   * @param doincludePUK bool
   * @return types
   */
  public abstract int[] getDataTypes(boolean doincludePUK);
/**
 * @param doincludePUK bool
 * @return text
 */
  public abstract String[] getFieldTexts(boolean doincludePUK);

  /**
   *
   * @return num
   */
  public int getNumberOfFields() {
    return getFields(includePUK).length;
  }

  /**
   * @param index index
   * @return text
   */
  public String getFieldText(final int index) {
    return getFieldTexts(includePUK)[index];
  }

  /**
   * @param index index
   * @return pointer
   */
  public String getFieldPointer(final int index) {
    return getFields(includePUK)[index];
  }

  /**
   * @param index index
   * @return type
   */
  public int getFieldDataType(final int index) {
    return getDataTypes(includePUK)[index];
  }

  /**
   * @param field field
   * @param value value
   */
  public void setField(final String field, final Object value) {
    data.put(field, value);
  }


  /**
   * @return id
   */
  public int getTokenProfileId() {
    if (data.get(HardToken.TOKENPROFILE) == null) {
      return 0;
    }
    return ((Integer) data.get(HardToken.TOKENPROFILE)).intValue();
  }

  /**
   * @param hardtokenprofileid id
   */
  public void setTokenProfileId(final int hardtokenprofileid) {
    data.put(HardToken.TOKENPROFILE, Integer.valueOf(hardtokenprofileid));
  }

  /** @return one of the LABEL_ constants or null of no label is set. */
  public String getLabel() {
    return (String) data.get(HardToken.LABEL);
  }

  /** @param hardTokenLabel should be one of the LABEL_ constants */
  public void setLabel(final String hardTokenLabel) {
    data.put(HardToken.LABEL, hardTokenLabel);
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion.
   * @return floae */
  @Override
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  @Override
  public void upgrade() { }
}
