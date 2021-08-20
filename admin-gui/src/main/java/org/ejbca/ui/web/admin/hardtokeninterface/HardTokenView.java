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

package org.ejbca.ui.web.admin.hardtokeninterface;

import java.util.Collection;
import java.util.Date;
import org.cesecore.util.StringUtil;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.types.HardToken;

/**
 * A class representing a web interface view of a hard token in the ra database.
 *
 * @version $Id: HardTokenView.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class HardTokenView implements java.io.Serializable, Cloneable {

  private static final long serialVersionUID = 4090246269386728977L;

  // Public constants.
  /**
   * Constructor.
   */
  public HardTokenView() {
    this.tokendata = new HardTokenInformation();
  }

  /**
   * @param newtokendata Data
   */
  public HardTokenView(final HardTokenInformation newtokendata) {
    tokendata = newtokendata;
  }

  /**
   * @param user User
   */
  public void setUsername(final String user) {
    tokendata.setUsername(StringUtil.stripUsername(user));
  }

  /**
   * @return User
   */
  public String getUsername() {
    return tokendata.getUsername();
  }

  /**
   * @param tokensn SN
   */
  public void setTokenSN(final String tokensn) {
    tokendata.setTokenSN(tokensn);
  }

  /**
   * @return SN
   */
  public String getTokenSN() {
    return tokendata.getTokenSN();
  }

  /**
   * @param createtime Time
   */
  public void setCreateTime(final Date createtime) {
    tokendata.setCreateTime(createtime);
  }

  /**
   * @return Time
   */
  public Date getCreateTime() {
    return tokendata.getCreateTime();
  }

  /**
   * @param modifytime Time
   */
  public void setModifyTime(final Date modifytime) {
    tokendata.setModifyTime(modifytime);
  }

  /**
   * @return Time
   */
  public Date getModifyTime() {
    return tokendata.getModifyTime();
  }

  /**
   * @return LAbel
   */
  public String getLabel() {
    return tokendata.getHardToken().getLabel();
  }

  /**
   * @return Fields
   */
  public int getNumberOfFields() {
    return tokendata.getHardToken().getNumberOfFields();
  }

  /**
   * @param index Index
   * @return Field
   */
  public String getTextOfField(final int index) {
    if (tokendata
        .getHardToken()
        .getFieldText(index)
        .equals(HardToken.EMPTYROW_FIELD)) {
      return "";
    }
    return tokendata.getHardToken().getFieldText(index);
  }

  /**
   * @return bool
   */
  public boolean isOriginal() {
    return tokendata.isOriginal();
  }

  /**
   * @return Copy
   */
  public String getCopyOf() {
    return tokendata.getCopyOf();
  }

  /**
   * @return copies
   */
  public Collection<String> getCopies() {
    return tokendata.getCopies();
  }

  /**
   * @return ID
   */
  public Integer getHardTokenProfileId() {
    return Integer.valueOf(tokendata.getHardToken().getTokenProfileId());
  }

  /**
   * @param index Index
   * @return Field
   */
  public Object getField(final int index) {
    HardToken token = tokendata.getHardToken();

    if (token.getFieldPointer(index).equals(HardToken.EMPTYROW_FIELD)) {
      return "";
    }
    return token.getField(token.getFieldPointer(index));
  }

  // Private constants.
  // Private methods.
  /** Param. */
  private final HardTokenInformation tokendata;
}
