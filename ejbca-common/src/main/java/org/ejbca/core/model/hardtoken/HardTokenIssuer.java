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

package org.ejbca.core.model.hardtoken;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * HardTokenIssuer V3 is a class representing the data saved for each
 * HardTokenIssuer. it isn't back compatible with the old version.
 *
 * @author TomSelleck
 * @version $Id: HardTokenIssuer.java 22117 2015-10-29 10:53:42Z mikekushner $
 */
public class HardTokenIssuer extends UpgradeableDataHashMap
    implements Serializable, Cloneable {

  private static final long serialVersionUID = -1794111124380177196L;

  // Default Values
  /** Config. */
  public static final float LATEST_VERSION = 1;

  // Protected Constants, must be overloaded by all deriving classes.
  /** Config. */
  protected static final String AVAILABLEHARDTOKENSPROFILES =
      "availablehardtokensprofiles";
  /** Config. */
  protected static final String DESCRIPTION = "description";

  /**
   * Constructor.
   */
  public HardTokenIssuer() {
    data.put(AVAILABLEHARDTOKENSPROFILES, new ArrayList<Integer>());
    data.put(DESCRIPTION, "");
  }

  // Public Methods

  // Availablehardtokens defines which hard tokens the issuer is able to issue.
  /**
   * @return tokens
   */
  @SuppressWarnings("unchecked")
  public ArrayList<Integer> getAvailableHardTokenProfiles() {
    return (ArrayList<Integer>) data.get(AVAILABLEHARDTOKENSPROFILES);
  }

  /**
   * @param availablehardtokens tokens
   */
  public void setAvailableHardTokenProfiles(
      final ArrayList<Integer> availablehardtokens) {
    data.put(AVAILABLEHARDTOKENSPROFILES, availablehardtokens);
  }

  /**
   * @return desc
   */
  public String getDescription() {
    return (String) data.get(DESCRIPTION);
  }

  /**
   * @param description desc
   */
  public void setDescription(final String description) {
    data.put(DESCRIPTION, description);
  }

  /**
   * @param field field
   * @param value value
   */
  public void setField(final String field, final Object value) {
    data.put(field, value);
  }

  /** Implementation of UpgradableDataHashMap function getLatestVersion.
   * @return version */
  public float getLatestVersion() {
    return LATEST_VERSION;
  }

  /** Implementation of UpgradableDataHashMap function upgrade. */
  public void upgrade() { }

  /**
   * @return clone
   * @throws CloneNotSupportedException fail
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  public Object clone() throws CloneNotSupportedException {
    HardTokenIssuer clone = new HardTokenIssuer();
    HashMap clonedata = (HashMap) clone.saveData();

    Iterator i = (data.keySet()).iterator();
    while (i.hasNext()) {
      Object key = i.next();
      clonedata.put(key, data.get(key));
    }

    clone.loadData(clonedata);
    return clone;
  }
}
