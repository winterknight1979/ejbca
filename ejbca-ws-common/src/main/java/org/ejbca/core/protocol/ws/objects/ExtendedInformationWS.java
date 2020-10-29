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
package org.ejbca.core.protocol.ws.objects;

import java.io.Serializable;

/**
 * Class used to represent extended information in userdata in the WebService
 * API. <br>
 * &nbsp;<br>
 * Example code:
 *
 * <pre>
 *   UserDataVOWS user = new UserDataVOWS ();
 *   user.setUsername ("tester");
 *   user.setPassword ("foo123");
 *     .
 *     .
 *     .
 *   List&lt;ExtendedInformationWS&gt; ei = new ArrayList&lt;
 *      ExtendedInformationWS&gt; ();
 *   ei.add (new ExtendedInformationWS ("A name", "A value));
 *   ei.add (new ExtendedInformationWS ("Another name", "Another value"));
 *     .
 *     .
 *   user.setExtendedInformation (ei);
 * </pre>
 *
 * @version $Id: ExtendedInformationWS.java 27586 2017-12-19 13:36:36Z
 *     mikekushner $
 */
public class ExtendedInformationWS implements Serializable {

  /** */
  private static final long serialVersionUID = 1L;

  /** Param. */
  private String name;

  /** Param. */
  private String value;

  /** Emtpy constructor used by internally by web services. */
  public ExtendedInformationWS() { }

  /**
   * Constructor used when creating a new ExtendedInformationWS.
   *
   * @param aname Name (key) to set.
   * @param avalue Value to set.
   */
  public ExtendedInformationWS(String aname, String avalue) {
    super();
    this.name = aname;
    this.value = avalue;
  }

  /** @return the name (key) property */
  public String getName() {
    return this.name;
  }

  /** @param aname Name (key) to set */
  public void setName(String aname) {
    this.name = aname;
  }

  /** @return the value property */
  public String getValue() {
    return value;
  }

  /** @param avalue Value to set. */
  public void setValue(String avalue) {
    this.value = avalue;
  }
}
