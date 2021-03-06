/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

/**
 * Value class containing information about an available crypto token registered
 * to the CryptoTokenCache.
 *
 * @version $Id: AvailableCryptoToken.java 17625 2013-09-20 07:12:06Z netmackan
 *     $
 */
public class AvailableCryptoToken {

  /** Classpath. */
  private String classpath;
  /** Name. */
  private String name;
  /** Can be translated. */
  private boolean translateable;
  /** Enabled. */
  private boolean use;

 /**
  * @param aClasspath Classpath
  * @param aName Name
  * @param isTranslateable Can be translated
  * @param doUse Enabled
  */
  public AvailableCryptoToken(
      final String aClasspath,
      final String aName,
      final boolean isTranslateable,
      final boolean doUse) {
    this.classpath = aClasspath;
    this.name = aName;
    this.translateable = isTranslateable;
    this.use = doUse;
  }

  /**
   * Method returning the classpath used to create the plugin. Must implement
   * the HardCAToken interface.
   *
   * @return classpath
   */
  public String getClassPath() {
    return this.classpath;
  }

  /**
   * Method returning the general name of the plug-in used in the adminweb-gui.
   * If translateable flag is set then must the resource be in the language
   * files.
   *
   * @return name
   */
  public String getName() {
    return this.name;
  }

  /**
   * Indicates if the name should be translated in the adminweb-gui.
   *
   * @return boolean
   */
  public boolean isTranslateable() {
    return this.translateable;
  }

  /**
   * Indicates if the plug should be used in the system or if it's a dummy or
   * test class.
   *
   * @return boolean
   */
  public boolean isUsed() {
    return this.use;
  }

  /** Classpath is considered the key for AvailableCryptoToken. */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((classpath == null) ? 0 : classpath.hashCode());
    return result;
  }

  /** Classpath is considered the key for AvailableCryptoToken. */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    final AvailableCryptoToken other = (AvailableCryptoToken) obj;
    if (classpath == null) {
      if (other.classpath != null) {
        return false;
      }
    } else if (!classpath.equals(other.classpath)) {
      return false;
    }
    return true;
  }
}
