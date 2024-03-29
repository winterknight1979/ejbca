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
package org.cesecore.keys.token.p11;

import java.lang.reflect.Method;
import java.security.Key;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreError;
import org.cesecore.keys.token.p11.exception.P11RuntimeException;

/**
 * The normal way to access PKCS#11 is with a JCA/JCE provider. But there are a
 * lot of functionality that can't be done with the provider. Most of this
 * functionality is not needed by the CESeCore library but there are some
 * functionality that the library needs. This class will be used to access such
 * functions.
 *
 * <p>Functionalities of the Sun PKCS#11 implementation are used but this class
 * is not using this implementation directly - the class
 * sun.security.pkcs11.CESeCoreUtils is used to provide the interface to the Sun
 * PKCS#11 implementation.
 *
 * <p>Since non public resources of the Sun PKCS#11 implementation is used the
 * CESeCoreUtils class must be located in the sun.security.pkcs11 package. The
 * class must also be deployed as an installed extension (see
 * https://docs.oracle.com/javase/tutorial/ext/basics/install.html) in order to
 * use parts of the sun implementation.
 *
 * <p>To deploy it, copy the jar $EJBCA_HOME/dist/ext/primekey-sunP11.jar to one
 * of the directories defined by the 'java.ext.dirs' system property. But when
 * running clientToolBox this deployment is not needed since the start script
 * takes care of this.
 *
 * <p>If CESeCoreUtils is not in the classpath then this class will work as a
 * dummy and just return each call without doing anything.
 *
 * <p>When CESeCoreUtils is not in the classpath a warning will be written to
 * {@link Logger}.
 *
 * @version $Id: PKCS11Utils.java 25864 2017-05-17 13:46:10Z anatom $
 */
public final class PKCS11Utils {
    /** Logger. */
  private static final Logger LOG = Logger.getLogger(PKCS11Utils.class);
  /** Instance. */
  private static PKCS11Utils p11utils = null;
  /** Key. */
  private final Method makeKeyUnmodifiable;
  /** Key. */
  private final Method isKeyModifiable;
  /** Info. */
  private final Method securityInfo;

  private PKCS11Utils(
      final Method aMakeKeyUnmodifiable,
      final Method anIsKeyModifiable,
      final Method aSecurityInfo) {
    this.makeKeyUnmodifiable = aMakeKeyUnmodifiable;
    this.isKeyModifiable = anIsKeyModifiable;
    this.securityInfo = aSecurityInfo;
  }

  /** @return The instance. */
  public static synchronized PKCS11Utils getInstance() {
    if (p11utils != null) {
      return p11utils;
    }
    final String className = "sun.security.pkcs11.CESeCoreUtils";
    final Class<? extends Object> clazz;
    if (LOG.isDebugEnabled()) {
      final String propertyKey = "java.ext.dirs";
      LOG.debug(
          String.format(
              "The value of the system property '%s' is '%s'.",
              propertyKey, System.getProperty(propertyKey)));
    }
    try {
      clazz = Class.forName(className);
    } catch (ClassNotFoundException e) {
      LOG.warn(
          String.format(
              "Class '%s' not available. The attribute of all generated keys"
                  + " will have 'CKA_MODIFYABLE=TRUE'. A '%s' exception was"
                  + " thrown with the message '%s'.",
              className, e.getClass().getName(), e.getMessage()));
      p11utils = new PKCS11Utils(null, null, null);
      return p11utils;
    }
    try {
      p11utils =
          new PKCS11Utils(
              clazz.getMethod(
                  "makeKeyUnmodifiable", new Class[] {String.class, Key.class}),
              clazz.getMethod(
                  "isKeyModifiable", new Class[] {String.class, Key.class}),
              clazz.getMethod(
                  "securityInfo",
                  new Class[] {String.class, Key.class, StringBuilder.class}));
    } catch (NoSuchMethodException e) {
      throw new CesecoreError(
          String.format(
              "Not compatible version of %s. Required methods not found.",
              className),
          e);
    }
    return p11utils;
  }

  /**
   * If CESeCoreUtils is in the classpath then the CKA_MODIFIABLE attribute of
   * the key will be set to false.
   *
   * @param key key
   * @param providerName provider
   */
  public void makeKeyUnmodifiable(final Key key, final String providerName) {
    final String sError =
        "Not possible to set the attribute CKA_MODIFIABLE to false for the key"
            + " object.";
    if (this.makeKeyUnmodifiable == null) {
      LOG.warn(sError);
      return;
    }
    try {
      final Object oResult =
          this.makeKeyUnmodifiable.invoke(
              null, new Object[] {providerName, key});
      assert oResult instanceof Boolean;
      if (LOG.isDebugEnabled()) {
        if (((Boolean) oResult).booleanValue()) {
          LOG.debug(
              String.format(
                  "CKA_MODIFIABLE attribute set to false for key '%s'.", key));
        } else {
          LOG.debug(
              String.format(
                  "CKA_MODIFIABLE attribute not changed for key '%s'. It was"
                      + " already set to false, or could not be changed",
                  key));
        }
      }
    } catch (ReflectiveOperationException e) {
      throw new P11RuntimeException(sError, e);
    }
  }

  /**
   * Reads the CKA_MODIFIABLE attribute of the p11 key object.
   *
   * @param key key
   * @param providerName provider
   * @return the value of CKA_MODIFIABLE
   */
  public boolean isKeyModifiable(final Key key, final String providerName) {
    final String sError =
        "Not possible to read the attribute CKA_MODIFIABLE for the key object.";
    if (this.isKeyModifiable == null) {
      LOG.warn(sError);
      return true; // we say modifiable when we can't find out.
    }
    try {
      final Object oResult =
          this.isKeyModifiable.invoke(null, new Object[] {providerName, key});
      assert oResult instanceof Boolean;
      return ((Boolean) oResult).booleanValue();
    } catch (ReflectiveOperationException e) {
      throw new P11RuntimeException(sError, e);
    }
  }

  /**
   * Writes info about security related attributes of the key. If there is no
   * CESeCoreUtils in the classpath then a message that the class is not in the
   * classpath will be written.
   *
   * @param key key
   * @param providerName Provider
   * @param sb the info is written to this.
   */
  public void securityInfo(
      final Key key, final String providerName, final StringBuilder sb) {
    if (this.securityInfo == null) {
      sb.append("No CESeCoreUtils in classpath.");
      return;
    }
    try {
      this.securityInfo.invoke(null, new Object[] {providerName, key, sb});
    } catch (ReflectiveOperationException e) {
      throw new P11RuntimeException(
          "Not possible to read attributes from key object.", e);
    }
  }
}
