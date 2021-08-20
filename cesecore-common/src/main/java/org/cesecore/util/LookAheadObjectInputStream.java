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
package org.cesecore.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Can be used instead of ObjectInputStream to safely deserialize(readObject)
 * unverified serialized java object.
 *
 * <p>Simple usage: LookAheadObjectInputStream lookAheadObjectInputStream = new
 * LookAheadObjectInputStream(new ByteArrayInputStream(someByteArray);
 * HashSet&lt;Class&lt;? extends Serializable&gt;&gt; acceptedClasses = new
 * HashSet&lt;Class&lt;? extends Serializable&gt;&gt;(3);
 * acceptedClasses.add(X509Certificate.class);
 * lookAheadObjectInputStream.setAcceptedClasses(acceptedClasses);
 * lookAheadObjectInputStream.setMaxObjects(1); X509Certificate certificate =
 * (X509Certificate) lookAheadObjectInputStream.readObject(); //If serialized
 * object is not of the type X509Certificate SecurityException will be thrown
 *
 * <p>See "LookAheadObjectInputStreamTest" in the test code for more examples
 *
 * @version $Id: LookAheadObjectInputStream.java 34325 2020-01-17 15:40:23Z
 *     jekaterina_b_helmes $
 */
public class LookAheadObjectInputStream extends ObjectInputStream {
  /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(LookAheadObjectInputStream.class);
  /** Accepted. */
  private Set<Class<? extends Serializable>> acceptedClasses = null;
  /** Accepted. */
  private Set<Class<? extends Serializable>> acceptedClassesDynamically = null;
 /** Subclasses. */
  private boolean enabledSubclassing = false;
  /** Interfaces. */
  private boolean enabledInterfaceImplementations = false;
  /** Max objects. */
   private int maxObjects = 1;
  /** Bool. */
  private boolean enabledMaxObjects = true;
  /** Objects. */
  private int objCount = 0;
  /** Prefixes. */
  private List<String> allowedSubclassingPackagePrefixes = Arrays.asList();
  /** Prefixes. */
  private List<String> allowedInterfaceImplementationsPackagePrefixes =
      Arrays.asList();

  /**
   * @param inputStream stream
   * @throws IOException fail
   */
  public LookAheadObjectInputStream(final InputStream inputStream)
      throws IOException {
    super(inputStream);
    enableResolveObject(true);
  }

  /**
   * @return set of accepted classes etc. Classes that are allowed to be read
   *     from this ObjectInputStream. This set can be modified with:
   * @see LookAheadObjectInputStream#setAcceptedClasses
   */
  public Collection<Class<? extends Serializable>> getAcceptedClasses() {
    return acceptedClasses;
  }

  /**
   * @return true if class should be accepted if it extends super class directly
   *     or indirectly that is listed in accepted class names, false otherwise.
   */
  public boolean isEnabledSubclassing() {
    return enabledSubclassing;
  }

  /**
   * @param enabled True if class should be accepted if it extends super class
   *     directly or indirectly that is listed in accepted class names, false
   *     otherwise.
   * @param packagePrefixes An array of class name prefixes that are allowed to
   *     be sub-classed like "org.ejbca".
   */
  public void setEnabledSubclassing(
      final boolean enabled, final String... packagePrefixes) {
    this.enabledSubclassing = enabled;
    this.allowedSubclassingPackagePrefixes = Arrays.asList(packagePrefixes);
  }

  /**
   * @return true if class should be accepted if it implements an interface
   *     directly or indirectly that is listed in accepted class names, false
   *     otherwise.
   */
  public boolean isEnabledInterfaceImplementations() {
    return enabledInterfaceImplementations;
  }

  /**
   * @param enabled True if class should be accepted if it extends super class
   *     directly or indirectly that is listed in accepted class names, false
   *     otherwise.
   * @param packagePrefixes An array of class name prefixes that implementations
   *     must comply to if set like "org.ejbca".
   */
  public void setEnabledInterfaceImplementations(
      final boolean enabled, final String... packagePrefixes) {
    this.enabledInterfaceImplementations = enabled;
    this.allowedInterfaceImplementationsPackagePrefixes =
        Arrays.asList(packagePrefixes);
  }

  /**
   * Set accepted classes that can be deserialized using this
   * LookAheadObjectInputStream. Primitive types (boolean, char, int,...), their
   * wrappers (Boolean, Character, Integer,...) and String class are always
   * accepted. All other classes have to be specified with setAcceptedClassName*
   *
   * @param theAcceptedClasses Collection of class names that
   *     will be accepted for deserializing readObject. Default: null
   */
  public void setAcceptedClasses(
      final Set<Class<? extends Serializable>> theAcceptedClasses) {
    this.acceptedClasses = theAcceptedClasses;
    this.acceptedClassesDynamically = null;
  }

  /**
   * NOTE: If you want to re-use the same Set of accepted classes, you should
   * use {@link #setAcceptedClasses(Set)}
   *
   * <p>Set accepted classes that can be deserialized using this
   * LookAheadObjectInputStream. Primitive types (boolean, char, int,...), their
   * wrappers (Boolean, Character, Integer,...) and String class are always
   * accepted. All other classes have to be specified with setAcceptedClassName*
   *
   * @param theAcceptedClasses Collection of class names that will be
   *     accepted for deserializing readObject. Default: null
   */
  public void setAcceptedClasses(
      final Collection<Class<? extends Serializable>> theAcceptedClasses) {
    this.acceptedClasses = new HashSet<>(theAcceptedClasses);
    this.acceptedClassesDynamically = null;
  }

  /**
   * Get maximum amount of objects that can be read with this
   * LookAheadObjectInputStream.
   *
   * @return maximum amount of objects that can be read. Default: 1
   */
  public int getMaxObjects() {
    return maxObjects;
  }

  /**
   * Set maximum amount of objects that can be read with this
   * LookAheadObjectInputStream. This method will also reset internal counter
   * for read objects.
   *
   * @param theMaxObjects maximum amount of objects that can be read.
   *     Default: 1
   */
  public void setMaxObjects(final int theMaxObjects) {
    objCount = 0;
    this.maxObjects = theMaxObjects;
  }

  /** Overriding resolveObject to limit amount of objects that could be read. */
  @Override
  protected Object resolveObject(final Object obj) throws IOException {
    if (enabledMaxObjects && ++objCount > maxObjects) {
      throw new SecurityException(
          "Attempt to deserialize too many objects from stream. Limit is "
              + maxObjects);
    }
    Object object = super.resolveObject(obj);
    return object;
  }

  /**
   * Overrides resolveClass to check Class type of serialized object before
   * deserializing readObject.
   *
   * @throws SecurityException if serialized object is not one of following: 1)
   *     a String 2) a java primitive data type or its corresponding class
   *     wrapper 3) in the list of accepted classes 4) extends class from the
   *     list of accepted classes (if enabledSubclassing==true)
   */
  @Override
  protected Class<?> resolveClass(final ObjectStreamClass desc) // NOPMD: irred
      throws IOException, ClassNotFoundException {
    Class<?> resolvedClass = super.resolveClass(desc); // can be an array
    Class<?> resolvedClassType =
        resolvedClass.isArray()
            ? resolvedClass.getComponentType()
            : resolvedClass;
    if (isClassAlwaysWhiteListed(resolvedClassType)) {
      return resolvedClass;
    } else if (acceptedClasses != null && !acceptedClasses.isEmpty()) {
      if (acceptedClasses.contains(resolvedClassType)) {
        return resolvedClass;
      }
      if (acceptedClassesDynamically != null
          && acceptedClassesDynamically.contains(resolvedClassType)) {
        whitelistImplementation(resolvedClassType);
        return resolvedClass;
      }
      if (enabledSubclassing) {
        final String resolvedClassName = resolvedClassType.getName();
        if (LOG.isTraceEnabled()) {
          LOG.trace("resolvedClassName: " + resolvedClassName);
        }
        boolean allowedPrefixFound = false;
        for (final String allowedPrefix : allowedSubclassingPackagePrefixes) {
          if (resolvedClassName.startsWith(allowedPrefix + ".")) {
            allowedPrefixFound = true;
            break;
          }
        }
        if (allowedSubclassingPackagePrefixes.isEmpty() || allowedPrefixFound) {
          Class<?> superclass = resolvedClassType.getSuperclass();
          while (superclass != null) {
            if (acceptedClasses.contains(superclass)) {
              whitelistImplementation(resolvedClassType);
              return resolvedClass;
            }
            superclass = superclass.getSuperclass();
          }
        }
      }
      if (enabledInterfaceImplementations) {
        final String resolvedClassName = resolvedClassType.getName();
        if (LOG.isTraceEnabled()) {
          LOG.trace("resolvedClassName: " + resolvedClassName);
        }
        boolean allowedPrefixFound = false;
        for (final String allowedPrefix
            : allowedInterfaceImplementationsPackagePrefixes) {
          if (resolvedClassName.startsWith(allowedPrefix + ".")) {
            allowedPrefixFound = true;
            break;
          }
        }
        if (allowedInterfaceImplementationsPackagePrefixes.isEmpty()
            || allowedPrefixFound) {
          Class<?> superclass = resolvedClassType;
          while (superclass != null) {
            if (LOG.isTraceEnabled()) {
              LOG.trace(
                  superclass.getName()
                      + " implements "
                      + Arrays.toString(superclass.getInterfaces()));
            }
            for (final Class<?> implementedInterface
                : superclass.getInterfaces()) {
              if (acceptedClasses.contains(implementedInterface)) {
                whitelistImplementation(resolvedClassType);
                return resolvedClass;
              }
            }
            superclass = superclass.getSuperclass();
          }
        }
      }
    }
    final String msg =
        "Prevented unauthorized deserialization attempt for type '"
            + resolvedClassType.getName()
            + "': "
            + desc;
    LOG.info(msg);
    throw new SecurityException(msg);
  }

  /**
   * @param c Class
   * @return Bool
   */
  public static boolean isClassAlwaysWhiteListed(final Class<?> c) {
    final Class<?> classType = c.isArray() ? c.getComponentType() : c;
    return classType.equals(String.class)
        || classType.isPrimitive()
        || Boolean.class.isAssignableFrom(classType)
        || Number.class.isAssignableFrom(classType)
        || Character.class.isAssignableFrom(classType);
  }

  /**
   * Add the provided class and all its dependencies needed for deserialization
   * to this instance's accept class white list.
   *
   * @param resolvedClassType type
   */
  @SuppressWarnings("unchecked")
  private void whitelistImplementation(final Class<?> resolvedClassType) {
    final Set<Class<? extends Serializable>> newAcceptedClassesDynamically =
        new HashSet<>();
    newAcceptedClassesDynamically.add(
        (Class<? extends Serializable>) resolvedClassType);
    newAcceptedClassesDynamically.addAll(
        getRequiredClassesToSerialize(resolvedClassType));
    newAcceptedClassesDynamically.removeAll(acceptedClasses);
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "Dynamically white-listed these classes for deserialization: "
              + Arrays.toString(newAcceptedClassesDynamically.toArray()));
    }
    if (acceptedClassesDynamically == null) {
      acceptedClassesDynamically = new HashSet<>();
    }
    acceptedClassesDynamically.addAll(newAcceptedClassesDynamically);
  }

  /**
   * @param clazz class
   * @return a Set of all classes declared as non-transient, non-static field in
   *     the class and its superclasses if such is defined
   * @throws NoClassDefFoundError if class not found
   */
  @SuppressWarnings("unchecked")
  public static Set<Class<? extends Serializable>>
      getRequiredClassesToSerialize(final Class<?> clazz)
          throws NoClassDefFoundError {
    final Set<Class<? extends Serializable>> acceptedClasses = new HashSet<>();
    for (final Field field : clazz.getDeclaredFields()) {
      if (!Modifier.isStatic(field.getModifiers())
          && !Modifier.isTransient(field.getModifiers())) {
        Class<?> type =
            field.getType().isArray()
                ? field.getType().getComponentType()
                : field.getType();
        if (!Object.class.equals(type)) {
          acceptedClasses.add((Class<? extends Serializable>) type);
        }
        if (field.getGenericType() instanceof ParameterizedType
            && (Collection.class.isAssignableFrom(field.getType())
                || Map.class.isAssignableFrom(field.getType()))) {
          Type[] actualTypeArguments =
              ((ParameterizedType) field.getGenericType())
                  .getActualTypeArguments();
          for (Type actualType : actualTypeArguments) {
            if (actualType instanceof ParameterizedType) {
              actualType = ((ParameterizedType) actualType).getRawType();
            }
            if (actualType instanceof Serializable
                && !Object.class.equals(actualType)) {
              acceptedClasses.add((Class<? extends Serializable>) actualType);
            }
          }
        }
      }
    }
    final Class<?> superClass = clazz.getSuperclass();
    if (superClass != null) {
      acceptedClasses.addAll(getRequiredClassesToSerialize(superClass));
    }
    return acceptedClasses;
  }

  /** @return true if checking for max objects is enabled, false otherwise */
  public boolean isEnabledMaxObjects() {
    return enabledMaxObjects;
  }

  /**
   * Enable or disable checking for max objects that can be read. This method
   * will also reset internal counter for read objects.
   *
   * @param theEnabledMaxObjects true or false
   */
  public void setEnabledMaxObjects(final boolean theEnabledMaxObjects) {
    objCount = 0;
    this.enabledMaxObjects = theEnabledMaxObjects;
  }
}
