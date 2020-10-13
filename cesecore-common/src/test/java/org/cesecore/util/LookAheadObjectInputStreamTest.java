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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests LookAheadObjectInputStream class that can be used to prevent java
 * deserialization issue.
 *
 * @version $Id: LookAheadObjectInputStreamTest.java 34262 2020-01-13 12:27:31Z
 *     jeklund $
 */
public class LookAheadObjectInputStreamTest {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(LookAheadObjectInputStreamTest.class);

  /** setup.
 * @throws Exception fail*/
  @Before
  public void setup() throws Exception { }
/** Teardown.
 * @throws Exception fail*/
  @After
  public void tearDown() throws Exception { }

  private static class ExploitClass implements Serializable {
    private static final long serialVersionUID = 1L;

    private void readObject(final java.io.ObjectInputStream stream)
        throws IOException, ClassNotFoundException {
      stream.defaultReadObject();
      throw new IllegalStateException("Run exploit code...");
    }
  }

  private static class GoodClass1 implements Serializable {
    private static final long serialVersionUID = 2L;
   /** Data. */
    private int data = 0;

   GoodClass1(final int aData) {
      this.data = aData;
    }

    public int getData() {
      return data;
    }
  }

  private static class GoodClass2 implements Serializable {
    private static final long serialVersionUID = 3L;
    /** Data. */
    private int data = 0;

    GoodClass2(final int aData) {
      this.data = aData;
    }

    public int getData() {
      return data;
    }
  }

  private abstract static class GoodAbstractClass implements Serializable {
    private static final long serialVersionUID = 2L;
  }

  private static class GoodExtendedClass extends GoodAbstractClass {
    private static final long serialVersionUID = 5L;
  }

  private static class GoodExtendedExtendedClass extends GoodExtendedClass {
    private static final long serialVersionUID = 6L;
  }

  private interface AnimalInterface extends Serializable {
    String getValue();
  }

  private static class BadDog implements AnimalInterface {
    private static final long serialVersionUID = 7L;
    /** Obj. */
    private Object object;

    BadDog(final Object anObject) {
      this.object = anObject;
    }

    @Override
    public String getValue() {
      return String.valueOf(object);
    }
  }

  private static class ExternalizableClass implements Externalizable {
      /** Obj. */
    private final boolean writeExploitObject;

    @SuppressWarnings("unused")
    ExternalizableClass() {
      this(false);
    }

    ExternalizableClass(final boolean aWriteExploitObject) {
      this.writeExploitObject = aWriteExploitObject;
    }

    @Override
    public void writeExternal(final ObjectOutput out) throws IOException {
      out.writeObject(
          writeExploitObject ? new ExploitClass() : new GoodClass1(123));
    }

    @Override
    public void readExternal(final ObjectInput in)
        throws IOException, ClassNotFoundException {
      final GoodClass1 obj = (GoodClass1) in.readObject();
      assertEquals("Got wrong data in nested object.", 123, obj.getData());
    }
  }

  /**
   * Test that accepted java objects can be deserialized.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingAcceptedJavaObject() throws Exception {
    LOG.trace(">testDeserializingAcceptedJavaObject");
    final byte[] serializedData = getEncoded(new GoodClass2(2));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, GoodClass2.class));
      laois.setMaxObjects(1);
      GoodClass2 goodClass = (GoodClass2) laois.readObject();
      assertEquals(
          "Data corrupted during testDeserializingAcceptedJavaObject",
          2,
          goodClass.getData());
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingAcceptedJavaObject");
    }
    LOG.trace("<testDeserializingAcceptedJavaObject");
  }

  /**
   * Test that non-accepted java objects can NOT be deserialized
   * (SecurityException has to be thrown).
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingNonAcceptedJavaObject() throws Exception {
    LOG.trace(">testDeserializingNonAcceptedJavaObject");
    final byte[] serializedData = getEncoded(new ExploitClass());
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, GoodClass2.class));
      laois.readObject();
      fail("Deserialization was unexpectedly successful.");
    } catch (IllegalStateException e) {
      fail("ExploitClass code was not caught with LookAheadSerializer");
    } catch (SecurityException e) {
      // Good
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingNonAcceptedJavaObject");
    }
    LOG.trace("<testDeserializingNonAcceptedJavaObject");
  }

  /**
   * Test that non-initialized LookAheadObjectInputStream can not read any
   * objects (except default (primitive) ones).
   *
   * @throws Exception fail
   */
  @Test
  public void testNonInitializedLookAheadObjectInputStream() throws Exception {
    LOG.trace(">testNonInitializedLookAheadObjectInputStream");
    final byte[] serializedData = getEncoded(new ExploitClass());
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(new HashSet<Class<? extends Serializable>>());
      laois.readObject();
      fail("Deserialization was unexpectedly successful.");
    } catch (IllegalStateException e) {
      fail("ExploitClass code was not caught with LookAheadObjectInputStream");
    } catch (SecurityException e) {
      // Good
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testNonInitializedLookAheadObjectInputStream");
    }
    LOG.trace("<testNonInitializedLookAheadObjectInputStream");
  }

  /**
   * Test that array of accepted java objects can be deserialized.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingAcceptedJavaObjectArray() throws Exception {
    LOG.trace(">testDeserializingAcceptedJavaObjectArray");
    final byte[] serializedData = getEncoded((Object) new GoodClass2[3]);
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, GoodClass2.class));
      GoodClass2[] deserialized = (GoodClass2[]) laois.readObject();
      assertEquals(
          "Data corrupted during testDeserializingAcceptedJavaObjectArray",
          3,
          deserialized.length);
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingAcceptedJavaObjectArray");
    }
    LOG.trace("<testDeserializingAcceptedJavaObjectArray");
  }

  /**
   * Test that array of non-accepted java objects can NOT be deserialized
   * (SecurityException has to be thrown). Although deserialization of
   * non-accepted class is not exploit by itself, it seems natural to not allow
   * it.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingNonAcceptedJavaObjectArray() throws Exception {
    LOG.trace(">testDeserializingNonAcceptedJavaObjectArray");
    final byte[] serializedData = getEncoded((Object) new ExploitClass[3]);
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, GoodClass2.class));
      laois.readObject();
      fail("Deserialization was unexpectedly successful.");
    } catch (IllegalStateException e) {
      fail("ExploitClass code was not caught with LookAheadObjectInputStream");
    } catch (SecurityException e) {
      // Good
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingNonAcceptedJavaObjectArray");
    }
    LOG.trace("<testDeserializingNonAcceptedJavaObjectArray");
  }

  /**
   * Test that array of mixed (accepted and non-accepted) objects can NOT be
   * deserialized.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingMixedObjectArray() throws Exception {
    LOG.trace(">testDeserializingMixedObjectArray");
    final Object[] mixedObjects =
        new Object[] {"Dummy string", new ExploitClass(), new GoodClass1(1)};
    final byte[] serializedData = getEncoded((Object) mixedObjects);
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, GoodClass2.class));
      laois.readObject();
      fail(
          "ExploitClass code was not caught with LookAheadObjectInputStream"
              + " during testDeserializingMixedObjectArray");
    } catch (SecurityException e) {
      // Good
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingMixedObjectArray");
    }
    LOG.trace("<testDeserializingMixedObjectArray");
  }
  /**
   * Test.
   * @throws Exception fail
   */
  @Test
  public void testDeserializeExternalizable() throws Exception {
    LOG.trace(">testDeserializeExternalizable");
    // Write exploit object that will be read be readExternal
    final byte[] serializedData = getEncoded(new ExternalizableClass(true));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, ExternalizableClass.class));
      // deserializing Externalizable object
      laois.readObject();
      fail("Deserialization was successful. This could be a bug in the test");
    } catch (IllegalStateException e) {
      fail("ExploitClass code was not caught with LookAheadSerializer");
    } catch (SecurityException e) {
      // Good
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializeExternalizable");
    }
    LOG.trace("<testDeserializeExternalizable");
  }

  /**
   * Test limiting maximum count of objects that can be deserialized.
   *
   * @throws Exception fail
   */
  @Test
  public void testLimitingMaxObjects() throws Exception {
    LOG.trace(">testLimitingMaxObjects");
    final byte[] serializedData =
        getEncoded(new GoodClass1(1), new GoodClass1(2), new GoodClass2(3));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(GoodClass1.class, GoodClass2.class));
      laois.setEnabledSubclassing(true);
      laois.setEnabledMaxObjects(true);
      laois.setMaxObjects(2);
      int i = 0;
      while (i++ < 3) {
        laois.readObject();
      }
      fail(
          "Deserialized more then specified max objects during"
              + " testLimitingMaxObjects");
    } catch (SecurityException e) {
      // Good
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testLimitingMaxObjects");
    }
    LOG.trace("<testLimitingMaxObjects");
  }

  /**
   * Test that Primitive types (boolean, char, int,...), their wrappers
   * (Boolean, Character, Integer,...) and String class can always be
   * deserialized.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingPrimitiveTypes() throws Exception {
    LOG.trace(">testDeserializingPrimitiveTypes");
    final byte[] serializedData =
        getEncoded(
            (byte) 0,
            (short) 1,
            (int) 2,
            (long) 3,
            (float) 4,
            (double) 5,
            Byte.valueOf((byte) 6),
            Short.valueOf((short) 7),
            Integer.valueOf((int) 8),
            Long.valueOf((long) 9),
            Float.valueOf((float) 10),
            Double.valueOf((double) 11),
            false,
            Boolean.valueOf(true),
            'c',
            "String",
            new byte[1],
            new short[1],
            new int[1],
            new long[1],
            new float[1],
            new double[1],
            new boolean[1]);
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setEnabledMaxObjects(false);
      assertEquals(
          "Data 0 corrupted during testDeserializingPrimitiveTypes",
          (byte) 0,
          (byte) laois.readObject());
      assertEquals(
          "Data 1 corrupted during testDeserializingPrimitiveTypes",
          (short) 1,
          (short) laois.readObject());
      assertEquals(
          "Data 2 corrupted during testDeserializingPrimitiveTypes",
          (int) 2,
          (int) laois.readObject());
      assertEquals(
          "Data 3 corrupted during testDeserializingPrimitiveTypes",
          (long) 3,
          (long) laois.readObject());
      assertEquals(
          "Data 4 corrupted during testDeserializingPrimitiveTypes",
          (float) 4,
          (float) laois.readObject(),
          0);
      assertEquals(
          "Data 5 corrupted during testDeserializingPrimitiveTypes",
          (double) 5,
          (double) laois.readObject(),
          0);
      assertEquals(
          "Data 6 corrupted during testDeserializingPrimitiveTypes",
          6,
          ((Byte) laois.readObject()).byteValue());
      assertEquals(
          "Data 7 corrupted during testDeserializingPrimitiveTypes",
          7,
          ((Short) laois.readObject()).shortValue());
      assertEquals(
          "Data 8 corrupted during testDeserializingPrimitiveTypes",
          8,
          ((Integer) laois.readObject()).intValue());
      assertEquals(
          "Data 9 corrupted during testDeserializingPrimitiveTypes",
          9,
          ((Long) laois.readObject()).longValue());
      assertEquals(
          "Data 10 corrupted during testDeserializingPrimitiveTypes",
          10,
          ((Float) laois.readObject()).floatValue(),
          0);
      assertEquals(
          "Data 11 corrupted during testDeserializingPrimitiveTypes",
          11,
          ((Double) laois.readObject()).doubleValue(),
          0);
      assertEquals(
          "Data 12 corrupted during testDeserializingPrimitiveTypes",
          false,
          (boolean) laois.readObject());
      assertEquals(
          "Data 13 corrupted during testDeserializingPrimitiveTypes",
          true,
          ((Boolean) laois.readObject()).booleanValue());
      assertEquals(
          "Data 14 corrupted during testDeserializingPrimitiveTypes",
          'c',
          (char) laois.readObject());
      assertEquals(
          "Data 15 corrupted during testDeserializingPrimitiveTypes",
          "String",
          ((String) laois.readObject()));
      assertEquals(
          "Data 16 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((byte[]) laois.readObject()).length);
      assertEquals(
          "Data 17 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((short[]) laois.readObject()).length);
      assertEquals(
          "Data 18 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((int[]) laois.readObject()).length);
      assertEquals(
          "Data 19 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((long[]) laois.readObject()).length);
      assertEquals(
          "Data 20 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((float[]) laois.readObject()).length);
      assertEquals(
          "Data 21 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((double[]) laois.readObject()).length);
      assertEquals(
          "Data 22 corrupted during testDeserializingPrimitiveTypes",
          1,
          ((boolean[]) laois.readObject()).length);
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingPrimitiveTypes");
    }
    LOG.trace("<testDeserializingPrimitiveTypes");
  }

  /**
   * Test deserializing subclass.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingExtendedClasses() throws Exception {
    LOG.trace(">testDeserializingExtendedClasses");
    final byte[] serializedData =
        getEncoded(new GoodExtendedClass(), new GoodExtendedExtendedClass());
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData)); ) {
      Collection<Class<? extends Serializable>> acceptedClasses =
          new ArrayList<Class<? extends Serializable>>(3);
      acceptedClasses.add(GoodAbstractClass.class);
      laois.setAcceptedClasses(acceptedClasses);
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(true);
      @SuppressWarnings("unused")
      GoodExtendedClass goodExtendedClass =
          (GoodExtendedClass) laois.readObject();
      @SuppressWarnings("unused")
      GoodExtendedExtendedClass goodExtendedExtendedClass =
          (GoodExtendedExtendedClass) laois.readObject();
    } catch (Exception e) {
      fail(
          "Unexpected exception: "
              + e.getMessage()
              + " during testDeserializingExtendedClasses");
    }
    LOG.trace("<testDeserializingExtendedClasses");
  }

  /**
   * Test deserializing inherited class without allowing the superclass.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingExtendedClassesWithoutAllowingSuperclass()
      throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new GoodExtendedExtendedClass());
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(GoodExtendedExtendedClass.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(false);
      laois.readObject();
      fail("SecurityException should have been thrown.");
    } catch (SecurityException e) {
      // Good
      LOG.info(
          "Succuessfully prevented deserialization of non-whitelisted super"
              + " class: "
              + e.getMessage());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(
                  GoodExtendedExtendedClass.class, GoodExtendedClass.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(false);
      laois.readObject();
      fail("SecurityException should have been thrown.");
    } catch (SecurityException e) {
      // Good
      LOG.info(
          "Succuessfully prevented deserialization of non-whitelisted super"
              + " class: "
              + e.getMessage());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(
                  GoodExtendedExtendedClass.class,
                  GoodExtendedClass.class,
                  GoodAbstractClass.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(false);
      assertEquals(
          GoodExtendedExtendedClass.class, laois.readObject().getClass());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test deserializing interface implementations.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingInterfaceImplementationDenied()
      throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new BadDog("regular String"));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(AnimalInterface.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(true);
      laois.readObject();
      fail("SecurityException should have been thrown.");
    } catch (SecurityException e) {
      // Good
      LOG.info(
          "Succuessfully prevented deserialization of non-whitelisted"
              + " implementation of whitelisted interface: "
              + e.getMessage());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test deserializing interface implementations where implementation is not
   * belonging to the correct package.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingInterfaceImplementationRestrictedToPackageFail()
      throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new BadDog("regular String"));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(AnimalInterface.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(false);
      laois.setEnabledInterfaceImplementations(true, "com.sploitsrus");
      laois.readObject();
      fail("SecurityException should have been thrown.");
    } catch (SecurityException e) {
      // Good
      LOG.info(
          "Succuessfully prevented deserialization of non-whitelisted"
              + " implementation of whitelisted interface: "
              + e.getMessage());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test deserializing interface implementations where implementation is not
   * belonging to the correct package.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingInterfaceImplementationRestrictedToPackageOk()
      throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new BadDog("regular String"));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(AnimalInterface.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(false);
      laois.setEnabledInterfaceImplementations(
          true, "org.cesecore", "org.ejbca");
      assertEquals("regular String", ((BadDog) laois.readObject()).getValue());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test deserializing interface implementations.
   *
   * @throws Exception fail
   */
  @Test
  public void
      testDeserializingInterfaceImplementationAllowedWithoutSubclassing()
          throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new BadDog("regular String"));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(AnimalInterface.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(false);
      laois.setEnabledInterfaceImplementations(true);
      assertEquals("regular String", ((BadDog) laois.readObject()).getValue());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test deserializing interface implementations (when also subclassing is
   * enabled).
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingInterfaceImplementationAllowedWithSubclassing()
      throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new BadDog("regular String"));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(AnimalInterface.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(true);
      laois.setEnabledInterfaceImplementations(true);
      assertEquals("regular String", ((BadDog) laois.readObject()).getValue());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test deserializing class where field object is not whitelisted.
   *
   * @throws Exception fail
   */
  @Test
  public void testDeserializingWithNonWhitelistedField() throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData = getEncoded(new BadDog(new ExploitClass()));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          new HashSet<Class<? extends Serializable>>(
              Arrays.asList(BadDog.class)));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(true);
      ((BadDog) laois.readObject()).getValue();
    } catch (SecurityException e) {
      // Good
      LOG.info(
          "Succuessfully prevented deserialization of non-whitelisted class: "
              + e.getMessage());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  /**
   * Test commonly serialized class combo.
   *
   * @throws Exception fail
   */
  @Test
  public void testAuthenticationToken() throws Exception {
    LOG.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
    final byte[] serializedData =
        getEncoded(
            new AlwaysAllowLocalAuthenticationToken(
                new UsernamePrincipal("test")));
    try (LookAheadObjectInputStream laois =
        new LookAheadObjectInputStream(
            new ByteArrayInputStream(serializedData))) {
      laois.setAcceptedClasses(
          Arrays.asList(
              AuthenticationToken.class,
              HashSet.class,
              UsernamePrincipal.class));
      laois.setEnabledMaxObjects(false);
      laois.setEnabledSubclassing(true, "org.cesecore");
      assertEquals(
          "test",
          ((AlwaysAllowLocalAuthenticationToken) laois.readObject())
              .getPrincipals()
              .iterator()
              .next()
              .getName());
    } catch (Exception e) {
      LOG.trace(e.getMessage(), e);
      fail("Unexpected exception: " + e.getMessage());
    }
    LOG.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
  }

  private byte[] getEncoded(final Object... objects) throws IOException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos); ) {
      for (final Object object : objects) {
        oos.writeObject(object);
      }
    }
    return baos.toByteArray();
  }
}
