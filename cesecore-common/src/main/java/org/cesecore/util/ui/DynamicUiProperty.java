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
package org.cesecore.util.ui;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.SerializationUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.util.Base64Util;
import org.cesecore.util.LookAheadObjectInputStream;

/**
 * Allows creation of dynamic properties for display in the UI.
 *
 * @version $Id: DynamicUiProperty.java 34324 2020-01-17 12:22:39Z henriks $
 * @param <T> Type
 */
public class DynamicUiProperty<T extends Serializable> // NOPMD
    implements Serializable, Cloneable {

  private static final long serialVersionUID = 1L;

  /** Literal for list separator. */
  public static final String LIST_SEPARATOR = ";";

  /** Literal for no rendering. */
  public static final String RENDER_NONE = "none";

  /** Literal for rendering hint for labels. */
  public static final String RENDER_LABEL = "label";

  /** Literal for rendering hint for text fields. */
  public static final String RENDER_TEXTFIELD = "textfield";

  /** Literal for rendering hint for text areas. */
  public static final String RENDER_TEXTAREA = "textarea";

  /** Literal for rendering hint for check boxes. */
  public static final String RENDER_CHECKBOX = "checkbox";

  /** Literal for rendering hint for buttons. */
  public static final String RENDER_BUTTON = "button";

  /** Literal for rendering hint for text fields. */
  public static final String RENDER_SELECT_ONE = "selectone";

  /** Literal for rendering hint for text fields. */
  public static final String RENDER_SELECT_MANY = "selectmany";

  /** Literal for rendering hint for file chooser. */
  public static final String RENDER_FILE_CHOOSER = "filechooser";

  /** The name (key) of the property. */
  private String name;

  /** Default value or null. */
  private T defaultValue;

  /** Property values (or value at index 0). */
  private List<T> values = new ArrayList<>();

  /** Value range or null. */
  private Collection<T> possibleValues;

  /** If the UI widget is supposed to be filled with a value. */
  private boolean required = false;

  /** If the UI widget is supposed to be disabled. */
  private boolean disabled = false;

  /** If the value has to be stored in the domain object properties. */
  private boolean transientValue = false;

  /**
   * If a domain object property is stored as semi-colon separated string
   * instead of {@link java.util.List}.
   */
  private boolean saveListAsString = false;

  /** Hint. */
  private String renderingHint;

  /** True if I18N labels has to be rendered. */
  private boolean labeled = false;

  /** List of I18N keys / labels if available. */
  private Map<?, String> labels = new LinkedHashMap<Object, String>();

  /**
   * Flag to indicate that the property is displayed as label in the label
   * column only (there will be no validation if available, etc.).
   */
  private boolean labelOnly = false;

  /** Action callback. */
  private DynamicUiActionCallback actionCallback;

  /** Property callback (default: NONE). */
  private DynamicUiPropertyCallback propertyCallback =
      DynamicUiPropertyCallback.NONE;

  /** Property type. */
  private Class<? extends Serializable> type;

  /** Field validator (will be applied if not null). */
  private DynamicUiPropertyValidator<T> validator = null;

  /** Reference to the holder object (implements coupling to components). */
  private DynamicUiModel dynamicUiModel;

  /** Denotes whether this property can have multiple values. */
  private boolean hasMultipleValues = false;

  /**
   * Constructor required by java.lang.Serializable. Type must be set if this
   * constructor is used.
   */
  public DynamicUiProperty() { }

  /**
   * Constructs a dynamic UI property rendered as a simple label in the UI.
   *
   * @param aName the name of this property, for display in the UI
   */
  @SuppressWarnings("unchecked")
  public DynamicUiProperty(final String aName) {
    this.name = aName;
    this.type = String.class;
    this.defaultValue = (T) aName;
    this.values.add((T) aName);
    this.possibleValues = null;
    setLabelOnly(true);
    setTransientValue(true);
  }

  /**
   * Constructor. Note the T must implement toString().
   *
   * @param aName the name of this property, for display in the UI.
   * @param aDefaultValue the default value, if any.
   */
  public DynamicUiProperty(final String aName, final T aDefaultValue) {
    this.name = aName;
    this.defaultValue = aDefaultValue;
    this.values.add(aDefaultValue);
    this.possibleValues = null;
    if (aDefaultValue != null) {
      this.type = aDefaultValue.getClass();
    }
  }

  /**
   * Constructor. Note the T must implement toString().
   *
   * @param aType Class type (as workaround for forgotten parameter type at
   *     runtime).
   * @param aName the name of this property, for display in the UI.
   * @param aDefaultValue the default value, if any.
   */
  @SuppressWarnings("unchecked")
  public DynamicUiProperty(
      final Class<T> aType, final String aName, final T aDefaultValue) {
    this.name = aName;
    this.defaultValue = aDefaultValue;
    if (String.class.equals(aType)
        && aDefaultValue != null
        && ((String) aDefaultValue).contains(LIST_SEPARATOR)) {
      for (String value
          : StringUtils.split((String) aDefaultValue, LIST_SEPARATOR)) {
        this.values.add((T) value);
      }
    } else {
      this.values.add(aDefaultValue);
    }
    this.possibleValues = null;
    this.type = aType;
    if (File.class.getName().equals(getType().getName())
        || byte[].class.getName().equals(getType().getName())) {
      setRenderingHint(RENDER_FILE_CHOOSER);
    }
  }

  /**
   * Constructor. Note the T must implement toString().
   *
   * @param aName the name of this property, for display in the UI.
   * @param aDefaultValue the default value, if any. May not be null.
   * @param thePossibleValues a Collection of possible values. If set to null no
   *     validation will be performed, if set to an empty list then values are
   *     presumed to be set at runtime.
   */
  public DynamicUiProperty(
      final String aName,
      final T aDefaultValue,
      final Collection<T> thePossibleValues) {
    this(aName, aDefaultValue);
    this.possibleValues = thePossibleValues;
  }

  /**
   * Constructor. Note the T must implement toString().
   *
   * @param aType Class type (as workaround for forgotten parameter type at
   *     runtime).
   * @param aNname The name of this property, for display in the UI
   * @param aDefaultValue the default value, if any.
   * @param thePossibleValues a Collection of possible values. If set to null no
   *     validation will be performed, if set to an empty list then values are
   *     presumed to be set at runtime.
   */
  public DynamicUiProperty(
      final Class<T> aType,
      final String aNname,
      final T aDefaultValue,
      final Collection<T> thePossibleValues) {
    this(aType, aNname, aDefaultValue);
    this.possibleValues = thePossibleValues;
  }

  /**
   * Copy constructor for DynamicUiProperty objects.
   *
   * @param original the original property
   */
  @SuppressWarnings("unchecked")
  public DynamicUiProperty(final DynamicUiProperty<T> original) {
    this.name = original.getName();
    this.type = original.getType();
    this.required = original.isRequired();
    this.renderingHint = original.getRenderingHint();
    this.labelOnly = original.isLabelOnly();
    this.labeled = original.isI18NLabeled();
    this.defaultValue = original.getDefaultValue();
    this.setHasMultipleValues(original.getHasMultipleValues());
    try {
      if (!original.getHasMultipleValues()) {
        setValue((T) SerializationUtils.clone(original.getValue()));
      } else {
        final List<T> clonedValues = new ArrayList<>();
        for (T value : original.getValues()) {
          clonedValues.add((T) SerializationUtils.clone(value));
        }
        setValues(clonedValues);
      }
    } catch (PropertyValidationException e) {
      throw new IllegalArgumentException(
          "Invalid value was intercepted in copy constructor, which should not"
              + " happen.",
          e);
    }
    this.possibleValues = original.getPossibleValues();
    this.propertyCallback = original.getPropertyCallback();
    this.actionCallback = original.getActionCallback();
    this.validator = original.validator;
    this.disabled = original.isDisabled();
    this.dynamicUiModel = original.getDynamicUiModel();
    this.transientValue = original.isTransientValue();
  }

  /**
   * Sets the dynamic UI model reference.
   *
   * @param aDynamicUiModel the dynamic UI model reference.
   */
  public void setDynamicUiModel(final DynamicUiModel aDynamicUiModel) {
    this.dynamicUiModel = aDynamicUiModel;
  }

  /**
   * Gets the dynamic UI model reference.
   *
   * @return the dynamic UI model reference.
   */
  public DynamicUiModel getDynamicUiModel() {
    return dynamicUiModel;
  }

  /**
   * Returns a value of type T from a string. Limited to the basic java types
   * {@link Integer}, {@link String}, {@link Boolean}, {@link Float}, {@link
   * Long}
   *
   * @param value the value to translate
   * @return and Object instantiated as T, or null if value was not of a usable
   *     class or was invalid for T
   */
  public Serializable valueOf(final String value) {
    // ECA-6320 Re-factor: New implementation uses constructor with type
    // parameter (not only Generic Operator because this information is lost at
    // runtime!).
    // The defaultValue of the old implementation MUST NOT be null, the one of
    // the new can be!
    if (defaultValue instanceof MultiLineString) {
      return new MultiLineString(value);
    } else if (defaultValue instanceof String) {
      return value;
    } else if (defaultValue instanceof Boolean) {
      if (value.equals(Boolean.TRUE.toString())
          || value.equals(Boolean.FALSE.toString())) {
        return Boolean.valueOf(value);
      }
    } else if (defaultValue instanceof Integer) {
      try {
        return Integer.valueOf(value);
      } catch (NumberFormatException e) {
        return null;
      }
    } else if (defaultValue instanceof Long) {
      try {
        return Long.valueOf(value);
      } catch (NumberFormatException e) {
        return null;
      }
    } else if (defaultValue instanceof BigInteger) {
      try {
        return new BigInteger(value);
      } catch (NumberFormatException e) {
        return null;
      }
    } else if (defaultValue instanceof Float) {
      try {
        return Float.valueOf(value);
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return null;
  }

  /**
   * Gets a string representation of the value (for example the string '1' for
   * the Integer with value 1. Value is retrieved inside as getValue()).
   *
   * @return string the string representation.
   */
  public String getValueAsString() {
    Serializable value = getValue();
    String result = StringUtils.EMPTY;
    if (value instanceof MultiLineString) {
      result = ((MultiLineString) value).getValue();
    } else if (value instanceof String) {
      result = (String) value;
    } else if (value instanceof RadioButton) {
      result = ((RadioButton) value).getLabel();
    } else {
      result = ((Object) value).toString();
    }
    return result;
  }

  /**
   * Gets the name (or key) of the property.
   *
   * @return the name.
   */
  public String getName() {
    return name;
  }

  /**
   * Gets if the UI widget is supposed to be filled with a value.
   *
   * @return true if is required.
   */
  public boolean isRequired() {
    return required;
  }

  /**
   * Sets if the UI widget is supposed to be filled with a value.
   *
   * @param isRequired true if required.
   */
  public void setRequired(final boolean isRequired) {
    this.required = isRequired;
  }

  /**
   * Gets if the UI widget is supposed to be disabled.
   *
   * @return true if disabled.
   */
  public boolean isDisabled() {
    return disabled;
  }

  /**
   * Sets if the UI widget is supposed to be disabled.
   *
   * @param isDisabled true if disabled.
   */
  public void setDisabled(final boolean isDisabled) {
    this.disabled = isDisabled;
  }

  /**
   * Gets weather the value has to be stored in the domain objects properties.
   *
   * @return true if transient.
   */
  public boolean isTransientValue() {
    return transientValue;
  }

  /**
   * Sets weather the value has to be stored in the domain objects properties.
   *
   * @param isTransientValue true if transient.
   */
  public void setTransientValue(final boolean isTransientValue) {
    this.transientValue = isTransientValue;
  }

  /**
   * Is set to true if I18N labels has to be rendered (mainly used in facelets).
   *
   * @return true if I18N labels has to be rendered.
   */
  public boolean isI18NLabeled() {
    return labeled;
  }

  /**
   * Gets if only the label has to be rendered.
   *
   * @return if the entry has to be rendered as label only (first column only).
   */
  public boolean isLabelOnly() {
    return labelOnly;
  }

  /**
   * Sets if only the label has to be rendered.
   *
   * @param isLabelOnly true if the entry has to be rendered as label only
   * (first column only)
   */
  public void setLabelOnly(final boolean isLabelOnly) {
    this.labelOnly = isLabelOnly;
  }

  /**
   * @return the type class of this property, based on the default value. If the
   *     default was null, then the type has to be set explicitly.
   */
  public Class<? extends Serializable> getType() {
    return type;
  }

  /**
   * @param aType type
   */
  public void setType(final Class<? extends Serializable> aType) {
    this.type = aType;
  }

  /**
   * Gets the given value of type &lt;T&gt;.
   *
   * @return the value.
   */
  public T getDefaultValue() {
    return defaultValue;
  }

  /**
   * Sets the given value of type &lt;T&gt;.
   *
   * @param theDefaultValue the value.
   */
  public void setDefaultValue(final T theDefaultValue) {
    this.defaultValue = theDefaultValue;
  }

  /**
   * Gets the list of current values.
   *
   * @return the list.
   */
  public List<T> getValues() {
    if (!hasMultipleValues) {
      throw new IllegalStateException(
          "Attempted to draw multiple values from a dynamic property with a"
              + " single value for "
              + getName());
    }
    return values;
  }

  /**
   * Gets the current value.
   *
   * @return the value.
   */
  public T getValue() {
    if (hasMultipleValues) {
      throw new IllegalStateException(
          "Attempted to draw single value from a dynamic property with"
              + " multiple value for "
              + getName());
    }
    return values.get(0);
  }

  /**
   * @return values
   */
  public List<String> getPossibleValuesAsStrings() {
    final List<String> strings = new ArrayList<String>();
    for (final T possibleValue : getPossibleValues()) {
      strings.add(possibleValue.toString());
    }
    return strings;
  }

  /**
   * @return values
   */
  public List<String> getValuesAsStrings() {
    final List<String> strings = new ArrayList<String>();
    for (final T value : getValues()) {
      strings.add(value.toString());
    }
    return strings;
  }

  /**
   * Gets a list of all possible values.
   *
   * @return the list.
   */
  public Collection<T> getPossibleValues() {
    return possibleValues;
  }

  /**
   * Sets the list of possible values.
   *
   * @param collection the collection of values.
   */
  @SuppressWarnings("unchecked")
  public void setPossibleValues(
          final Collection<? extends Serializable> collection) {
    this.possibleValues = (Collection<T>) collection;
  }

  /**
   * Sets the current value of type &lt;T&gt;.
   *
   * @param object a value for this property.
   * @throws PropertyValidationException if the validation of the value failed.
   */
  public void setValue(final T object) throws PropertyValidationException {
    if (hasMultipleValues) {
      throw new IllegalStateException(
          "Attempted to set multiple values from a dynamic property with"
              + " single value.");
    }
    final List<T> newValues = new ArrayList<>();
    if (object == null) {
      newValues.add(defaultValue);
    } else {
      if (validator != null) {
        validator.validate(object);
      }
      if (possibleValues != null && !possibleValues.contains(object)) {
        throw new IllegalArgumentException(
            object
                + " (class="
                + object.getClass().getSimpleName()
                + ") is not in the list of approved objects (class="
                + possibleValues.getClass().getSimpleName()
                + "<"
                + possibleValues.getClass().getSimpleName()
                + ">): "
                + possibleValues);
      }
      newValues.add(object);
    }
    if (dynamicUiModel != null) {
      dynamicUiModel.setProperty(name, newValues.get(0));
    }
    this.values = newValues;
  }

  /**
   * Sets the list of current values of type &lt;T&gt;.
   *
   * @param objects a list of values to set.
   * @throws PropertyValidationException if any one of the values didn't pass
   *     validation.
   */
  public void setValues(final List<T> objects)
          throws PropertyValidationException {
    if (!hasMultipleValues) {
      throw new IllegalStateException(
          "Attempted to set single value from a dynamic property with multiple"
              + " values.");
    }
    final List<T> objectsCopy =
        new ArrayList<>(
            objects); // extra safety in case list is modified during function
                      // call
    final List<T> newValues;
    if (CollectionUtils.isEmpty(objectsCopy)) {
      newValues = new ArrayList<>();
      newValues.add(defaultValue);
    } else {
      if (!CollectionUtils.isEmpty(possibleValues)) {
        newValues = new ArrayList<>();
        for (final T object : objectsCopy) {
          if (validator != null) {
            validator.validate(object);
          }
          if (possibleValues.contains(object)) {
            newValues.add(object);
          } else {
            throw new IllegalArgumentException(
                object
                    + " (class="
                    + object.getClass().getSimpleName()
                    + ") is not in the list of approved objects (class="
                    + possibleValues.getClass().getSimpleName()
                    + "<"
                    + possibleValues.getClass().getSimpleName()
                    + ">): "
                    + possibleValues);
          }
        }
      } else {
        newValues = objectsCopy;
      }
    }
    if (dynamicUiModel != null) {
      dynamicUiModel.setProperty(
          name, StringUtils.join(newValues, LIST_SEPARATOR));
    }
    this.values = newValues;
  }

  /**
   * Gets the current value of type &lt;T&gt; as base 64 encoded string.
   *
   * @return the base 64 encoded string.
   */
  public String getEncodedValue() {
    return getAsEncodedValue(getValue());
  }

  /**
   * Gets the list of current values of type &lt;T&gt; as list of base 64
   * encoded strings.
   *
   * @return the list.
   */
  public List<String> getEncodedValues() {
    return getAsEncodedValues(getValues());
  }

  /**
   * Gets the base 64 encoded string of the value.
   *
   * @param value the value.
   * @return the base 64 encoded string.
   */
  public String getAsEncodedValue(final Serializable value) {
    return new String(Base64Util.encode(getAsByteArray(value), false));
  }

  /**
   * Gets the list of base 64 encoded strings of the values.
   *
   * @param list the list of values.
   * @return the list of base 64 encoded strings.
   */
  private List<String> getAsEncodedValues(final List<T> list) {
    final List<String> result = new ArrayList<>();
    for (final Serializable value : list) {
      result.add(new String(Base64Util.encode(getAsByteArray(value), false)));
    }
    return result;
  }

  /**
   * Sets the current value of type &lt;T&gt; by the given base 64 encoded
   * string.
   *
   * @param encodedValue the base 64 encoded value.
   */
  @SuppressWarnings("unchecked")
  public void setEncodedValue(final String encodedValue) {
    try {
      setValue(
        (T) getAsObject(Base64Util.decode(encodedValue.getBytes()), getType()));
    } catch (PropertyValidationException e) {
      throw new IllegalArgumentException(
          "Invalid value was intercepted from an encoded source, which should"
              + " not happen.",
          e);
    }
  }

  /**
   * Sets the list of values of type &lt;T&gt; by the given list of base 64
   * encoded strings.
   *
   * @param encodedValues a list of encoded values.
   * @throws PropertyValidationException if any one of the values doesn't pass
   *     validation.
   */
  @SuppressWarnings("unchecked")
  public void setEncodedValues(final List<String> encodedValues)
      throws PropertyValidationException {
    List<T> decodedValues = new ArrayList<>();
    for (String encodedValue : encodedValues) {
      decodedValues.add(
        (T) getAsObject(Base64Util.decode(encodedValue.getBytes()), getType()));
    }
    setValues(decodedValues);
  }

  /**
   * Sets the current value of type &lt;T&gt;.
   *
   * @param object the value.
   */
  @SuppressWarnings("unchecked")
  public void setValueGeneric(final Serializable object) {
    final List<T> newValues = new ArrayList<>();
    if (object == null) {
      newValues.add(defaultValue);
    } else {
      if (validator != null) {
        try {
          validator.validate((T) object);
        } catch (PropertyValidationException e) {
          throw new IllegalStateException(
              "Generic setter is normally only used internally, so an"
                  + " incorrect value should not be passed.",
              e);
        }
      }
      newValues.add((T) object);
    }
    this.values = newValues;
  }

  /**
   * Sets the current value of type &lt;T&gt;.
   *
   * @param object the value.
   */
  @SuppressWarnings("unchecked")
  public void setValueGenericIncludeNull(final Serializable object) {
    final List<T> newValues = new ArrayList<>();
    if (object == null) {
      newValues.add((T) object);
    } else {
      if (validator != null) {
        try {
          validator.validate((T) object);
        } catch (PropertyValidationException e) {
          throw new IllegalStateException(
              "Generic setter is normally only used internally, so an"
                  + " incorrect value should not be passed.",
              e);
        }
      }
      newValues.add((T) object);
    }
    this.values = newValues;
  }

  /**
   * Sets the list of current values of type &lt;T&gt;.
   *
   * @param list the list of values.
   */
  @SuppressWarnings("unchecked")
  public void setValuesGeneric(final List<? extends Serializable> list) {
    final List<? extends Serializable> listCopy =
        new ArrayList<>(
            list); // extra safety in case list is modified during the function
                   // call
    final List<T> newValues = new ArrayList<>();
    if (CollectionUtils.isEmpty(listCopy)) {
      newValues.add(defaultValue);
    } else {
      for (final Serializable object : listCopy) {
        if (validator != null) {
          try {
            validator.validate((T) object);
          } catch (PropertyValidationException e) {
            throw new IllegalStateException(
                "Generic setter is normally only used internally, so an"
                    + " incorrect value should not be passed.",
                e);
          }
        }
        newValues.add((T) object);
      }
    }
    this.values = newValues;
  }

  /**
   * Creates a deep clone of this instance.
   *
   * @return the new instance.
   */
  @SuppressWarnings("unchecked")
  @Override
  public DynamicUiProperty<T> clone() {
    return (DynamicUiProperty<T>) SerializationUtils.clone(this);
  }

  /**
   * Gets the object a byte array stream.
   *
   * @param o the object
   * @return the byte array.
   */
  private byte[] getAsByteArray(final Serializable o) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos); ) {
      oos.writeObject(o);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  /**
   * @param <T> Type
   * @param encodedValue Value
   * @param type Type
   * @return T
   */
  public static <T extends Serializable> T getAsObject(
      final String encodedValue, final Class<T> type) {
    return getAsObject(Base64Util.decode(encodedValue.getBytes()), type);
  }

  /**
   * @param <T> Type
   * @param bytes Bytes
   * @param type Type
   * @return T
   */
  private static <T extends Serializable> T getAsObject(
      final byte[] bytes, final Class<T> type) {
    try (LookAheadObjectInputStream lookAheadObjectInputStream =
        new LookAheadObjectInputStream(new ByteArrayInputStream(bytes))) {
      lookAheadObjectInputStream.setAcceptedClasses(
          Arrays.asList(
              type,
              LinkedHashMap.class,
              HashMap.class,
              HashSet.class,
              DynamicUiPropertyCallback.class,
              AccessMatchType.class,
              MultiLineString.class,
              String.class,
              PositiveIntegerValidator.class,
              RadioButton.class,
              ArrayList.class,
              Enum.class,
              Collections.emptyList().getClass().asSubclass(Serializable.class),
              Class.forName("org.cesecore.roles.RoleInformation")
                  .asSubclass(Serializable.class),
              Class.forName("org.cesecore.roles.RoleData")
                  .asSubclass(Serializable.class),
              Class.forName(
                      "org.cesecore.authorization.user.AccessUserAspectData")
                  .asSubclass(Serializable.class)));
      lookAheadObjectInputStream.setEnabledMaxObjects(false);
      lookAheadObjectInputStream.setEnabledSubclassing(false);
      lookAheadObjectInputStream.setEnabledInterfaceImplementations(false);
      return type.cast(lookAheadObjectInputStream.readObject());
    } catch (IOException | ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Gets the action callback.
   *
   * @return the callback.
   */
  public DynamicUiActionCallback getActionCallback() {
    return actionCallback;
  }

  /**
   * Sets the action callback.
   *
   * @param anActionCallback the callback.
   */
  public void setActionCallback(
          final DynamicUiActionCallback anActionCallback) {
    this.actionCallback = anActionCallback;
  }

  /**
   * Gets the property call back.
   *
   * @return the call back.
   */
  public DynamicUiPropertyCallback getPropertyCallback() {
    return propertyCallback;
  }

  /**
   * Sets the property call back.
   *
   * @param aPropertyCallback the call back.
   */
  public void setPropertyCallback(
      final DynamicUiPropertyCallback aPropertyCallback) {
    this.propertyCallback = aPropertyCallback;
  }

  /**
   * Gets if the property is allowed to consist of multiple values.
   *
   * @return true if this property can have multiple values.
   */
  public boolean getHasMultipleValues() {
    return hasMultipleValues;
  }

  /**
   * Sets if the property is allowed to consist of multiple values (i.e. list,
   * or LIST_SEPARATOR separated string).
   *
   * @param hasGotMultipleValues true if the property may have multiple values.
   */
  public void setHasMultipleValues(final boolean hasGotMultipleValues) {
    this.hasMultipleValues = hasGotMultipleValues;
  }

  /**
   * @return bool
   */
  public boolean isMultiValued() {
    return possibleValues != null;
  }

  /**
   * Returns the current value, like getValue, but has a workaround for JSF bug
   * with ui:repeat and rendered. See ECA-5342
   *
   * @return value
   */
  @SuppressWarnings("unchecked")
  public T getJsfBooleanValue() {
    if (hasMultipleValues || type != Boolean.class) {
      // In this case, JSF made a spurious call and will throw away the return
      // value, but it must be of expected type (boolean)
      return (T) Boolean.FALSE;
    } else {
      return getValue();
    }
  }

  /**
   * Sets the value, by calling setValue. Needed for the getJsfBooleanValue
   * workaround.
   *
   * @param newValue the new value of type &lt;T&gt;.
   * @throws PropertyValidationException if the value failed validation.
   */
  public void setJsfBooleanValue(final T newValue)
      throws PropertyValidationException {
    setValue(newValue);
  }

  /**
   * Sets the validator instance.
   *
   * @param aValidator the validator.
   */
  public void setValidator(final DynamicUiPropertyValidator<T> aValidator) {
    this.validator = aValidator;
  }

  /**
   * Gets the validator type.
   *
   * @return the validator type or "dummyValidator" if the validator is null.
   */
  public String getValidatorType() {
    if (validator != null) {
      return validator.getValidatorType();
    } else {
      return "dummyValidator";
    }
  }

  /**
   * Gets the map of I18N key / value pairs.
   *
   * @return the list.
   */
  public Map<?, String> getLabels() {
    return labels;
  }

  /**
   * Sets the map of I18N key / value pairs.
   *
   * @param theLabels the map.
   */
  public void setLabels(final Map<?, String> theLabels) {
    labeled = MapUtils.isNotEmpty(theLabels);
    this.labels = theLabels;
  }

  /**
   * Returns true if the property type is java.lang.Boolean (this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.lang.Boolean.
   */
  public boolean isBooleanType() {
    return Boolean.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.lang.Integer (this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.lang.Integer.
   */
  public boolean isIntegerType() {
    return Integer.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.lang.BigInteger (this method is
   * used because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.lang.BigInteger.
   */
  public boolean isBigIntegerType() {
    return BigInteger.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.lang.Long (this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.lang.Long.
   */
  public boolean isLongType() {
    return Long.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.lang.FLoat (this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.lang.Float.
   */
  public boolean isFloatType() {
    return Float.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.lang.String(this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.lang.String.
   */
  public boolean isStringType() {
    return String.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.util.HashMap (this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.util.HashMap.
   */
  public boolean isMapType() {
    return TreeMap.class.getName().equals(getType().getName());
  }

  /**
   * Returns true if the property type is java.io.File (this method is used
   * because of the lack of 'instanceof' operator in JSF EL).
   *
   * @return true if the property type is java.io.File.
   */
  public boolean isFileType() {
    return File.class.getName().equals(getType().getName());
  }

  /**
   * @return bool
   */
  public boolean isByteArrayType() {
    return byte[].class.getName().equals(getType().getName());
  }

  /**
   * Returns true if a check box should be rendered.
   *
   * @return true or false.
   */
  public boolean isRenderCheckBox() {
    return isBooleanType();
  }

  /**
   * Temp. method to store java.util.List as LIST_SEPARATOR separated List of
   * Strings (use for PublicKeyBlacklistKeyValidator only at the time).
   *
   * @return true if the list of Strings has to be stored as string.
   */
  public boolean isSaveListAsString() {
    return saveListAsString;
  }

  /**
   * Temp. method to store java.util.List as LIST_SEPARATOR separated List of
   * Strings (use for PublicKeyBlacklistKeyValidator only at the time).
   *
   * @param doSaveListAsString true if the list of Strings has to be stored as
   *     string.
   */
  public void setSaveListAsString(final boolean doSaveListAsString) {
    this.saveListAsString = doSaveListAsString;
  }

  /**
   * Sets the rendering hint ((see {@link #RENDER_NONE}, {@link #RENDER_LABEL},
   * {@link #RENDER_CHECKBOX}, {@link #RENDER_TEXTFIELD}, {@link
   * #RENDER_SELECT_ONE} or {@link #RENDER_SELECT_MANY})).
   *
   * @param aRenderingHint the rendering hint.
   */
  public void setRenderingHint(final String aRenderingHint) {
    this.renderingHint = aRenderingHint;
  }

  /**
   * Gets the rendering hint ((see {@link #RENDER_NONE}, {@link #RENDER_LABEL},
   * {@link #RENDER_CHECKBOX}, {@link #RENDER_TEXTFIELD}, {@link
   * #RENDER_SELECT_ONE} or {@link #RENDER_SELECT_MANY})).
   *
   * @return the rendering hint.
   */
  public String getRenderingHint() {
    // User explicit set rendering hint.
    if (renderingHint != null) {
      return renderingHint;
    }
    if (isLabelOnly()) {
      return RENDER_NONE;
    }
    String result = RENDER_TEXTFIELD;
    // Multiple values always use drop-down boxes.
    if (getHasMultipleValues()) {
      result = RENDER_SELECT_MANY;
    } else {
      if (!Boolean.class.equals(getType())) { // NOPMD
        // NOOP
      } else {
        result = RENDER_CHECKBOX;
      }
    }
    return result;
  }

  @Override
  public String toString() {
    return "DynamicUiProperty [name="
        + name
        + ", required="
        + required
        + ", defaultValue="
        + defaultValue
        + ", values="
        + values
        + ", possibleValues="
        + possibleValues
        + ", renderingHint="
        + renderingHint
        + ", labeled="
        + labeled
        + ", labels="
        + labels
        + ", labelOnly="
        + labelOnly
        + ", type="
        + type
        + ", hasMultipleValues="
        + hasMultipleValues
        + "]";
  }

  /**
   * Delegation method for {@link DynamicUiModel#addDynamicUiComponent}.
   *
   * @param component component
   */
  public void addDynamicUiComponent(final DynamicUiComponent component) {
    getDynamicUiModel().addDynamicUiComponent(name, component);
  }

  /** Update the view components attributes here! */
  public void updateViewComponents() {
    for (DynamicUiComponent component
        : getDynamicUiModel().getViewComponents(name)) {
      component.setDisabled(getDynamicUiModel().isDisabled() || isDisabled());
    }
  }
}
