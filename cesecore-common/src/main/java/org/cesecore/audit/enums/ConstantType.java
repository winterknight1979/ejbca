package org.cesecore.audit.enums;

import java.io.Serializable;

/**
 * Generic constant type holder.
 *
 * @version $Id: ConstantType.java 17625 2013-09-20 07:12:06Z netmackan $
 * @param <T> Type
 */
public interface ConstantType<T extends ConstantType<T>> extends Serializable {
  /**
   * Test for equality.
   *
   * @param value Value
   * @return same as {@link Object#equals(Object)}
   */
  boolean equals(T value);
  /**
   * Convert to string.
   *
   * @return A string representation.
   */
  String toString();
}
