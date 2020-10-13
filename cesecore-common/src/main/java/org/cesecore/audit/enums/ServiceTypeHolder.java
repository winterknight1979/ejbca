package org.cesecore.audit.enums;

/**
 * Simple implementation of ServiceType that holds the identifier.
 *
 * @version $Id: ServiceTypeHolder.java 26796 2017-10-12 04:29:58Z anatom $
 */
public class ServiceTypeHolder implements ServiceType {

  private static final long serialVersionUID = 1L;

  /** Value. */
  private final String value;

  /**
   * Constructor.
   *
   * @param aValue Value
   */
  public ServiceTypeHolder(final String aValue) {
    this.value = aValue;
  }

  @Override
  public String toString() {
    return value;
  }

  @Override
  public boolean equals(final ServiceType aValue) {
    if (aValue == null) {
      return false;
    }
    return this.value.equals(aValue.toString());
  }
}
