package org.cesecore.audit.enums;

/**
 * Simple implementation of ServiceType that holds the identifier.
 * 
 * @version $Id: ServiceTypeHolder.java 26796 2017-10-12 04:29:58Z anatom $
 */
public class ServiceTypeHolder implements ServiceType {

    private static final long serialVersionUID = 1L;

    private final String value;
    
    public ServiceTypeHolder(final String value) {
        this.value = value;
    }
    
    @Override
    public String toString() {
        return value;
    }
    
    @Override
    public boolean equals(final ServiceType value) {
        if (value == null) {
            return false;
        }
        return this.value.equals(value.toString());
    }
}
