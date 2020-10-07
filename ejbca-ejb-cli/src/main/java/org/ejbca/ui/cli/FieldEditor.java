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
package org.ejbca.ui.cli;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.beanutils.ConvertingWrapDynaBean;
import org.apache.commons.beanutils.DynaBean;
import org.apache.commons.beanutils.DynaProperty;
import org.apache.commons.beanutils.WrapDynaBean;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;

/**
 *
 * @version $Id: FieldEditor.java 23457 2016-05-16 17:18:31Z mikekushner $
 */
public class FieldEditor {

    private final Logger logger;

    public FieldEditor(Logger logger) {
        this.logger = logger;
    }
    
    /** List of fields that should be excluded from bean lists. This should contain fields that should never be changed by a user */
    private static final ArrayList<String> excluded = new ArrayList<String>();
    static {
        excluded.add("type");
        excluded.add("version");
        excluded.add("class");
        excluded.add("latestVersion");
        excluded.add("upgraded");
        excluded.add("CAId");
        excluded.add("CAType");
        excluded.add("CAToken");
        excluded.add("hidden");
    }
    /** Lists methods in a class the has "setXyz", and prints them as "Xyz".
     * Ignores (does not list) type, version, latestVersion, upgrade and class
     * 
     * @param obj the Object where to look for setMethods
     */
    public void listSetMethods(final Object obj) {
        DynaBean wrapper = new WrapDynaBean(obj);
        DynaProperty[] props = wrapper.getDynaClass().getDynaProperties();
        for (DynaProperty dynaProperty : props) {
            if (!excluded.contains(dynaProperty.getName())) {
                logger.info(dynaProperty.getName()+", "+dynaProperty.getType());                
            }
        }
    }
    
    public List<String> getSetMethodNames(final Object obj) {
        List<String> result = new ArrayList<String>();
        DynaBean wrapper = new WrapDynaBean(obj);
        DynaProperty[] props = wrapper.getDynaClass().getDynaProperties();
        for (DynaProperty dynaProperty : props) {
            if (!excluded.contains(dynaProperty.getName())) {
                result.add(dynaProperty.getName());
            }
        }
        return result;
    }
    
    /** gets a field value from a bean
     * 
     * @param field the field to get
     * @param obj the bran to get the value from
     * @return the value
     * @throws FieldNotFoundException if field doesn't exist.
     */
    public Object getBeanValue(final String field, final Object obj) throws FieldNotFoundException {
        final DynaBean moddb = new WrapDynaBean(obj);
        DynaProperty prop = moddb.getDynaClass().getDynaProperty(field);
        if (prop == null) {
            throw new FieldNotFoundException("Field '" + field + "' does not exist. Did you use correct case for every character of the field?");
        }
        final Object gotValue = moddb.get(field);
        logger.info(field+" returned value '"+gotValue+"'.");
        return gotValue;
    }
    
    /** Lists, Gets or sets fields in a Bean.
     * 
     * @param name the name of the Bean to be modified
     * @param field the field name to get or set
     * @param value the value to set, of we should set a new value
     * @param obj the Bean to list, get or set fields
     * 
     * @throws FieldNotFoundException if field was not found. 
     */
    public void setValue(final String name, final String field, final String value, final Object obj) throws FieldNotFoundException {

        Object val = value;
        logger.info("Modifying '" + name + "'...");
        final ConvertingWrapDynaBean db = new ConvertingWrapDynaBean(obj);
        DynaProperty prop = db.getDynaClass().getDynaProperty(field);
        if (prop == null) {
            throw new FieldNotFoundException("Field '" + field + "' does not exist. Did you use correct case for every character of the field?");
        }
        if (prop.getType().isInterface()) {
            logger.info("Converting value '" + value + "' to type '" + ArrayList.class + "', ");
            // If the value can be converted into an integer, we will use an ArrayList<Integer>
            // Our problem here is that the type of a collection (<Integer>, <String>) is only compile time, it can not be determined in runtime.
            List<Object> arr = new ArrayList<Object>();

            if (NumberUtils.isNumber(value)) {
                logger.info("using Integer value.");
                arr.add(Integer.valueOf(value));
            } else {
                // Make it into an array of String
                logger.info("using String value.");
                arr.add(value);
            }
            val = arr;
        }
        final Object gotValue = db.get(field);
        logger.info("Current value of " + field + " is '" + gotValue + "'.");
        db.set(field, val);
    }


}
