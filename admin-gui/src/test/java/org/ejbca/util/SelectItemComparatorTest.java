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
package org.ejbca.util;

import static org.junit.Assert.assertArrayEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.faces.model.SelectItem;
import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test for SelectItemComparator.
 *
 * @see SelectItemComparator
 * @version $Id: SelectItemComparatorTest.java 29652 2018-08-15 12:05:16Z anatom
 *     $
 */
public class SelectItemComparatorTest {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(SelectItemComparatorTest.class);

  /** Test. */
  @Test
  public void testBasic() {
    LOG.debug(">testBasic");
    List<SelectItem> items = new ArrayList<>();
    items.add(new SelectItem(10, "A"));
    items.add(new SelectItem(5));
    items.add(new SelectItem(7, "1"));
    items.add(new SelectItem(8, null));
    items.add(new SelectItem(null, "B"));
    Collections.sort(items, new SelectItemComparator());
    final Object[] values = valuesToArray(items);
    LOG.debug("After sorting: " + Arrays.toString(values));
    assertArrayEquals(
        "Wrong order of items.", new Object[] {8, 7, 5, 10, null}, values);
    LOG.debug("<testBasic");
  }

  /** Test. */
  @Test
  public void testWithSpecialItems() {
    LOG.debug(">testWithSpecialItems");
    List<SelectItem> items = new ArrayList<>();
    items.add(new SelectItem(10, "A"));
    items.add(new SelectItem(5));
    items.add(new SelectItem(7, "1"));
    items.add(new SelectItem(8, null));
    items.add(new SelectItem(null, "B"));
    Collections.sort(items, new SelectItemComparator(7, null));
    final Object[] values = valuesToArray(items);
    LOG.debug("After sorting: " + Arrays.toString(values));
    assertArrayEquals(
        "Wrong order of items.", new Object[] {7, null, 8, 5, 10}, values);
    LOG.debug("<testWithSpecialItems");
  }

  private Object[] valuesToArray(final List<SelectItem> items) {
    final Object[] values = new Object[items.size()];
    for (int i = 0; i < items.size(); i++) {
      values[i] = items.get(i).getValue();
    }
    return values;
  }
}
