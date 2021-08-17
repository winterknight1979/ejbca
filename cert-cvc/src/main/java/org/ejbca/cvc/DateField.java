/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Represents a CVC field of type Date.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class DateField extends AbstractDataField {

  private static final long serialVersionUID = 6092901788235446614L;

  /** The length of the array is always the same. */
  private static final int DATE_ARRAY_SIZE = 6;

  /** Time Zone GMT must be used for effective and expiration dates. */
  private static final TimeZone GMTTIMEZONE = TimeZone.getTimeZone("GMT");

  /** Date format when returning this object as text. */
  private static final DateFormat FORMAT_PRINTABLE =
      new SimpleDateFormat("yyyy-MM-dd");

  static {
    FORMAT_PRINTABLE.setTimeZone(GMTTIMEZONE);
  }

  /** Param. */
  private Date date;

  /**
   * @param type typ
   */
  DateField(final CVCTagEnum type) {
    super(type);
  }

  /**
   * Constructs a new instance from tag and Date.
   *
   * @param type type
   * @param adate date
   */
  DateField(final CVCTagEnum type, final Date adate) {
    this(type);

    Calendar cal = Calendar.getInstance(GMTTIMEZONE);
    cal.setTimeInMillis(adate.getTime());

    // Remove time part
    int year = cal.get(Calendar.YEAR);
    int month = cal.get(Calendar.MONTH);
    int day = cal.get(Calendar.DAY_OF_MONTH);
    cal.clear();
    cal.set(year, month, day);
    this.date = cal.getTime();
  }

  /**
   * Constructs instance by decoding DER-encoded data.
   *
   * @param type type
   * @param data data
   */
  DateField(final CVCTagEnum type, final byte[] data) {
    this(type);
    final int midHours = 23;
    final int midMins = 59;
    final int len = 6;
    final int twok = 2000;
    if (data == null || data.length != len) {
      throw new IllegalArgumentException(
          "data argument must have length 6, was "
              + (data == null ? 0 : data.length));
    }
    int year = twok + data[0] * 10 + data[1];
    int month = data[2] * 10 + data[3] - 1; // Java month index starts with
    // 0...
    int day = data[4] * 10 + data[5];
    // Now create a Date instance using the decoded values
    Calendar cal = Calendar.getInstance(GMTTIMEZONE);
    cal.clear();
    if (type == CVCTagEnum.EFFECTIVE_DATE) {
      cal.set(year, month, day, 0, 0, 0);
    } else { // EXPIRE_DATE
      // Validity is inclusive this date, so to make sure that
      // a Date comparison gives the expected result we add a
      // time component
      cal.set(year, month, day, midHours, midMins, midMins);
    }
    date = cal.getTime();
  }

  /**
   * Returns the date.
   *
   * @return date
   */
  public Date getDate() {
    return date;
  }

  /**
   * Encodes the date value so that every number in '080407' is stored as an
   * individual byte.
   *
   * @return date
   */
  @Override
  protected byte[] getEncoded() {
    byte[] dateArr = new byte[DATE_ARRAY_SIZE];

    final int twok = 2000;
    Calendar cal = Calendar.getInstance(GMTTIMEZONE);
    cal.setTimeInMillis(date.getTime());
    int year = cal.get(Calendar.YEAR) - twok; // Year is encoded as 08, 09,
    // 10 ...
    int month = cal.get(Calendar.MONTH) + 1; // Month is encoded as 1,2, ...
    // ,12
    int day = cal.get(Calendar.DAY_OF_MONTH);
    dateArr[0] = (byte) (year / 10);
    dateArr[1] = (byte) (year % 10);
    dateArr[2] = (byte) (month / 10);
    dateArr[3] = (byte) (month % 10);
    dateArr[4] = (byte) (day / 10);
    dateArr[5] = (byte) (day % 10);
    return dateArr;
  }

  @Override
  protected String valueAsText() {
    return FORMAT_PRINTABLE.format(date);
  }
}
