/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.ui.DynamicUiModel;

/**
 * @version $Id: KeyValidatorBase.java 28140 2018-01-30 12:40:30Z andresjakobs $
 */
public abstract class KeyValidatorBase extends ValidatorBase
    implements KeyValidator {

  /** Class logger. */
  private static final Logger LOG = Logger.getLogger(KeyValidatorBase.class);

  private static final long serialVersionUID = 1L;

  /** List of applicable issuance phases (see {@link IssuancePhase}). */
  protected static List<Integer> applicablePhases;

  static {
    applicablePhases = new ArrayList<Integer>();
    applicablePhases.add(IssuancePhase.DATA_VALIDATION.getIndex());
  }

  /** Dynamic UI model extension. */
  protected DynamicUiModel uiModel;

  /** Public constructor needed for deserialization. */
  public KeyValidatorBase() {
    super();
  }

  /**
   * Creates a new instance.
   *
   * @param name name
   */
  public KeyValidatorBase(final String name) {
    super(name);
  }

  @Override
  public void init() {
    super.init();
    if (null == data.get(PHASE)) {
      setPhase(getApplicablePhases().get(0));
    }
    if (null == data.get(NOT_BEFORE_CONDITION)) {
      setNotBeforeCondition(KeyValidatorDateConditions.LESS_THAN.getIndex());
    }
    if (null == data.get(NOT_AFTER_CONDITION)) {
      setNotAfterCondition(KeyValidatorDateConditions.LESS_THAN.getIndex());
    }
  }

  @Override
  public void initDynamicUiModel() {
      // NOPMD: no-op
  }

  @Override
  public List<Integer> getApplicablePhases() {
    return applicablePhases;
  }

  @Override
  public Class<? extends Validator> getValidatorSubType() {
    return KeyValidator.class;
  }

  @Override
  public Date getNotBefore() {
    return (Date) data.get(NOT_BEFORE);
  }

  @Override
  public void setNotBefore(final Date date) {
    data.put(NOT_BEFORE, date);
  }

  @Override
  public int getNotBeforeCondition() {
    return ((Integer) data.get(NOT_BEFORE_CONDITION)).intValue();
  }

  @Override
  public void setNotBeforeCondition(final int index) {
    data.put(NOT_BEFORE_CONDITION, index);
  }

  @Override
  public Date getNotAfter() {
    return (Date) data.get(NOT_AFTER);
  }

  @Override
  public void setNotAfter(final Date date) {
    data.put(NOT_AFTER, date);
  }

  @Override
  public void setNotAfterCondition(final int index) {
    data.put(NOT_AFTER_CONDITION, index);
  }

  @Override
  public int getNotAfterCondition() {
    return ((Integer) data.get(NOT_AFTER_CONDITION)).intValue();
  }

  @Override
  public String getNotBeforeAsString() {
    return formatDate(getNotBefore());
  }

  @Override
  public String getNotAfterAsString() {
    return formatDate(getNotAfter());
  }

  @Override
  public void setNotBeforeAsString(final String formattedDate) {
    try {
      setNotBefore(parseDate(formattedDate));
    } catch (ParseException e) {
      LOG.debug("Could not parse Date: " + formattedDate);
    }
  }

  @Override
  public void setNotAfterAsString(final String formattedDate) {
    try {
      setNotAfter(parseDate(formattedDate));
    } catch (ParseException e) {
      LOG.debug("Could not parse Date: " + formattedDate);
    }
  }

  @Override
  public DynamicUiModel getDynamicUiModel() {
    return uiModel;
  }

  /**
   * Formats a date.
   *
   * @param date the date
   * @return the formatted date string.
   */
  private String formatDate(final Date date) {
    String result = StringUtils.EMPTY;
    if (null != date) {
      result = new SimpleDateFormat(DATE_FORMAT[0]).format(date);
    }
    return result;
  }

  /**
   * Parses a date string with the date format list.
   *
   * @param string the formatted date string.
   * @return the date or null, if the date could not be parsed.
   * @throws ParseException if the date couldn't be parsed
   */
  public static Date parseDate(final String string) throws ParseException {
    Date result = null;
    if (StringUtils.isNotBlank(string)) {
      final String dateString = string.trim();
      result = DateUtils.parseDate(dateString, DATE_FORMAT);
    }
    return result;
  }
}
