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
package org.ejbca.ui.web.admin.audit;

import java.util.List;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringEscapeUtils;
import org.cesecore.audit.AuditLogEntry;

/**
 * @version $Id: AuditSearchCondition.java 25716 2017-04-19 19:52:35Z
 *     mikekushner $
 */
public class AuditSearchCondition {

      /** param. */
  private Operation operation = Operation.AND;
  /** param. */
  private final String column;
  /** param. */
  private Condition condition = Condition.EQUALS;
  /** param. */
  private String value;

  /** param. */
  private final List<SelectItem> options;
  /** param. */
  private final List<SelectItem> conditions;

  /**
   * @param acolumn col
   * @param theconditions conds
   * @param theoptions opts
   * @param acondition condition
   * @param defaultValue value
   */
  public AuditSearchCondition(
      final String acolumn,
      final List<SelectItem> theconditions,
      final List<SelectItem> theoptions,
      final Condition acondition,
      final String defaultValue) {
    this.column = acolumn;
    this.options = theoptions;
    this.value = defaultValue;
    this.condition = acondition;
    this.conditions = theconditions;
  }

  /**
   * @param acolumn Col
   * @param theconditions Conds
   * @param theoptions Pos
   */
  public AuditSearchCondition(
      final String acolumn,
      final List<SelectItem> theconditions,
      final List<SelectItem> theoptions) {
    this.column = acolumn;
    this.options = theoptions;
    this.conditions = theconditions;
  }

  /**
   * @param anoperation Operation
   */
  public void setOperation(final Operation anoperation) {
    this.operation = anoperation;
  }

  /**
   * @return Operation
   */
  public Operation getOperation() {
    return operation;
  }

  /**
   * @return column
   */
  public String getColumn() {
    return column;
  }

  /**
   * @param acondition condition
   */
  public void setCondition(final String acondition) {
    this.condition = Condition.valueOf(acondition);
  }

  /**
   * @return condition
   */
  public String getCondition() {
    return condition.name();
  }

  /**
   * @param avalue value
   */
  public void setValue(final String avalue) {
    // The details column is XML-encoded, so escape any sensitive characters
    if (column.equals(AuditLogEntry.FIELD_ADDITIONAL_DETAILS)) {
      this.value = StringEscapeUtils.escapeXml(avalue);
    } else {
      this.value = avalue;
    }
  }

  /**
   * @return label
   */
  public String getValueLabel() {
    if (options != null) {
      for (final SelectItem option : options) {
        if (option.getValue().equals(value)) {
          return option.getLabel();
        }
      }
    }
    if (column.equals(AuditLogEntry.FIELD_ADDITIONAL_DETAILS)) {
      return StringEscapeUtils.unescapeXml(value);
    } else {
      return value;
    }
  }

  /**
   * @return Value
   */
  public String getValue() {
    return value;
  }

  /**
   * @return Options
   */
  public List<SelectItem> getOptions() {
    return options;
  }

  /**
   * @return Conditions
   */
  public List<SelectItem> getConditions() {
    return conditions;
  }
}
