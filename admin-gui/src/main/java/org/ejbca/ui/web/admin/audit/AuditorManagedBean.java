/*************************************************************************
 *                                                                       *
 *
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.event.ActionEvent;
import javax.faces.model.SelectItem;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.AuditExporterXml;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.XmlSerializer;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * JSF Backing bean for viewing security audit logs.
 *
 * <p>Reloads the data lazily if when requested if something was cause for an
 * update (first time, user has invoked reload etc).
 *
 * <p>getConditions() will handle special cases when HTTP GET parameters are
 * passed (e.g. show history for a username).
 *
 * @version $Id: AuditorManagedBean.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class AuditorManagedBean implements Serializable {

  private static final long serialVersionUID = 1L;
  /** param. */
  private static final Logger LOG = Logger.getLogger(AuditorManagedBean.class);

  /** param. */
  private static final boolean ORDER_ASC = true;
  /** param. */
  private static final boolean ORDER_DESC = false;

  /** param. */
  private final SecurityEventsAuditorSessionLocal securityEventsAuditorSession =
      new EjbLocalHelper().getSecurityEventsAuditorSession();
  /** param. */
  private final CaSessionLocal caSession = new EjbLocalHelper().getCaSession();

  /** param. */
  private boolean renderNext = false;

  /** param. */
  private boolean reloadResultsNextView = true;
  /** param. */
  private String device;
  /** param. */
  private String sortColumn = AuditLogEntry.FIELD_TIMESTAMP;
  /** param. */
  private boolean sortOrder = ORDER_DESC;
  /** param. */
  private final int defaultMaxResults = 40;
  /** param. */
  private int maxResults = defaultMaxResults;
  /** param. */
  private int startIndex = 1;
  /** param. */
  private final List<SelectItem> sortColumns = new ArrayList<>();
  /** param. */
  private final List<SelectItem> columns = new ArrayList<>();
  /** param. */
  private final List<SelectItem> sortOrders = new ArrayList<>();
  /** param. */
  private List<? extends AuditLogEntry> results;
  /** param. */
  private Map<Object, String> caIdToNameMap;

  /** param. */
  private final Map<String, String> columnNameMap = new HashMap<>();
  /** param. */
  private final List<SelectItem> eventStatusOptions = new ArrayList<>();
  /** param. */
  private final List<SelectItem> eventTypeOptions = new ArrayList<>();
  /** param. */
  private final List<SelectItem> moduleTypeOptions = new ArrayList<>();
  /** param. */
  private final List<SelectItem> serviceTypeOptions = new ArrayList<>();
  /** param. */
  private final List<SelectItem> operationsOptions = new ArrayList<>();
  /** param. */
  private final List<SelectItem> conditionsOptions = new ArrayList<>();
  /** param. */
  private final List<SelectItem> conditionsOptionsExact = new ArrayList<>();
  /** param. */
  private final List<SelectItem> conditionsOptionsContains = new ArrayList<>();
  /** param. */
  private final List<SelectItem> conditionsOptionsNumber = new ArrayList<>();
  /** param. */
  private final List<SelectItem> cmsSigningCaOptions = new ArrayList<>();
  /** param. */
  private Integer cmsSigningCa = null;
  /** param. */
  private String conditionColumn = AuditLogEntry.FIELD_SEARCHABLE_DETAIL2;
  /** param. */
  private AuditSearchCondition conditionToAdd;
  /** param. */
  private List<AuditSearchCondition> conditions = new ArrayList<>();
  /** param. */
  private boolean automaticReload = true;

  /** Constructor. */
  public AuditorManagedBean() {
    final EjbcaWebBean ejbcaWebBean =
        EjbcaJSFHelper.getBean().getEjbcaWebBean();
    columnNameMap.put(
        AuditLogEntry.FIELD_AUTHENTICATION_TOKEN,
        ejbcaWebBean.getText("ADMINISTRATOR"));
    columnNameMap.put(
        AuditLogEntry.FIELD_CUSTOM_ID, ejbcaWebBean.getText("CUSTOM_ID"));
    columnNameMap.put(
        AuditLogEntry.FIELD_EVENTSTATUS, ejbcaWebBean.getText("EVENTSTATUS"));
    columnNameMap.put(
        AuditLogEntry.FIELD_EVENTTYPE, ejbcaWebBean.getText("EVENTTYPE"));
    columnNameMap.put(
        AuditLogEntry.FIELD_MODULE, ejbcaWebBean.getText("MODULE"));
    columnNameMap.put(AuditLogEntry.FIELD_NODEID, ejbcaWebBean.getText("NODE"));
    columnNameMap.put(
        AuditLogEntry.FIELD_SEARCHABLE_DETAIL1,
        ejbcaWebBean.getText("CERTIFICATE"));
    columnNameMap.put(
        AuditLogEntry.FIELD_SEARCHABLE_DETAIL2,
        ejbcaWebBean.getText("USERNAME_ABBR"));
    // columnNameMap.put(AuditLogEntry.FIELD_SEQUENCENUMBER,
    // ejbcaWebBean.getText("SEQUENCENUMBER"));
    // columnNameMap.put(AuditLogEntry.FIELD_SERVICE,
    // ejbcaWebBean.getText("SERVICE"));
    columnNameMap.put(
        AuditLogEntry.FIELD_TIMESTAMP, ejbcaWebBean.getText("TIMESTAMP"));
    for (final Entry<String, String> entry : columnNameMap.entrySet()) {
      sortColumns.add(new SelectItem(entry.getKey(), entry.getValue()));
    }
    columnNameMap.put(
        AuditLogEntry.FIELD_ADDITIONAL_DETAILS,
        ejbcaWebBean.getText("ADDITIONAL_DETAILS"));
    columns.addAll(sortColumns);
    // Commented out due to the fact that searching through the details field is
    // unreliable. If there are any non ascii-characters in the field,
    // (such as é), it will in its entirety be b64-encoded, which renders it
    // unsearchable, even for ascii characters that may happen to be there
    // as well.
    // columns.add(new SelectItem(AuditLogEntry.FIELD_ADDITIONAL_DETAILS,
    // columnNameMap.get(AuditLogEntry.FIELD_ADDITIONAL_DETAILS)));
    sortOrders.add(new SelectItem(ORDER_ASC, "ASC"));
    sortOrders.add(new SelectItem(ORDER_DESC, "DESC"));
    // If no device is chosen we select the first available as default
    if (getDevices().size() > 0) {
      device = (String) getDevices().get(0).getValue();
    }
    // We can't use enums directly in JSF 1.2
    for (Operation current : Operation.values()) {
      operationsOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    for (Condition current : Condition.values()) {
      conditionsOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    conditionsOptionsExact.add(
        new SelectItem(
            Condition.EQUALS.toString(),
            ejbcaWebBean.getText(Condition.EQUALS.toString())));
    conditionsOptionsExact.add(
        new SelectItem(
            Condition.NOT_EQUALS.toString(),
            ejbcaWebBean.getText(Condition.NOT_EQUALS.toString())));
    conditionsOptionsNumber.addAll(conditionsOptionsExact);
    conditionsOptionsNumber.add(
        new SelectItem(
            Condition.GREATER_THAN.toString(),
            ejbcaWebBean.getText(Condition.GREATER_THAN.toString())));
    conditionsOptionsNumber.add(
        new SelectItem(
            Condition.LESS_THAN.toString(),
            ejbcaWebBean.getText(Condition.LESS_THAN.toString())));
    conditionsOptionsContains.add(
        new SelectItem(
            Condition.CONTAINS.toString(),
            ejbcaWebBean.getText(Condition.CONTAINS.toString())));
    for (EventStatus current : EventStatus.values()) {
      eventStatusOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    for (EventTypes current : EventTypes.values()) {
      // TODO: Verify if these are used by EJBCA
      switch (current) {
        case BACKUP:
        case RESTORE:
        case TIME_SYNC_ACQUIRE:
        case TIME_SYNC_LOST:
          // case LOG_MANAGEMENT_CHANGE:
          // case LOG_SIGN:
        case CERTIFICATE_KEY_BIND:
        case CERTIFICATE_KEY_UNBIND:
          // Ignore!
          break;
        default:
          eventTypeOptions.add(
              new SelectItem(
                  current.toString(),
                  ejbcaWebBean.getText(current.toString())));
      }
    }
    for (EventType current : EjbcaEventTypes.values()) {
      eventTypeOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    for (ModuleType current : ModuleTypes.values()) {
      moduleTypeOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    for (ModuleType current : EjbcaModuleTypes.values()) {
      moduleTypeOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    for (ServiceType current : ServiceTypes.values()) {
      serviceTypeOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    for (ServiceType current : EjbcaServiceTypes.values()) {
      serviceTypeOptions.add(
          new SelectItem(
              current.toString(), ejbcaWebBean.getText(current.toString())));
    }
    // By default, don't show the authorized to resource events
    conditions.add(
        new AuditSearchCondition(
            AuditLogEntry.FIELD_EVENTTYPE,
            conditionsOptionsExact,
            eventTypeOptions,
            Condition.NOT_EQUALS,
            EventTypes.ACCESS_CONTROL.name()));
    updateCmsSigningCas();
  }

  /**
   * @return devices
   */
  public List<SelectItem> getDevices() {
    final List<SelectItem> list = new ArrayList<>();
    for (final String deviceId
        : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
      list.add(new SelectItem(deviceId, deviceId));
    }
    return list;
  }

  /**
   * @return bool
   */
  public boolean isOneLogDevice() {
    return getDevices().size() == 1;
  }

  /**
   * @return bool
   */
  public boolean isRenderNext() {
    getResults();
    return renderNext;
  }

  /**
   * @return orders
   */
  public int getResultSize() {
    getResults();
    return results == null ? 0 : results.size();
  }

  /**
   * @return cols
   */
  public List<SelectItem> getSortColumns() {
    return sortColumns;
  }

  /**
   * @return orders
   */
  public List<SelectItem> getSortOrders() {
    return sortOrders;
  }

  /**
   * @return cols
   */
  public List<SelectItem> getColumns() {
    return columns;
  }

  /**
   * @param selectedDevice device
   */
  public void setDevice(final String selectedDevice) {
    this.device = selectedDevice;
  }

  /**
   * @return device
   */
  public String getDevice() {
    return device;
  }

  /**
   * @return results
   */
  public List<? extends AuditLogEntry> getResults() {
    if (getDevice() != null && reloadResultsNextView) {
      reloadResults();
      reloadResultsNextView = false;
    }
    return results;
  }

  /**
   * Converts a map with possibly Base64 encoded items to a string.
   *
   * @param value Value
   * @return String
   */
  public String mapToString(final Map<String, Object> value) {
    return MapToStringConverter.getAsString(value);
  }

  /**
   * @param asortColumn column
   */
  public void setSortColumn(final String asortColumn) {
    this.sortColumn = asortColumn;
  }

  /**
   * @return column
   */
  public String getSortColumn() {
    return sortColumn;
  }

  /**
   * @param themaxResults results
   */
  public void setMaxResults(final int themaxResults) {
    final int limit = 1000;
    this.maxResults =
        Math.min(limit, Math.max(1, themaxResults)); // 1-1000 results allowed
  }

  /**
   * @return results
   */
  public int getMaxResults() {
    return maxResults;
  }

  /**
   * @param astartIndex index
   */
  public void setStartIndex(final int astartIndex) {
    this.startIndex = Math.max(1, astartIndex);
  }

  /**
   * @return index
   */
  public int getStartIndex() {
    return startIndex;
  }

  /**
   * @param dosortOrder bool
   */
  public void setSortOrder(final boolean dosortOrder) {
    this.sortOrder = dosortOrder;
  }

  /**
   * @return bool
   */
  public boolean isSortOrder() {
    return sortOrder;
  }

  /**
   * @param aconditionColumn column
   */
  public void setConditionColumn(final String aconditionColumn) {
    this.conditionColumn = aconditionColumn;
  }

  /**
   * @return column
   */
  public String getConditionColumn() {
    return conditionColumn;
  }

  /**
   * @param aconditionToAdd condition
   */
  public void setConditionToAdd(final AuditSearchCondition aconditionToAdd) {
    this.conditionToAdd = aconditionToAdd;
  }

  /**
   * @return condition
   */
  public AuditSearchCondition getConditionToAdd() {
    return conditionToAdd;
  }

  /** Clear. */
  public void clearConditions() {
    setConditions(new ArrayList<AuditSearchCondition>());
    setConditionToAdd(null);
    onConditionChanged();
  }

  /** New. **/
  public void newCondition() {
    if (AuditLogEntry.FIELD_AUTHENTICATION_TOKEN.equals(conditionColumn)
        || AuditLogEntry.FIELD_NODEID.equals(conditionColumn)
        || AuditLogEntry.FIELD_SEARCHABLE_DETAIL1.equals(conditionColumn)
        || AuditLogEntry.FIELD_SEARCHABLE_DETAIL2.equals(conditionColumn)
        || AuditLogEntry.FIELD_SEQUENCENUMBER.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn, conditionsOptions, null, Condition.EQUALS, ""));
    } else if (AuditLogEntry.FIELD_CUSTOM_ID.equals(conditionColumn)) {
      List<SelectItem> caIds = new ArrayList<>();
      for (Entry<Object, String> entry : caIdToNameMap.entrySet()) {
        caIds.add(new SelectItem(entry.getKey(), entry.getValue()));
      }
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn, conditionsOptionsExact, caIds));
    } else if (AuditLogEntry.FIELD_EVENTSTATUS.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn, conditionsOptionsExact, eventStatusOptions));
    } else if (AuditLogEntry.FIELD_EVENTTYPE.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn, conditionsOptionsExact, eventTypeOptions));
    } else if (AuditLogEntry.FIELD_MODULE.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn, conditionsOptionsExact, moduleTypeOptions));
    } else if (AuditLogEntry.FIELD_SERVICE.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn, conditionsOptionsExact, serviceTypeOptions));
    } else if (AuditLogEntry.FIELD_TIMESTAMP.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn,
              conditionsOptionsNumber,
              null,
              Condition.EQUALS,
              ValidityDate.formatAsISO8601(
                  new Date(), ValidityDate.TIMEZONE_SERVER)));
    } else if (AuditLogEntry.FIELD_ADDITIONAL_DETAILS.equals(conditionColumn)) {
      setConditionToAdd(
          new AuditSearchCondition(
              conditionColumn,
              conditionsOptionsContains,
              null,
              Condition.CONTAINS,
              ""));
    }
  }

  /** CAncel. */
  public void cancelCondition() {
    setConditionToAdd(null);
  }

  /**
   * Add.
   */
  public void addCondition() {
    getConditions().add(getConditionToAdd());
    setConditionToAdd(null);
    onConditionChanged();
  }

  /**
   * @param event event
   */
  public void removeCondition(final ActionEvent event) {
    getConditions()
        .remove(event.getComponent().getAttributes().get("removeCondition"));
    onConditionChanged();
  }

  /**
   * @return bool
   */
  public boolean isAutomaticReload() {
    return automaticReload;
  }

  /**
   * @param doautomaticReload bool
   */
  public void setAutomaticReload(final boolean doautomaticReload) {
    this.automaticReload = doautomaticReload;
  }

  private void onConditionChanged() {
    reloadResultsNextView = isAutomaticReload();
    first();
  }

  /** Reload. */
  public void reload() {
    reloadResultsNextView = true;
  }

  private void reloadResults() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Reloading audit load. selectedDevice=" + device);
    }
    updateCaIdToNameMap();
    try {
      final AuthenticationToken authenticationToken =
          EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();
      results =
          getResults(
              authenticationToken,
              columnNameMap.keySet(),
              device,
              getConditions(),
              sortColumn,
              sortOrder,
              startIndex - 1,
              maxResults);
    } catch (Exception e) {
      if (results != null) {
        results.clear();
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(e.getMessage(), e);
      }
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage("Invalid search conditions: " + e.getMessage()));
    }
    renderNext =
        results != null && !results.isEmpty() && results.size() == maxResults;
  }

  /**
   * Build and executing audit log queries that are safe from SQL injection.
   *
   * @param token the requesting entity. Will also limit the results to
   *     authorized CAs.
   * @param validColumns a Set of legal column names
   * @param adevice the name of the audit log device
   * @param theconditions the list of conditions to transform into a query
   * @param asortColumn ORDER BY column
   * @param asortOrder true=ASC, false=DESC order
   * @param firstResult first entry from the result set. Index starts with 0.
   * @param themaxResults number of results to return
   * @return the query result
   * @throws AuthorizationDeniedException if the administrator is not authorized
   *     to perform the requested query
   */
  private List<? extends AuditLogEntry> getResults(
      final AuthenticationToken token,
      final Set<String> validColumns,
      final String adevice,
      final List<AuditSearchCondition> theconditions,
      final String asortColumn,
      final boolean asortOrder,
      final int firstResult,
      final int themaxResults)
      throws AuthorizationDeniedException {
    final List<Object> parameters = new ArrayList<>();
    final StringBuilder whereClause = new StringBuilder();
    final String errorMessage =
        "This should never happen unless you are intentionally trying to"
            + " perform an SQL injection attack.";
    for (int i = 0; i < theconditions.size(); i++) {
      final AuditSearchCondition condition = theconditions.get(i);
      if (i > 0) {
        switch (condition.getOperation()) {
          case AND:
            whereClause.append(" AND ");
            break;
          case OR:
            whereClause.append(" OR ");
            break;
          default: break;
        }
      }
      // Validate that the column we are adding to the SQL WHERE clause is
      // exactly one of the legal column names
      if (!validColumns.contains(condition.getColumn())) {
        throw new IllegalArgumentException(errorMessage);
      }
      Object conditionValue = condition.getValue();
      if (AuditLogEntry.FIELD_TIMESTAMP.equals(condition.getColumn())) {
        try {
          conditionValue =
              Long.valueOf(
                  ValidityDate.parseAsIso8601(conditionValue.toString())
                      .getTime());
        } catch (ParseException e) {
          LOG.debug(
              "Admin entered invalid date for audit log search: "
                  + condition.getValue());
          continue;
        }
      }
      switch (Condition.valueOf(condition.getCondition())) {
        case EQUALS:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" = ?")
              .append(i);
          break;
        case NOT_EQUALS:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" != ?")
              .append(i);
          break;
        case CONTAINS:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" LIKE ?")
              .append(i);
          conditionValue = "%" + conditionValue + "%";
          break;
        case ENDS_WITH:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" LIKE ?")
              .append(i);
          conditionValue = "%" + conditionValue;
          break;
        case STARTS_WITH:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" LIKE ?")
              .append(i);
          conditionValue = conditionValue + "%";
          break;
        case GREATER_THAN:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" > ?")
              .append(i);
          break;
        case LESS_THAN:
          whereClause
              .append("a.")
              .append(condition.getColumn())
              .append(" < ?")
              .append(i);
          break;
        default:
          throw new IllegalArgumentException(errorMessage);
      }
      // The condition value will be added to the query using JPA's setParameter
      // (safe from SQL injection)
      parameters.add(conditionValue);
    }
    // Validate that the column we are adding to the SQL ORDER clause is exactly
    // one of the legal column names
    if (!validColumns.contains(asortColumn)) {
      throw new IllegalArgumentException(errorMessage);
    }
    final String orderClause =
        new StringBuilder("a.")
            .append(asortColumn)
            .append(asortOrder ? " ASC" : " DESC")
            .toString();
    return new EjbLocalHelper()
        .getEjbcaAuditorSession()
        .selectAuditLog(
            token,
            adevice,
            firstResult,
            themaxResults,
            whereClause.toString(),
            orderClause,
            parameters);
  }

  /**
   * @return ID
   */
  public Map<Object, String> getCaIdToName() {
    return caIdToNameMap;
  }

  /** Update. */
  private void updateCaIdToNameMap() {
    final Map<Integer, String> map = caSession.getCAIdToNameMap();
    final Map<Object, String> ret = new HashMap<>();
    final AuthenticationToken authenticationToken =
        EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();
    for (final Entry<Integer, String> entry : map.entrySet()) {
      if (caSession.authorizedToCANoLogging(
          authenticationToken, entry.getKey())) {
        ret.put(entry.getKey().toString(), entry.getValue());
      }
    }
    caIdToNameMap = ret;
  }

  /**
   * @return Name
   */
  public Map<String, String> getNameFromColumn() {
    return columnNameMap;
  }

  /** First. */
  public void first() {
    setStartIndex(1);
    reloadResultsNextView = true;
  }

  /** Next. */
  public void next() {
    setStartIndex(startIndex + maxResults);
    reloadResultsNextView = true;
  }

  /** Prev. */
  public void previous() {
    setStartIndex(startIndex - maxResults);
    reloadResultsNextView = true;
  }

  /**
   * @param theconditions conditions
   */
  public void setConditions(final List<AuditSearchCondition> theconditions) {
    this.conditions = theconditions;
  }

  /**
   * @return conditiions
   */
  public List<AuditSearchCondition> getConditions() {
    // Special case when we supply "username" as parameter to allow view of a
    // user's history
    final String searchDetail2String = getHttpParameter("username");
    if (searchDetail2String != null) {
      reloadResultsNextView = true;
      startIndex = 1;
      conditions.clear();
      conditions.add(
          new AuditSearchCondition(
              AuditLogEntry.FIELD_SEARCHABLE_DETAIL2,
              conditionsOptions,
              null,
              Condition.EQUALS,
              searchDetail2String));
      sortColumn = AuditLogEntry.FIELD_TIMESTAMP;
      sortOrder = ORDER_DESC;
    }
    return conditions;
  }

  /**
   * @return ops
   */
  public List<SelectItem> getDefinedOperations() {
    return operationsOptions;
  }

  /**
   * @return conditions
   */
  public List<SelectItem> getDefinedConditions() {
    return conditionToAdd.getConditions();
  }

  private String getHttpParameter(final String key) {
    return FacesContext.getCurrentInstance()
        .getExternalContext()
        .getRequestParameterMap()
        .get(key);
  }

  /** Reorder. */
  public void reorderAscByTime() {
    reorderBy(AuditLogEntry.FIELD_TIMESTAMP, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByTime() {
    reorderBy(AuditLogEntry.FIELD_TIMESTAMP, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscByEvent() {
    reorderBy(AuditLogEntry.FIELD_EVENTTYPE, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByEvent() {
    reorderBy(AuditLogEntry.FIELD_EVENTTYPE, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscByStatus() {
    reorderBy(AuditLogEntry.FIELD_EVENTSTATUS, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByStatus() {
    reorderBy(AuditLogEntry.FIELD_EVENTSTATUS, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscByAuthToken() {
    reorderBy(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByAuthToken() {
    reorderBy(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscByModule() {
    reorderBy(AuditLogEntry.FIELD_MODULE, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByModule() {
    reorderBy(AuditLogEntry.FIELD_MODULE, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscByCustomId() {
    reorderBy(AuditLogEntry.FIELD_CUSTOM_ID, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByCustomId() {
    reorderBy(AuditLogEntry.FIELD_CUSTOM_ID, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscBySearchDetail1() {
    reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescBySearchDetail1() {
    reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL1, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscBySearchDetail2() {
    reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescBySearchDetail2() {
    reorderBy(AuditLogEntry.FIELD_SEARCHABLE_DETAIL2, ORDER_DESC);
  }

  /** Reorder. */
  public void reorderAscByNodeId() {
    reorderBy(AuditLogEntry.FIELD_NODEID, ORDER_ASC);
  }

  /** Reorder. */
  public void reorderDescByNodeId() {
    reorderBy(AuditLogEntry.FIELD_NODEID, ORDER_DESC);
  }

  private void reorderBy(final String column, final boolean orderAsc) {
    if (!sortColumn.equals(column)) {
      reloadResultsNextView = true;
    }
    sortColumn = column;
    if (sortOrder != orderAsc) {
      reloadResultsNextView = true;
    }
    sortOrder = orderAsc ? ORDER_ASC : ORDER_DESC;
  }

  /**
   * Ugly hack to be able to read the length of the resulting String from JSF
   * EL.
   *
   * <p>Example: "#{auditor.stringTooLong[(auditLogEntry.mapAdditionalDetails)]
   * &gt; 50}"
   *
   * <p>TODO: Use javax.faces.model.DataModel instead
   *
   * @return a fake "Map" where the get(Map) returns the length of the
   *     output-formatted Map
   */
  public Map<String, Integer> getStringTooLong() {
    return new Map<String, Integer>() {
      @Override
      public Integer get(final Object key) {
        return new MapToStringConverter().getAsString(null, null, key).length();
      }

      @Override
      public void clear() { }

      @Override
      public boolean containsKey(final Object key) {
        return false;
      }

      @Override
      public boolean containsValue(final Object value) {
        return false;
      }

      @Override
      public Set<Entry<String, Integer>> entrySet() {
        return null;
      }

      @Override
      public boolean isEmpty() {
        return false;
      }

      @Override
      public Set<String> keySet() {
        return null;
      }

      @Override
      public Integer put(final String key, final Integer value) {
        return null;
      }

      @Override
      public void putAll(final Map<? extends String, ? extends Integer> m) { }

      @Override
      public Integer remove(final Object key) {
        return null;
      }

      @Override
      public int size() {
        return 0;
      }

      @Override
      public Collection<Integer> values() {
        return null;
      }
    };
  }

  private void updateCmsSigningCas() {
    final Map<Integer, String> map = caSession.getCAIdToNameMap();
    cmsSigningCaOptions.clear();
    for (int caid
        : caSession.getAuthorizedCaIds(
            EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject())) {
      // TODO: Would be nice to check if the CMS signer service is activated
      // here before we add it
      cmsSigningCaOptions.add(new SelectItem(caid, map.get(caid)));
    }
    if (cmsSigningCa == null && !cmsSigningCaOptions.isEmpty()) {
      cmsSigningCa = (Integer) cmsSigningCaOptions.get(0).getValue();
    }
  }

  /**
   * @return CAs
   */
  public List<SelectItem> getCmsSigningCas() {
    return cmsSigningCaOptions;
  }

  /**
   * @return CA
   */
  public Integer getCmsSigningCa() {
    return cmsSigningCa;
  }

  /**
   * @param acmsSigningCa CA
   */
  public void setCmsSigningCa(final Integer acmsSigningCa) {
    this.cmsSigningCa = acmsSigningCa;
  }

  /** Download. */
  public void downloadResultsCms() {
    try {
      if (cmsSigningCa == null) {
        FacesContext.getCurrentInstance()
            .addMessage(
                null, new FacesMessage("Invalid or no CMS signing CA."));
      } else {
        final CmsCAServiceRequest request =
            new CmsCAServiceRequest(
                exportToByteArray(), CmsCAServiceRequest.MODE_SIGN);
        final CAAdminSession caAdminSession =
            new EjbLocalHelper().getCaAdminSession();
        final AuthenticationToken authenticationToken =
            EjbcaJSFHelper.getBean().getAdmin();
        final CmsCAServiceResponse resp =
            (CmsCAServiceResponse)
                caAdminSession.extendedService(
                    authenticationToken, cmsSigningCa, request);
        try {
          downloadResults(
              resp.getCmsDocument(),
              "application/octet-stream",
              "export-" + results.get(0).getTimeStamp() + ".p7m");
        } catch (IOException e) {
          LOG.info(
              "Administration tried to export audit log, but failed. "
                  + e.getMessage());
          FacesContext.getCurrentInstance()
              .addMessage(null, new FacesMessage(e.getMessage()));
        }
      }
    } catch (Exception e) {
      LOG.info(
          "Administration tried to export audit log, but failed. "
              + e.getMessage());
      FacesContext.getCurrentInstance()
          .addMessage(null, new FacesMessage(e.getMessage()));
    }
  }

  /** Download. */
  public void downloadResults() {
    try {
      // text/xml doesn't work since it gets filtered and all non-ASCII bytes
      // get encoded as entities as if they were Latin-1 (ECA-5831)
      downloadResults(
          exportToByteArray(),
          "application/octet-stream",
          "export-"
              + results.get(0).getTimeStamp()
              + ".xml"); // "application/force-download" is an alternative
                         // here..
    } catch (IOException e) {
      LOG.info(
          "Administration tried to export audit log, but failed. "
              + e.getMessage());
      FacesContext.getCurrentInstance()
          .addMessage(null, new FacesMessage(e.getMessage()));
    }
  }

  private byte[] exportToByteArray() throws IOException {
    // We could extend this without too much problems to allow the admin to
    // choose between different formats.
    // By reading it from the config we could drop a custom exporter in the
    // class-path and use it if configured
    final Class<? extends AuditExporter> exporterClass =
        AuditDevicesConfig.getExporter(getDevice());
    AuditExporter auditExporter = null;
    if (exporterClass != null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Using AuditExporter class: " + exporterClass.getName());
      }

      try {
        auditExporter = exporterClass.getConstructor().newInstance();
      } catch (Exception e) {
        LOG.warn(
            "AuditExporter for "
                + getDevice()
                + " is not configured correctly.",
            e);
      }
    }

    if (auditExporter == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "AuditExporter not configured. Using default: "
                + AuditExporterXml.class.getSimpleName());
      }
      auditExporter =
          new AuditExporterXml(); // Use Java-friendly XML as default
    }
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      auditExporter.setOutputStream(baos);
      for (final AuditLogEntry auditLogEntry : results) {
        writeToExport(auditExporter, (AuditRecordData) auditLogEntry);
      }
      auditExporter.close();
      return baos.toByteArray();
    }
  }

  /**
   * Uses the provided exporter to generate export data in memory. Responds with
   * the data instead of rendering a new page.
   *
   * @param b Bytes
   * @param contentType Type
   * @param filename File
   * @throws IOException On error
   */
  private void downloadResults(
      final byte[] b, final String contentType, final String filename)
      throws IOException {
    final HttpServletResponse response =
        (HttpServletResponse)
            FacesContext.getCurrentInstance()
                .getExternalContext()
                .getResponse();
    response.setContentType(contentType);
    response.addHeader(
        "Content-Disposition",
        "attachment; filename=\"" + StringTools.stripFilename(filename) + "\"");
    final ServletOutputStream out = response.getOutputStream();
    response.setContentLength(b.length);
    out.write(b);
    out.close();
    FacesContext.getCurrentInstance()
        .responseComplete(); // No further JSF navigation
  }

  /* Duplicate of code from
   * org.cesecore.audit.impl.integrityprotected.IntegrityProtectedAuditorSessionBean.writeToExport
   * (unusable from here.. :/) */
  /**
   * We want to export exactly like it was stored in the database, to comply
   * with requirements on logging systems where no altering of the original log
   * data is allowed.
   *
   * @param auditExporter Exporter
   * @param auditRecordData Data
   * @throws IOException On fail
   */
  private void writeToExport(
      final AuditExporter auditExporter, final AuditRecordData auditRecordData)
      throws IOException {
    auditExporter.writeStartObject();
    auditExporter.writeField("pk", auditRecordData.getPk());
    auditExporter.writeField(
        AuditLogEntry.FIELD_NODEID, auditRecordData.getNodeId());
    auditExporter.writeField(
        AuditLogEntry.FIELD_SEQUENCENUMBER,
        auditRecordData.getSequenceNumber());
    auditExporter.writeField(
        AuditLogEntry.FIELD_TIMESTAMP, auditRecordData.getTimeStamp());
    auditExporter.writeField(
        AuditLogEntry.FIELD_EVENTTYPE,
        auditRecordData.getEventTypeValue().toString());
    auditExporter.writeField(
        AuditLogEntry.FIELD_EVENTSTATUS,
        auditRecordData.getEventStatusValue().toString());
    auditExporter.writeField(
        AuditLogEntry.FIELD_AUTHENTICATION_TOKEN,
        auditRecordData.getAuthToken());
    auditExporter.writeField(
        AuditLogEntry.FIELD_SERVICE,
        auditRecordData.getServiceTypeValue().toString());
    auditExporter.writeField(
        AuditLogEntry.FIELD_MODULE,
        auditRecordData.getModuleTypeValue().toString());
    auditExporter.writeField(
        AuditLogEntry.FIELD_CUSTOM_ID, auditRecordData.getCustomId());
    auditExporter.writeField(
        AuditLogEntry.FIELD_SEARCHABLE_DETAIL1,
        auditRecordData.getSearchDetail1());
    auditExporter.writeField(
        AuditLogEntry.FIELD_SEARCHABLE_DETAIL2,
        auditRecordData.getSearchDetail2());
    final Map<String, Object> additionalDetails =
        XmlSerializer.decode(auditRecordData.getAdditionalDetails());
    final String additionalDetailsEncoded =
        XmlSerializer.encodeWithoutBase64(additionalDetails);
    auditExporter.writeField(
        AuditLogEntry.FIELD_ADDITIONAL_DETAILS, additionalDetailsEncoded);
    auditExporter.writeField(
        "rowProtection", auditRecordData.getRowProtection());
    auditExporter.writeEndObject();
  }
}
