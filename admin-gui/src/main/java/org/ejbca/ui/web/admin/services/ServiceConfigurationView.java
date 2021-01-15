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

package org.ejbca.ui.web.admin.services;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.faces.model.SelectItem;
import org.apache.log4j.Logger;
import org.ejbca.core.model.services.IAction;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.web.admin.CustomLoader;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.NoActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.ServiceType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class responsible for converting the data between the GUI and a
 * ServiceConfiguration VO.
 *
 * @version $Id: ServiceConfigurationView.java 28844 2018-05-04 08:31:02Z
 *     samuellb $
 */
public class ServiceConfigurationView implements Serializable {

  private static final long serialVersionUID = 1L;
  /** Log. */
  private static final Logger LOG =
      Logger.getLogger(ServiceConfigurationView.class);

  /** Param. */
  private WorkerType workerType;
  /** Param. */
  private ActionType actionType;
  /** Param. */
  private IntervalType intervalType;

  /** Param. */
  private String selectedInterval;
  /** Param. */
  private String selectedAction;

  /** Param. */
  private final ServiceTypeManager typeManager;
  /** Param. */

  private boolean active = false;
  /** Param. */
  private boolean hidden = false;
  /** Param. */
  private String description = "";
  /** Param. */
  private String[] pinToNodes = new String[0];
  /** Param. */
  private boolean runOnAllNodes = false;

  /** Param. */
  private final ServiceConfiguration serviceConfiguration;

  /**
   * @param aserviceConfiguration config.
   */
  public ServiceConfigurationView(
      final ServiceConfiguration aserviceConfiguration) {

    typeManager = new ServiceTypeManager();

    this.serviceConfiguration = aserviceConfiguration;
    WorkerType aworkerType =
        (WorkerType)
            typeManager.getServiceTypeByClassPath(
                aserviceConfiguration.getWorkerClassPath());
    if (aworkerType == null) {
      aworkerType =
          (WorkerType) typeManager.getServiceTypeByName(CustomWorkerType.NAME);
      ((CustomWorkerType) aworkerType)
          .setClassPath(aserviceConfiguration.getWorkerClassPath());
    }
    setWorkerType(aworkerType);

    IntervalType anintervalType =
        (IntervalType)
            typeManager.getServiceTypeByClassPath(
                aserviceConfiguration.getIntervalClassPath());
    if (anintervalType == null) {
      if (aworkerType
          .getCompatibleIntervalTypeNames()
          .contains(PeriodicalIntervalType.NAME)) {
        // It seems most likely that the admin wants to configure a periodic
        // interval even if custom interval are available
        anintervalType =
            (IntervalType)
                typeManager.getServiceTypeByName(PeriodicalIntervalType.NAME);
      } else {
        anintervalType =
            (IntervalType)
                typeManager.getServiceTypeByName(CustomIntervalType.NAME);
        ((CustomIntervalType) anintervalType)
            .setClassPath(aserviceConfiguration.getIntervalClassPath());
      }
    }
    setIntervalType(anintervalType);
    selectedInterval = anintervalType.getName();

    ActionType anactionType =
        (ActionType)
            typeManager.getServiceTypeByClassPath(
                aserviceConfiguration.getActionClassPath());
    if (anactionType == null) {
      if (aworkerType
          .getCompatibleActionTypeNames()
          .contains(NoActionType.NAME)) {
        // It seems most likely that the admin wants to configure a "no action"
        // action even if custom actions are available
        anactionType =
            (ActionType) typeManager.getServiceTypeByName(NoActionType.NAME);
      } else {
        anactionType =
            (ActionType)
                typeManager.getServiceTypeByName(CustomActionType.NAME);
        ((CustomActionType) anactionType)
            .setClassPath(aserviceConfiguration.getActionClassPath());
      }
    }
    setActionType(anactionType);
    selectedAction = anactionType.getName();

    setDescription(aserviceConfiguration.getDescription());
    setActive(aserviceConfiguration.isActive());
    setHidden(aserviceConfiguration.isHidden());
    setPinToNodes(aserviceConfiguration.getPinToNodes());
    setRunOnAllNodes(aserviceConfiguration.isRunOnAllNodes());
  }

  /**
   * Method that populates a service configuration from a GUI data.
   *
   * @param errorMessages Messages
   * @return Config
   * @throws IOException Fail
   */
  public ServiceConfiguration getServiceConfiguration(
      final ArrayList<String> errorMessages) throws IOException {
    ServiceConfiguration retval = new ServiceConfiguration();
    retval.setActive(isActive());
    retval.setHidden(isHidden());
    retval.setDescription(getDescription());
    retval.setActionClassPath(getActionType().getClassPath());
    retval.setActionProperties(getActionType().getProperties(errorMessages));
    retval.setIntervalClassPath(getIntervalType().getClassPath());
    retval.setIntervalProperties(
        getIntervalType().getProperties(errorMessages));
    retval.setWorkerClassPath(getWorkerType().getClassPath());
    retval.setWorkerProperties(getWorkerType().getProperties(errorMessages));
    retval.setPinToNodes(getPinToNodes());
    retval.setRunOnAllNodes(isRunOnAllNodes());
    return retval;
  }

  /** @return the actionType */
  public ActionType getActionType() {
    return actionType;
  }

  /** @param anactionType the actionType to set */
  public void setActionType(final ActionType anactionType) {
    try {
      anactionType.setProperties(serviceConfiguration.getActionProperties());
    } catch (IOException e) {
      LOG.error(e);
    }
    this.actionType = anactionType;
  }

  /** @return the active flag */
  public boolean isActive() {
    return active;
  }

  /** @param isactive the active flag to set */
  public void setActive(final boolean isactive) {
    this.active = isactive;
  }

  /**
   * @return bool
   */
  public boolean isHidden() {
    return hidden;
  }

  /** @param ishidden the hidden flag to set */
  public void setHidden(final boolean ishidden) {
    this.hidden = ishidden;
  }

  /** @return the description */
  public String getDescription() {
    return description;
  }

  /** @param adescription the description to set */
  public void setDescription(final String adescription) {
    this.description = adescription;
  }

  /** @return the intervalType */
  public IntervalType getIntervalType() {
    return intervalType;
  }

  /** @param anintervalType the intervalType to set */
  public void setIntervalType(final IntervalType anintervalType) {
    try {
      anintervalType.setProperties(
              serviceConfiguration.getIntervalProperties());
    } catch (IOException e) {
      LOG.error(e);
    }
    this.intervalType = anintervalType;
  }

  /** @return the workerType */
  public WorkerType getWorkerType() {
    return workerType;
  }

  /** @param aworkerType the workerType to set */
  public void setWorkerType(final WorkerType aworkerType) {
    try {
      aworkerType.setProperties(serviceConfiguration.getWorkerProperties());
      this.workerType = aworkerType;

      if (selectedInterval != null
          && !aworkerType
              .getCompatibleIntervalTypeNames()
              .contains(selectedInterval)) {
        setSelectedInterval(
            aworkerType.getCompatibleIntervalTypeNames().iterator().next());
        setIntervalType(
            (IntervalType)
                typeManager.getServiceTypeByName(getSelectedInterval()));
      }

      if (selectedAction != null
          && !aworkerType
              .getCompatibleActionTypeNames()
              .contains(selectedAction)) {
        setSelectedAction(
            aworkerType.getCompatibleActionTypeNames().iterator().next());
        setActionType(
            (ActionType) typeManager.getServiceTypeByName(getSelectedAction()));
      }

    } catch (IOException e) {
      LOG.error(e);
    }
  }

  /** @return the selectedAction */
  public String getSelectedAction() {
    return selectedAction;
  }

  /** @param aselectedAction the selectedAction to set */
  public void setSelectedAction(final String aselectedAction) {
    this.selectedAction = aselectedAction;
  }

  /** @return the selectedInterval */
  public String getSelectedInterval() {
    return selectedInterval;
  }

  /** @param aselectedInterval the selectedInterval to set */
  public void setSelectedInterval(final String aselectedInterval) {
    this.selectedInterval = aselectedInterval;
  }

  /** @return the selectedWorker */
  public String getSelectedWorker() {
    final WorkerType aworkerType = getWorkerType();
    if (aworkerType instanceof CustomWorkerType) {
      final CustomWorkerType customWorkerType = (CustomWorkerType) aworkerType;
      if (customWorkerType.getClassPath() != null
          && customWorkerType.getClassPath().length() > 0) {
        return aworkerType.getName() + "-" + customWorkerType.getClassPath();
      }
    }
    return aworkerType.getName();
  }

  /** @param selectedWorker the selectedWorker to set */
  public void setSelectedWorker(final String selectedWorker) {
    final int separatorPos = selectedWorker.indexOf('-');
    if (separatorPos == -1) {
      final WorkerType aworkerType =
          (WorkerType)
              getServiceTypeManager().getServiceTypeByName(selectedWorker);
      if (aworkerType instanceof CustomWorkerType) {
        ((CustomWorkerType) aworkerType).setClassPath("");
      }
      setWorkerType(aworkerType);
    } else {
      final String customClassPath = selectedWorker.split("-")[1];
      final WorkerType aworkerType =
          (WorkerType) typeManager.getServiceTypeByName(CustomWorkerType.NAME);
      ((CustomWorkerType) aworkerType).setClassPath(customClassPath);
      setWorkerType(aworkerType);
    }
  }

  /**
   * @return workers
   */
  public List<SelectItem> getAvailableWorkers() {
    final ArrayList<SelectItem> retval = new ArrayList<>();
    final Collection<ServiceType> available =
        typeManager.getAvailableWorkerTypes();
    for (final ServiceType next : available) {
      String label = next.getName();
      if (next.isTranslatable()) {
        label = EjbcaJSFHelper.getBean().getText().get(next.getName());
      }
      retval.add(new SelectItem(next.getName(), label));
      if (next instanceof CustomWorkerType) {
        List<String> customClasses =
            CustomLoader.getCustomClasses(IWorker.class);
        for (final String customClass : customClasses) {
          final String customClassSimpleName =
              customClass.substring(customClass.lastIndexOf('.') + 1);
          final String labelKey =
              customClassSimpleName.toUpperCase() + "_TITLE";
          label = EjbcaJSFHelper.getBean().getText().get(labelKey);
          if (label.equals(labelKey)) {
            label =
                customClassSimpleName
                    + " ("
                    + EjbcaJSFHelper.getBean().getText().get(next.getName())
                    + ")";
          }
          retval.add(new SelectItem(next.getName() + "-" + customClass, label));
        }
      }
    }
    // Sort by label
    Collections.sort(
        retval,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem arg0, final SelectItem arg1) {
            return arg0.getLabel().compareTo(arg1.getLabel());
          }
        });
    return retval;
  }

  /**
   * @return intervals
   */
  public List<SelectItem> getAvailableIntervals() {
    final ArrayList<SelectItem> retval = new ArrayList<>();
    final WorkerType currentWorkerType = getWorkerType();
    for (final String name
        : currentWorkerType.getCompatibleIntervalTypeNames()) {
      final ServiceType next = typeManager.getServiceTypeByName(name);
      String label = name;
      if (next.isTranslatable()) {
        label = EjbcaJSFHelper.getBean().getText().get(name);
      }
      retval.add(new SelectItem(name, label));
    }
    return retval;
  }

  /**
   * @return actions
   */
  public List<SelectItem> getAvailableActions() {
    final ArrayList<SelectItem> retval = new ArrayList<>();
    final WorkerType currentWorkerType = getWorkerType();
    for (final String name : currentWorkerType.getCompatibleActionTypeNames()) {
      final ServiceType next = typeManager.getServiceTypeByName(name);
      String label = name;
      if (next.isTranslatable()) {
        label = EjbcaJSFHelper.getBean().getText().get(name);
      }
      retval.add(new SelectItem(name, label));
    }
    return retval;
  }

  private List<SelectItem> stringsToItems(final List<String> stringList) {
    List<SelectItem> itemList = new ArrayList<>(stringList.size());
    for (String s : stringList) {
      itemList.add(new SelectItem(s, s));
    }
    return itemList;
  }

  /**
   * @return items
   */
  public List<SelectItem> getAvailableCustomWorkerItems() {
    final List<String> customClasses =
        CustomLoader.getCustomClasses(IWorker.class);
    final List<String> customClassesWithoutUiSupport = new ArrayList<>();
    for (final String classPath : customClasses) {
      // Exclude all the workers that have custom UI support and will be shown
      // as any other worker
      if (!CustomWorkerType.isCustomUiRenderingSupported(classPath)) {
        customClassesWithoutUiSupport.add(classPath);
      }
    }
    return stringsToItems(customClassesWithoutUiSupport);
  }

  /**
   * @return items
   */
  public List<SelectItem> getAvailableCustomIntervalItems() {
    return stringsToItems(CustomLoader.getCustomClasses(IInterval.class));
  }

  /**
   * @return items
   */
  public List<SelectItem> getAvailableCustomActionItems() {
    return stringsToItems(CustomLoader.getCustomClasses(IAction.class));
  }

  /**
   * returns this sessions service type manager.
   *
   * @return Manager
   */
  public ServiceTypeManager getServiceTypeManager() {
    return typeManager;
  }

  /**
   * @return nodes
   */
  public String[] getPinToNodes() {
    return pinToNodes;
  }

  /**
   * @param apinToNodes nodes
   */
  public void setPinToNodes(final String[] apinToNodes) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("view setPinToNodes: " + Arrays.toString(apinToNodes));
    }
    this.pinToNodes = apinToNodes;
  }

  /**
   * @return nodes
   */
  public boolean isRunOnAllNodes() {
    return runOnAllNodes;
  }

  /**
   * @param arunOnAllNodes nodes
   */
  public void setRunOnAllNodes(final boolean arunOnAllNodes) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("view setRunOnAllNodes: " + arunOnAllNodes);
    }
    this.runOnAllNodes = arunOnAllNodes;
  }

  /**
   * @return nodes
   */
  public List<SelectItem> getNodesInCluster() {
    final List<SelectItem> ret = new LinkedList<>();
    final Set<String> nodes =
        EjbcaJSFHelper.getBean()
            .getEjbcaWebBean()
            .getGlobalConfiguration()
            .getNodesInCluster();
    for (String node : nodes) {
      ret.add(new SelectItem(node));
    }
    // Also add unknown nodes, that is nodes that has been removed but this
    // service still is pinned to
    for (String node : getPinToNodes()) {
      if (!nodes.contains(node)) {
        ret.add(
            new SelectItem(
                node,
                node
                    + " "
                    + EjbcaJSFHelper.getBean()
                        .getText()
                        .get("PINTONODESUNKNOWNNODE")));
      }
    }
    return ret;
  }
}
