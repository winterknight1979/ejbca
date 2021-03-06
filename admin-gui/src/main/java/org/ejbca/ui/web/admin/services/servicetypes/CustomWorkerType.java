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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import org.ejbca.core.model.services.CustomServiceWorkerProperty;
import org.ejbca.core.model.services.CustomServiceWorkerUiSupport;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.ui.web.admin.CustomLoader;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class used to populate the fields in the customworker.jsp subview page.
 *
 * <p>Is compatible with custom action and custom interval.
 *
 * @version $Id: CustomWorkerType.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public class CustomWorkerType extends WorkerType {

      /** Param. */
  private static final long serialVersionUID = 1790314768357040269L;
  /** Param. */
  public static final String NAME = "CUSTOMWORKER";

  /** Param. */
  private String autoClassPath;
  /** Param. */
  private String manualClassPath;
  /** Param. */
  private String propertyText;
  /** Param. */
  private final Collection<String> compatibleActionTypeNames =
      new ArrayList<>();
  /** Param. */
  private final Collection<String> compatibleIntervalTypeNames =
      new ArrayList<>();
  /** Param. */
  private ListDataModel<CustomServiceWorkerProperty>
      customUiPropertyListDataModel = null;

  /** Constructor. */
  public CustomWorkerType() {
    super("customworker.jsp", NAME, true);

    compatibleActionTypeNames.add(CustomActionType.NAME);
    compatibleActionTypeNames.add(NoActionType.NAME);
    compatibleActionTypeNames.add(MailActionType.NAME);

    compatibleIntervalTypeNames.add(CustomIntervalType.NAME);
    compatibleIntervalTypeNames.add(PeriodicalIntervalType.NAME);
  }

  /** @return the propertyText */
  public String getPropertyText() {
    return propertyText;
  }

  /** @param apropertyText the propertyText to set */
  public void setPropertyText(final String apropertyText) {
    this.propertyText = apropertyText;
  }

  /**
   * Sets the class path, and detects if it is an auto-detected class or a
   * manually specified class.
   *
   * @param classPath Classpath
   */
  public void setClassPath(final String classPath) {

    if (CustomLoader.isDisplayedInList(classPath, IWorker.class)) {
      autoClassPath = classPath;
      manualClassPath = "";
    } else {
      autoClassPath = "";
      manualClassPath = classPath;
    }
  }

  @Override
  public String getClassPath() {
    return autoClassPath != null && !autoClassPath.isEmpty()
        ? autoClassPath
        : manualClassPath;
  }

  /**
   * @param classPath CP
   */
  public void setAutoClassPath(final String classPath) {
    autoClassPath = classPath;
  }

  /**
   * @return CP
   */
  public String getAutoClassPath() {
    return autoClassPath;
  }

  /**
   * @param classPath CP
   */
  public void setManualClassPath(final String classPath) {
    manualClassPath = classPath;
  }

  /**
   * @return CP
   */
  public String getManualClassPath() {
    return manualClassPath;
  }

  @Override
  @SuppressWarnings("unchecked")
  public Properties getProperties(final ArrayList<String> errorMessages)
      throws IOException {
    final Properties retval = new Properties();
    if (customUiPropertyListDataModel == null) {
      retval.load(new ByteArrayInputStream(getPropertyText().getBytes()));
    } else {
      for (final CustomServiceWorkerProperty customUiProperty
          : (List<CustomServiceWorkerProperty>)
              customUiPropertyListDataModel.getWrappedData()) {
        retval.setProperty(
            customUiProperty.getName(), customUiProperty.getValue());
      }
    }
    return retval;
  }

  @Override
  public void setProperties(final Properties properties) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    properties.store(baos, null);
    setPropertyText(new String(baos.toByteArray()));
  }

  /** @return the names of the Compatible Action Types */
  @Override
  public Collection<String> getCompatibleActionTypeNames() {
    return compatibleActionTypeNames;
  }

  /** @return the names of the Compatible Interval Types */
  @Override
  public Collection<String> getCompatibleIntervalTypeNames() {
    return compatibleIntervalTypeNames;
  }

  @Override
  public boolean isCustom() {
    return true;
  }

  /**
   * @return bool
   */
  public boolean isCustomUiRenderingSupported() {
    return isCustomUiRenderingSupported(getClassPath());
  }

  /**
   * @param classPath CP
   * @return Bool
   */
  public static boolean isCustomUiRenderingSupported(final String classPath) {
    try {
      return Arrays.asList(Class.forName(classPath).getInterfaces())
          .contains(CustomServiceWorkerUiSupport.class);
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  /**
   * @return Param. */
  public ListDataModel<CustomServiceWorkerProperty> getCustomUiPropertyList() {
    if (isCustomUiRenderingSupported()) {
      if (customUiPropertyListDataModel == null) {
        final List<CustomServiceWorkerProperty> customUiPropertyList =
            new ArrayList<>();
        try {
          final CustomServiceWorkerUiSupport customPublisherUiSupport =
              (CustomServiceWorkerUiSupport)
                  Class.forName(getClassPath()).getConstructor().newInstance();
          final Properties currentProperties = new Properties();
          currentProperties.load(
              new ByteArrayInputStream(getPropertyText().getBytes()));
          customUiPropertyList.addAll(
              customPublisherUiSupport.getCustomUiPropertyList(
                  EjbcaJSFHelper.getBean().getAdmin(),
                  currentProperties,
                  EjbcaJSFHelper.getBean().getText()));
        } catch (InstantiationException | InvocationTargetException e) {
          e.printStackTrace();
        } catch (IllegalAccessException e) {
          e.printStackTrace();
        } catch (ClassNotFoundException | NoSuchMethodException e) {
          e.printStackTrace();
        } catch (IOException e) {
          e.printStackTrace();
        }
        this.customUiPropertyListDataModel =
            new ListDataModel<>(customUiPropertyList);
      }
    }
    return customUiPropertyListDataModel;
  }

  /**
   * @return Items
   */
  public List<SelectItem> getCustomUiPropertySelectItems() {
    final List<SelectItem> ret = new ArrayList<>();
    final CustomServiceWorkerProperty customServiceWorkerProperty =
        getCustomUiPropertyList().getRowData();
    customServiceWorkerProperty.getOptions();
    for (int i = 0; i < customServiceWorkerProperty.getOptions().size(); i++) {
      ret.add(
          new SelectItem(
              customServiceWorkerProperty.getOptions().get(i),
              customServiceWorkerProperty.getOptionTexts().get(i)));
    }
    return ret;
  }

  /**
   * @return Text
   */
  public String getCustomUiTitleText() {
    final String customClassSimpleName =
        getClassPath().substring(getClassPath().lastIndexOf('.') + 1);
    return EjbcaJSFHelper.getBean()
        .getText()
        .get(customClassSimpleName.toUpperCase() + "_TITLE");
  }

  /**
   * @return Text
   */
  public String getCustomUiPropertyText() {
    final String customClassSimpleName =
        getClassPath().substring(getClassPath().lastIndexOf('.') + 1);
    final String name =
        (getCustomUiPropertyList().getRowData())
            .getName()
            .replaceAll("\\.", "_");
    return EjbcaJSFHelper.getBean()
        .getText()
        .get(customClassSimpleName.toUpperCase() + "_" + name.toUpperCase());
  }
}
