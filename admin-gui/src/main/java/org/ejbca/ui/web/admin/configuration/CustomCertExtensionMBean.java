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
package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ServiceLoader;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.event.ValueChangeEvent;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing the configuration of a single
 * CustomCertificateExtension.
 *
 * @version $Id: CustomCertExtensionMBean.java 29873 2018-09-13 09:36:27Z aminkh
 *     $
 */
public class CustomCertExtensionMBean extends BaseManagedBean
    implements Serializable {

  private static final long serialVersionUID = 1L;

  /** Prefix for properties in custom certificate extensions. */
  private static final String CUSTOMCERTEXTENSION_PROPERTY_PREFIX =
      "CUSTOMCERTEXTENSION_PROPERTY_";

  public class CurrentExtensionGUIInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    /** Param. */
    private int id;
    /** Param. */
    private String oid;
    /** Param. */
    private String displayName;
    /** Param. */
    private boolean critical;
    /** Param. */
    private boolean required;
    /** Param. */
    private Map<String, CustomExtensionPropertyGUIInfo> extensionProperties;
    /** Param. */
    private CustomCertificateExtension extension;

    /**
     * @param anextension ext
     */
    public CurrentExtensionGUIInfo(
            final CustomCertificateExtension anextension) {
      this.id = anextension.getId();
      this.oid = anextension.getOID();
      this.displayName =
              getEjbcaWebBean().getText(anextension.getDisplayName());
      this.critical = anextension.isCriticalFlag();
      this.required = anextension.isRequiredFlag();
      setExtension(anextension);
    }

    /**
     * @return ID
     */
    public int getId() {
      return this.id;
    }

    /**
     * @param anid ID
     */
    public void setId(final int anid) {
      this.id = anid;
    }

    /**
     * @return OID
     */
    public String getOid() {
      return this.oid;
    }

    /**
     * @param anoid OID
     */
    public void setOid(final String anoid) {
      this.oid = anoid;
    }

    /**
     * @return name
     */
    public String getDisplayName() {
      return this.displayName;
    }

    /**
     * @param adisplayName name
     */
    public void setDisplayName(final String adisplayName) {
      this.displayName = adisplayName;
    }

    /**
     * @return bool
     */
    public boolean isCritical() {
      return this.critical;
    }

    /**
     * @param iscritical vool
     */
    public void setCritical(final boolean iscritical) {
      this.critical = iscritical;
    }

    /**
     * @return bool
     */
    public boolean isRequired() {
      return this.required;
    }

    /**
     * @param isrequired bool
     */
    public void setRequired(final boolean isrequired) {
      this.required = isrequired;
    }

    /**
     * @param key Key
     * @param value Value
     * @throws InvalidCustomExtensionPropertyException Fail
     */
    public void setProperty(final String key, final String value)
        throws InvalidCustomExtensionPropertyException {
      CustomExtensionPropertyGUIInfo property = extensionProperties.get(key);
      property.setValue(value);
      extensionProperties.put(key, property);
    }

    /**
     * @return props
     */
    public Map<String, CustomExtensionPropertyGUIInfo>
        getExtensionProperties() {
      return extensionProperties;
    }

    /**
     * @return Props
     */
    public Properties getProperties() {
      Properties properties = new Properties();
      for (String key : extensionProperties.keySet()) {
        properties.put(key, extensionProperties.get(key).getValue());
      }
      return properties;
    }

    /**
     * @return Ext
     */
    public CustomCertificateExtension getExtension() {
      return extension;
    }

    /**
     * @param classPath CP
     */
    public void setClassPath(final String classPath) {
      setExtension(availableCertificateExtensions.get(classPath));
    }

    /**
     * @param anextension Ext
     */
    public void setExtension(final CustomCertificateExtension anextension) {
      this.extension = anextension;
      // Load the available properties
      Map<String, CustomExtensionPropertyGUIInfo> extensionPropertiesCopy =
          new LinkedHashMap<>();
      for (Entry<String, String[]> entry
          : anextension.getAvailableProperties().entrySet()) {
        String key = entry.getKey();
        String label =
            getEjbcaWebBean()
                .getText(CUSTOMCERTEXTENSION_PROPERTY_PREFIX + key);
        Properties properties = anextension.getProperties();
        String value =
            (properties != null && properties.get(key) != null
                ? (String) properties.get(key)
                : null);
        CustomExtensionPropertyGUIInfo property =
            new CustomExtensionPropertyGUIInfo(
                key, label, value, entry.getValue());
        extensionPropertiesCopy.put(key, property);
      }
      extensionProperties = extensionPropertiesCopy;
    }

    /**
     * @return CP
     */
    public String getClassPath() {
      return extension.getClass().getCanonicalName();
    }
  }

  public class CustomExtensionPropertyGUIInfo {

        /** Param. */
    private final String key;
    /** Param. */
    private final String label;
    /** Param. */
    private String value;
    /** Param. */
    private String[] possibleValues;

    /**
     * @param akey Key
     * @param alabel Label
     * @param avalue Value
     * @param thepossibleValues Values
     */
    public CustomExtensionPropertyGUIInfo(
        final String akey,
        final String alabel,
        final String avalue,
        final String... thepossibleValues) {
      this.key = akey;
      this.label = alabel;
      if (avalue != null) {
        this.value = avalue;
      } else {
        if (thepossibleValues.length > 0) {
          this.value = thepossibleValues[0];
        } else {
          this.value = "";
        }
      }
      this.possibleValues = thepossibleValues;
    }

    /**
     * @return Key
     */
    public String getKey() {
      return key;
    }

    /**
     * @return Label
     */
    public String getLabel() {
      return label;
    }

    /**
     * @return value
     */
    public String getValue() {
      return value;
    }

    /**
     * Sets the value.
     *
     * @param avalue the value to be set
     * @throws InvalidCustomExtensionPropertyException if a list of possible
     *     values has been set, and the given value was not in the set.
     */
    public void setValue(final String avalue)
        throws InvalidCustomExtensionPropertyException {
      // Evaluate the value, if any defaults have been given
      valueSearch:
      if (possibleValues.length > 0) {
        for (String possibleValue : possibleValues) {
          if (avalue.equals(possibleValue)) {
            break valueSearch;
          }
        }
        // There should be a check for property validity here, but since I can't
        // manage to decouple the list of properties when the page is refreshed
        // after
        // the extension class has been changed, we'll fail nicely and simply
        // ignore unfound values.
        return;
      }
      this.value = avalue;
    }

    /**
     * @return values
     */
    public String[] getPossibleValues() {
      return possibleValues;
    }

    /**
     * @return count
     */
    public int getPossibleValuesCount() {
      return possibleValues.length;
    }
  }

  /** Param. */
  private final AuthorizationSessionLocal authorizationSession =
      getEjbcaWebBean().getEjb().getAuthorizationSession();

  // Declarations in faces-config.xml
  // @javax.faces.bean.ManagedProperty(value="#{systemConfigMBean}")
  /** Param. */
  private SystemConfigMBean systemConfigMBean;

  /** Param. */
  private AvailableCustomCertificateExtensionsConfiguration
      availableExtensionsConfig = null;
  /** Param. */
  private Map<String, CustomCertificateExtension>
      availableCertificateExtensions = null;
  /** Param. */
  private List<SelectItem> availableCertificateExtensionsList = null;
  /** Param. */
  private CurrentExtensionGUIInfo currentExtensionGUIInfo = null;
  /** Param. */
  private ListDataModel<CustomExtensionPropertyGUIInfo>
      currentExtensionProperties = null;
  /** Param. */
  private int currentExtensionId = 0;

  /** Constructor. */
  public CustomCertExtensionMBean() {
    super();
  }

  private void flushCurrentExtension() {
    availableExtensionsConfig = null;
    currentExtensionId = 0;
    currentExtensionGUIInfo = null;
    currentExtensionProperties = null;
  }

  private AvailableCustomCertificateExtensionsConfiguration
      getAvailableExtensionsConfig() {
    if (availableExtensionsConfig == null) {
      availableExtensionsConfig =
          getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
    }
    return availableExtensionsConfig;
  }

  /**
   * @return bean
   */
  public SystemConfigMBean getSystemConfigMBean() {
    return systemConfigMBean;
  }

  /**
   * @param asystemConfigMBean bean
   */
  public void setSystemConfigMBean(final SystemConfigMBean asystemConfigMBean) {
    this.systemConfigMBean = asystemConfigMBean;
  }

  /**
   * @return IS
   */
  public int getCurrentExtensionId() {
    this.currentExtensionId =
        systemConfigMBean.getSelectedCustomCertExtensionID();
    return this.currentExtensionId;
  }

  /**
   * @return Exts
   */
  public List<SelectItem> getAvailableCustomCertificateExtensions() {
    if (availableCertificateExtensions == null) {
      availableCertificateExtensions = new HashMap<>();
      availableCertificateExtensionsList = new ArrayList<>();
      ServiceLoader<? extends CustomCertificateExtension> serviceLoader =
          ServiceLoader.load(CustomCertificateExtension.class);
      for (CustomCertificateExtension extension : serviceLoader) {
        availableCertificateExtensionsList.add(
            new SelectItem(
                extension.getClass().getCanonicalName(),
                extension.getDisplayName()));
        availableCertificateExtensions.put(
            extension.getClass().getCanonicalName(), extension);
      }
      Collections.sort(
          availableCertificateExtensionsList,
          new Comparator<SelectItem>() {
            @Override
            public int compare(final SelectItem o1, final SelectItem o2) {
              return o1.getLabel().compareTo(o2.getLabel());
            }
          });
    }
    return availableCertificateExtensionsList;
  }

  /**
   * @return cached or populate a new CustomCertificateExtension GUI
   *     representation for view or edit
   */
  public CurrentExtensionGUIInfo getCurrentExtensionGUIInfo() {
    AvailableCustomCertificateExtensionsConfiguration cceConfig =
        getAvailableExtensionsConfig();
    int currentID = getCurrentExtensionId();
    if ((currentExtensionGUIInfo == null)
        || (currentExtensionGUIInfo.getId() != currentID)) {
      flushCurrentExtension();
      currentExtensionGUIInfo =
          new CurrentExtensionGUIInfo(
              cceConfig.getCustomCertificateExtension(currentID));
    }
    return currentExtensionGUIInfo;
  }

  /** Save. */
  @SuppressWarnings("unchecked")
  public void saveCurrentExtension() {
    if (StringUtils.isEmpty(currentExtensionGUIInfo.getOid())) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No CustomCertificateExtension OID is set.",
                  null));
      return;
    }
    if (StringUtils.isEmpty(currentExtensionGUIInfo.getDisplayName())) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No CustomCertificateExtension Label is set.",
                  null));
      return;
    }

    if (StringUtils.isEmpty(currentExtensionGUIInfo.getClassPath())) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "No CustomCertificateExtension is set.",
                  null));
      return;
    }

    Properties properties = new Properties();
    for (CustomExtensionPropertyGUIInfo extensionProperty
       : (List<CustomExtensionPropertyGUIInfo>)
            currentExtensionProperties.getWrappedData()) {
      properties.put(extensionProperty.getKey(), extensionProperty.getValue());
    }

    AvailableCustomCertificateExtensionsConfiguration cceConfig =
        getAvailableExtensionsConfig();
    try {
      cceConfig.addCustomCertExtension(
          currentExtensionGUIInfo.getId(),
          currentExtensionGUIInfo.getOid(),
          currentExtensionGUIInfo.getDisplayName(),
          currentExtensionGUIInfo.getClassPath(),
          currentExtensionGUIInfo.isCritical(),
          currentExtensionGUIInfo.isRequired(),
          properties);
      getEjbcaWebBean()
          .saveAvailableCustomCertExtensionsConfiguration(cceConfig);
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_INFO,
                  "Extension was saved successfully.",
                  null));
    } catch (Exception e) {
      FacesContext.getCurrentInstance()
          .addMessage(
              null,
              new FacesMessage(
                  FacesMessage.SEVERITY_ERROR,
                  "Failed to edit Custom Certificate Extension. "
                      + e.getLocalizedMessage(),
                  e.getLocalizedMessage()));
      return;
    }
    flushCurrentExtension();
  }

  // -------------------------------------------------------------
  //              Current Extension Properties
  // ------------------------------------------------------------
  /**
   * @return Info
   */
  public ListDataModel<CustomExtensionPropertyGUIInfo>
      getCurrentExtensionPropertiesList() {
    if (currentExtensionProperties == null) {
      currentExtensionProperties =
          new ListDataModel<>(
              new ArrayList<>(
                  getCurrentExtensionGUIInfo()
                      .getExtensionProperties()
                      .values()));
    }
    return currentExtensionProperties;
  }

  /**
   * @return edit
   */
  public String update() {
    return "edit";
  }

  /**
   * @param e event
   */
  public void updateExtension(final ValueChangeEvent e) {
    String extensionClass = (String) e.getNewValue();
    currentExtensionGUIInfo.setClassPath(extensionClass);
    currentExtensionProperties.setWrappedData(null);
    currentExtensionProperties = null;
  }

  /**
   * @return true if admin may create new or modify existing Custom Certificate
   *     Extensions.
   */
  public boolean isAllowedToEditCustomCertificateExtension() {
    return authorizationSession.isAuthorizedNoLogging(
            getAdmin(),
            StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource())
        && !systemConfigMBean.getCustomCertificateExtensionViewMode();
  }
}
