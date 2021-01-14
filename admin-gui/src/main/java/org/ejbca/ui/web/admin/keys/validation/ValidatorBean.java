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

package org.ejbca.ui.web.admin.keys.validation;

import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.html.HtmlPanelGrid;
import javax.faces.component.html.HtmlSelectOneMenu;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import javax.faces.validator.ValidatorException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.validation.ExternalCommandCertificateValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorBase;
import org.cesecore.keys.validation.KeyValidatorDateConditions;
import org.cesecore.keys.validation.KeyValidatorDoesntExistsException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSettingsTemplate;
import org.cesecore.keys.validation.PhasedValidator;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.keys.validation.ValidatorFactory;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiModelAware;
import org.cesecore.util.ui.DynamicUiModelException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.psm.jsf.JsfDynamicUiPsmFactory;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the edit key validators page.
 *
 * @version $Id: ValidatorBean.java 29467 2018-07-05 16:23:04Z mikekushner $
 */
// Declarations in faces-config.xml
// @javax.faces.bean.ViewScoped
// @javax.faces.bean.ManagedBean(name="validatorBean")
public class ValidatorBean extends BaseManagedBean implements Serializable {

  private static final long serialVersionUID = -2889613238729145716L;

  /** Class logger. */
  private static final Logger LOG = Logger.getLogger(ValidatorBean.class);

  /** Param. */
  @EJB private GlobalConfigurationSessionLocal configurationSession;

  /** Param. */
  @EJB private CertificateProfileSessionLocal certificateProfileSession;
  /** Param. */
  @EJB private KeyValidatorSessionLocal keyValidatorSession;

  /** Declarations in faces-config.xml.
   javax.faces.bean.ManagedProperty(value="#{validatorsBean}") */
  private ValidatorsBean validatorsBean;

  /** The validators ID. */
  private int validatorId;

  /** Selected key validator. */
  private Validator validator = null;

  /** Dynamic UI PIM component. */
  private DynamicUiModel uiModel;

  /** Dynamic UI PSM component. */
  private HtmlPanelGrid dataGrid;

  /** Resets the dynamic UI properties PSM. */
  private void reset() {
    setValidatorId(-1);
    validator = null;
  }

  /**
   * Checks if the administrator is authorized the edit key validators.
   *
   * @return true if the administrator is authorized.
   */
  public boolean hasEditRights() {
    return getEjbcaWebBean()
        .isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_EDITVALIDATOR);
  }

  /**
   * Gets the ValidatorsBean reference.
   *
   * @return the ValidatorsBean.
   */
  public ValidatorsBean getValidatorsBean() {
    return validatorsBean;
  }

  /**
   * Sets the ValidatorsBean reference.
   *
   * @param bean bean
   */
  public void setValidatorsBean(final ValidatorsBean bean) {
    this.validatorsBean = bean;
  }

  /**
   * Processes the key validation type changed event and renders the concrete
   * validator view.
   *
   * @param e the event.
   * @throws DynamicUiModelException if the PSM could not be initialized.
   */
  public void validatorTypeChanged(final AjaxBehaviorEvent e)
      throws DynamicUiModelException {
    setValidatorType(
        (String) ((HtmlSelectOneMenu) e.getComponent()).getValue());
    FacesContext.getCurrentInstance().renderResponse();
  }

  /**
   * @return Type
   */
  public String getValidatorType() {
    return getValidator().getValidatorTypeIdentifier();
  }

  /**
   * ˛ Sets the selected validator type. This re-creates the entire validator,
   * so only do it if it actually changed type.
   *
   * @param type the type {@link ValidatorBase#getValidatorTypeIdentifier()}.
   */
  public void setValidatorType(final String type) {
    final String oldType = validator.getValidatorTypeIdentifier();
    if (!oldType.equals(type)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Change key validator type from " + oldType + " to " + type);
      }
      setValidator(ValidatorFactory.INSTANCE.getArcheType(type));
      getValidator().setDataMap(getValidator().getDataMap());
      getValidator().setProfileId(validatorsBean.getValidatorId());
      getValidator().setProfileName(validatorsBean.getValidatorName());
    }
  }

  /**
   * Gets the selected validator.
   *
   * @return the validator.
   */
  public Validator getValidator() {
    // @ViewScoped: If the back link was called it may happen that the same view
    // is rendered again with another validator.
    final int newId =
        (validatorsBean.getValidatorId() != null
            ? validatorsBean.getValidatorId()
            : -1);
    final int oldId = getValidatorId();
    if (validator != null && oldId != newId) {
      reset();
    }
    if (validator == null && newId != -1) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Request validator with id " + newId);
      }
      setValidatorId(newId);
      setValidator(keyValidatorSession.getValidator(newId));
    }
    // (Re-)initialize dynamic UI PSM.
    if (validator instanceof DynamicUiModelAware) {
      if (uiModel == null
          || !uiModel.equals(
              ((DynamicUiModelAware) validator).getDynamicUiModel())) {
        ((DynamicUiModelAware) validator).initDynamicUiModel();
        uiModel = ((DynamicUiModelAware) validator).getDynamicUiModel();
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Request dynamic UI properties for validator with (id="
                  + validator.getProfileId()
                  + ") with properties "
                  + validator.getDataMap());
        }
        try {
          initGrid(uiModel, validator.getClass().getSimpleName());
        } catch (DynamicUiModelException e) {
          LOG.warn("Could not initialize dynamic UI PSM: " + e.getMessage(), e);
        }
      }
    }
    return validator;
  }

  /**
   * Sets the current validator.
   *
   * @param avalidator the validator.
   */
  public void setValidator(final Validator avalidator) {
    this.validator = avalidator;
  }

  /**
   * Gets the validators ID.
   *
   * @return the ID.
   */
  public int getValidatorId() {
    return validatorId;
  }

  /**
   * Sets the validators ID.
   *
   * @param avalidatorId the ID.
   */
  public void setValidatorId(final int avalidatorId) {
    this.validatorId = avalidatorId;
  }

  /**
   * Gets the dynamic UI properties PSM component as HTML data grid.
   *
   * @return the data grid.
   * @throws DynamicUiModelException if the PSM could not be initialized.
   */
  public HtmlPanelGrid getDataGrid() throws DynamicUiModelException {
    return dataGrid;
  }

  /**
   * Sets the dynamic UI properties PSM component as HTML data grid.
   *
   * @param adataGrid the data grid.
   */
  public void setDataGrid(final HtmlPanelGrid adataGrid) {
    this.dataGrid = adataGrid;
  }

  /**
   * Initializes the dynamic UI model grid panel.
   *
   * @param pim the PIM.
   * @param prefix the HTML components ID prefix.
   * @throws DynamicUiModelException if the PSM could not be created.
   */
  private void initGrid(final DynamicUiModel pim, final String prefix)
      throws DynamicUiModelException {
    if (dataGrid == null) {
      dataGrid = new HtmlPanelGrid();
      dataGrid.setId(getClass().getSimpleName() + "-dataGrid");
    }
    uiModel.setDisabled(validatorsBean.getViewOnly());
    JsfDynamicUiPsmFactory.initGridInstance(dataGrid, pim, prefix);
  }

  /**
   * Checks whether the Validator settings template is set to "Use custom
   * settings".
   *
   * @return true if custom settings are enabled
   */
  public boolean isCustomBaseSettingsEnabled() {
    return KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption()
        == getValidator().getSettingsTemplate();
  }

  /**
   * Gets the available key validator types.
   *
   * @return List of the available key validator types
   */
  public List<SelectItem> getAvailableValidators() {
    final List<Class<?>> excludeClasses = new ArrayList<>();
    if (!((GlobalConfiguration)
            configurationSession.getCachedConfiguration(
                GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
        .getEnableExternalScripts()) {
      excludeClasses.add(ExternalCommandCertificateValidator.class);
    }
    final List<SelectItem> ret = new ArrayList<>();
    for (final Validator avalidator
        : ValidatorFactory.INSTANCE.getAllImplementations(excludeClasses)) {
      ret.add(
          new SelectItem(
              avalidator.getValidatorTypeIdentifier(), avalidator.getLabel()));
    }
    Collections.sort(
        ret,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem o1, final SelectItem o2) {
            return o1.getLabel().compareToIgnoreCase(o2.getLabel());
          }
        });
    return ret;
  }

  /**
   * Gets a list of select items of the available base parameter options.
   *
   * @return the list.
   */
  public List<SelectItem> getAvailableValidatorSettingsTemplates() {
    final List<SelectItem> result = new ArrayList<>();
    final KeyValidatorSettingsTemplate[] items =
        KeyValidatorSettingsTemplate.values();
    for (int i = 0, j = items.length; i < j; i++) {
      result.add(
          new SelectItem(
              items[i].getOption(),
              getEjbcaWebBean().getText(items[i].getLabel())));
    }
    return result;
  }

  /**
   * Gets a list of select items of the certificate issuance process phases (see
   * {@link IssuancePhase}).
   *
   * @return the list.
   */
  public List<SelectItem> getAllApplicablePhases() {
    final List<SelectItem> result = new ArrayList<>();
    final IssuancePhase[] items = IssuancePhase.values();
    for (IssuancePhase phase : items) {
      result.add(
          new SelectItem(
              phase.getIndex(), getEjbcaWebBean().getText(phase.getLabel())));
    }
    return result;
  }

  /**
   * Gets a list of select items of the certificate issuance process phases (see
   * {@link IssuancePhase}).
   *
   * @return the list.
   */
  public List<SelectItem> getApplicablePhases() {
    final List<SelectItem> result = new ArrayList<>();
    for (Integer index
        : ((PhasedValidator) getValidator()).getApplicablePhases()) {
      result.add(
          new SelectItem(
              index,
              getEjbcaWebBean()
                  .getText(IssuancePhase.fromIndex(index).getLabel())));
    }
    return result;
  }

  /**
   * Validates the description field, see {@link
   * ValidatorBase#getDescription()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateDescription(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    final String descripion = (String) value;
    final int max = 256;
    if (StringUtils.isNotBlank(descripion)
        && descripion.trim().length() > max) {
      final String message =
          "Description must not contain more than 256 characters.";
      if (LOG.isDebugEnabled()) {
        LOG.debug(message);
      }
      throw new ValidatorException(
          new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
    }
  }

  /**
   * Validates the BaseKeyValildator notBefore field, see {@link
   * org.cesecore.keys.validation.ValidityAwareValidator#getNotBefore()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateNotBefore(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    final String string = (String) value;
    try {
      if (StringUtils.isNotBlank(string)
          && null == KeyValidatorBase.parseDate(string)) {
        final String message =
            "Key validator not before must be a valid ISO 8601 date or time "
                + value;
        throw new ValidatorException(
            new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
      }
    } catch (ParseException e) {
      LOG.debug("Could not parse Date: " + string);
    }
  }

  /**
   * Validates the BaseKeyValildator notBefore condition field, see {@link
   * org.cesecore.keys.validation.ValidityAwareValidator#getNotBeforeCondition()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateNotBeforeCondition(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    final Integer type = (Integer) value;
    if (!KeyValidatorDateConditions.index().contains(type)) {
      final String message =
          "Key validator not before condition must be on of "
              + KeyValidatorDateConditions.index();
      throw new ValidatorException(
          new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
    }
  }

  /**
   * Validates the BaseKeyValildator notAfter field, see {@link
   * org.cesecore.keys.validation.ValidityAwareValidator#getNotAfter()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateNotAfter(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    final String string = (String) value;
    try {
      if (StringUtils.isNotBlank(string)
          && null == KeyValidatorBase.parseDate((String) value)) {
        final String message =
            "Key validator not after must be a valid ISO 8601 date or time "
                + value;
        throw new ValidatorException(
            new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
      }
    } catch (ParseException e) {
      LOG.debug("Could not parse Date: " + string);
    }
  }

  /**
   * Validates the BaseKeyValildator notAfter condition field, see {@link
   * org.cesecore.keys.validation.ValidityAwareValidator#getNotAfterCondition()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateNotAfterCondition(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    final Integer index = (Integer) value;
    if (!KeyValidatorDateConditions.index().contains(index)) {
      final String message =
          "Key validator not after condition must be on of "
              + KeyValidatorDateConditions.index();
      throw new ValidatorException(
          new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
    }
  }

  /**
   * Validates the BaseKeyValildator failedAction field, see {@link
   * ValidatorBase#getFailedAction()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateFailedAction(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    final Integer index = (Integer) value;
    if (!KeyValidationFailedActions.index().contains(index)) {
      final String message =
          "Key validator action must be on of "
              + KeyValidatorDateConditions.index();
      throw new ValidatorException(
          new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
    }
  }

  /**
   * Validates the BaseKeyValildator certificateProfileIds field, see {@link
   * ValidatorBase#getCertificateProfileIds()}.
   *
   * @param context the faces context.
   * @param component the events source component
   * @param value the source components value attribute
   * @throws ValidatorException if the validation fails.
   */
  public void validateCertificateProfileIds(
      final FacesContext context,
      final UIComponent component,
      final Object value)
      throws ValidatorException {
    @SuppressWarnings("unchecked")
    final List<String> selectedIds = (List<String>) value;
    final List<Integer> ids =
        new ArrayList<>(
            certificateProfileSession
                .getCertificateProfileIdToNameMap()
                .keySet());
    for (String id : selectedIds) {
      if (!ids.contains(Integer.parseInt(id))) {
        final String message =
            "Key validator certificate profile id must be on of " + ids;
        throw new ValidatorException(
            new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
      }
    }
  }

  /**
   * Cancel action.
   *
   * @return the navigation outcome defined in faces-config.xml.
   */
  public String cancel() {
    reset();
    return "done";
  }

  /**
   * Save action.
   *
   * @return the navigation outcome defined in faces-config.xml.
   */
  public String save() {
    final Validator avalidator = getValidator();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Try to save validator: " + avalidator);
    }
    try {
      if (avalidator instanceof DynamicUiModelAware) {
        ((DynamicUiModelAware) avalidator)
            .getDynamicUiModel()
            .writeProperties(((ValidatorBase) avalidator).getRawData());
      }
      keyValidatorSession.changeKeyValidator(getAdmin(), avalidator);
      addInfoMessage("VALIDATORSAVED");
      reset();
      return "done";
    } catch (AuthorizationDeniedException e) {
      addNonTranslatedErrorMessage(
          "Not authorized to edit validator " + avalidator.getProfileName());
    } catch (KeyValidatorDoesntExistsException e) {
      // NOPMD: ignore do nothing
    }
    return StringUtils.EMPTY;
  }

  /**
   * Gets a list of select items of the available certificate profiles.
   *
   * @return the list.
   */
  public List<SelectItem> getAvailableCertificateProfiles() {
    final List<SelectItem> result = new ArrayList<>();
    List<Integer> authorizedCertificateProfiles =
        certificateProfileSession.getAuthorizedCertificateProfileIds(
            getAdmin(), CertificateConstants.CERTTYPE_UNKNOWN);
    final Map<Integer, String> map =
        certificateProfileSession.getCertificateProfileIdToNameMap();
    for (Integer certificateProfileId : authorizedCertificateProfiles) {
      // Don't include fixed certificate profiles in validators, keep it clean
      // and force usage of "real"
      // profiles if you want to issue serious certificates.
      if (certificateProfileId
          > CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
        result.add(
            new SelectItem(
                certificateProfileId, map.get(certificateProfileId)));
      }
    }
    Collections.sort(
        result,
        new Comparator<SelectItem>() {
          @Override
          public int compare(final SelectItem o1, final SelectItem o2) {
            return o1.getLabel().compareToIgnoreCase(o2.getLabel());
          }
        });
    return result;
  }

  /**
   * Gets the BaseKeyValidator certificateProfileIds field.
   *
   * @return the list
   */
  public List<Integer> getCertificateProfileIds() {
    return getValidator().getCertificateProfileIds();
  }

  /**
   * Sets the BaseKeyValidator certificateProfileIds field.
   *
   * @param ids the list of certificate profile IDs.
   */
  public void setCertificateProfileIds(final List<String> ids) {
    final List<Integer> list = new ArrayList<>();
    for (String id : ids) {
      list.add(Integer.parseInt(id));
    }
    getValidator().setCertificateProfileIds(list);
  }

  /**
   * Gets a list of select items of the available notBefore conditions.
   *
   * @return the list.
   */
  public List<SelectItem> getAvailableNotBeforeConditions() {
    return conditionsToSelectItems();
  }

  /**
   * Gets a list of select items of the available notAfter conditions.
   *
   * @return the list.
   */
  public List<SelectItem> getAvailableNotAfterConditions() {
    return conditionsToSelectItems();
  }

  /**
   * Gets a list of select items of the available failed actions.
   *
   * @return the list.
   */
  public List<SelectItem> getAvailableFailedActions() {
    final List<SelectItem> result = new ArrayList<>();
    final KeyValidationFailedActions[] items =
        KeyValidationFailedActions.values();
    for (int i = 0, j = items.length; i < j; i++) {
      result.add(
          new SelectItem(
              items[i].getIndex(),
              getEjbcaWebBean().getText(items[i].getLabel())));
    }
    return result;
  }

  /**
   * Transforms date condition enumerations to a list of select items.
   *
   * @return the list.
   */
  private List<SelectItem> conditionsToSelectItems() {
    final List<SelectItem> result = new ArrayList<>();
    final KeyValidatorDateConditions[] items =
        KeyValidatorDateConditions.values();
    for (int i = 0, j = items.length; i < j; i++) {
      result.add(
          new SelectItem(
              items[i].getIndex(),
              getEjbcaWebBean().getText(items[i].getLabel())));
    }
    return result;
  }
}
