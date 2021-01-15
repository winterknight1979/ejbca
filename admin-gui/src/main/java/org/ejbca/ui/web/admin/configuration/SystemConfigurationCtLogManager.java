/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.configuration;

import java.io.IOException;
import java.util.Calendar;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CtLogManager;
import org.cesecore.keys.util.KeyTools;

/**
 * This class is used to manage CT logs in EJBCA's system configuration. It adds
 * some additional functionality to the CtLogManager, such as loading and saving
 * state from the database, editing of new CT logs, checking whether a CT log is
 * in use before removing it and language awareness.
 *
 * @version $Id: SystemConfigurationCtLogManager.java 28511 2018-03-18 21:24:03Z
 *     bastianf $
 */
public class SystemConfigurationCtLogManager extends CtLogManager {
    /** PAram. */
  private static final String EDIT_CT_LOG = "editCTLog";
  /** PAram. */
  private static final String CT_LOG_SAVED = "saved";
  /** PAram. */
  private static final Logger LOG =
      Logger.getLogger(SystemConfigurationCtLogManager.class);
  /** PAram. */
  private final SystemConfigurationHelper systemConfigurationHelper;
  /** PAram. */
  private final CtLogEditor ctLogEditor;

  public class CtLogEditor {

        /** PAram. */
    private final int def = 5000;
    /** PAram. */
    private String url;
    /** PAram. */
    private UploadedFile publicKeyFile;
    /** PAram. */
    private String label;
    /** PAram. */
    private int timeout = def;
    /** PAram. */
    private CTLogInfo ctLogBeingEdited;
    /** PAram. */
    private boolean isAcceptingByExpirationYear;
    /** PAram. */
    private String expirationYearRequired;

    /**
     * @return URL
     */
    public String getCtLogUrl() {
      if (StringUtils.isEmpty(url)) {
        return null;
      }
      return CTLogInfo.fixUrl(url);
    }

    /**
     * @return file
     */
    public UploadedFile getPublicKeyFile() {
      return publicKeyFile;
    }

    /**
     * @return label
     */
    public String getCtLogLabel() {
      return label;
    }

    /**
     * @return timeoutr
     */
    public int getCtLogTimeout() {
      return timeout;
    }

    /**
     * @param aurl URL
     */
    public void setCtLogUrl(final String aurl) {
      this.url = aurl;
    }

    /**
     * @param apublicKeyFile file
     */
    public void setPublicKeyFile(final UploadedFile apublicKeyFile) {
      this.publicKeyFile = apublicKeyFile;
    }

    /**
     * @param alabel label
     */
    public void setCtLogLabel(final String alabel) {
      this.label = alabel;
    }

    /**
     * @param atimeout timeout
     */
    public void setCtLogTimeout(final int atimeout) {
      this.timeout = atimeout;
    }

    /**
     * @return bool
     */
    public boolean hasValidUrl() {
      return url.contains("://");
    }

    /**
     * Set a boolean indicating whether the log being edited only accepts
     * certificates with a certain year of expiry, e.g. all certificates
     * expiring in 2019.
     *
     * @param anisAcceptingByExpirationYear true if the log is discriminating
     *     based on year of expiry
     */
    public void setIsAcceptingByExpirationYear(
        final boolean anisAcceptingByExpirationYear) {
      this.isAcceptingByExpirationYear = anisAcceptingByExpirationYear;
    }

    /**
     * @return bool
     */
    public boolean getIsAcceptingByExpirationYear() {
      return isAcceptingByExpirationYear;
    }

    /**
     * @param anexpirationYearRequired year
     */
    public void setExpirationYearRequired(
            final String anexpirationYearRequired) {
      this.expirationYearRequired = anexpirationYearRequired;
    }

    /**
     * @return year
     */
    public String getExpirationYearRequired() {
      return expirationYearRequired;
    }

    /**
     * Load an existing CT log into the editor.
     *
     * @param ctLog Log
     */
    public void loadIntoEditor(final CTLogInfo ctLog) {
      this.label = ctLog.getLabel();
      // Only replace the key if a new one was uploaded
      this.publicKeyFile = null;
      this.timeout = ctLog.getTimeout();
      this.url = ctLog.getUrl();
      this.ctLogBeingEdited = ctLog;
      this.isAcceptingByExpirationYear =
          ctLog.getExpirationYearRequired() != null;
      this.expirationYearRequired =
          ctLog.getExpirationYearRequired() == null
              ? String.valueOf(Calendar.getInstance().get(Calendar.YEAR))
              : String.valueOf(ctLog.getExpirationYearRequired());
    }

    /** Reset all input to this CT log editor. */
    public void clear() {
      url = null;
      publicKeyFile = null;
      label = null;
      timeout = def;
    }

    /**
     * Returns the CT log currently being edited by this CT log editor.
     *
     * @return the CT log being edited, or null
     */
    public CTLogInfo getCtLogBeingEdited() {
      return ctLogBeingEdited;
    }

    /** Stop. */
    public void stopEditing() {
      ctLogBeingEdited = null;
      clear();
    }
  }

  public interface SystemConfigurationHelper {
    /**
     * Displays an error message to the user.
     *
     * @param languageKey the language key of the message to show
     */
    void addErrorMessage(String languageKey);

    /**
     * Displays an error message to the user with a formatted message.
     *
     * @param languageKey the language key of the message to show
     * @param params additional parameters to include in the error message
     */
    void addErrorMessage(String languageKey, Object... params);

    /**
     * Displays an information message to the user.
     *
     * @param languageKey the language key of the message to show
     */
    void addInfoMessage(String languageKey);

    /**
     * Saves a list of CT logs to persistent storage.
     *
     * @param ctLogs the CT logs to save
     */
    void saveCtLogs(List<CTLogInfo> ctLogs);

    /**
     * Get a list with names of certificate profiles which references a
     * particular CT log.
     *
     * @param ctLog a CT log which should be checked
     * @return a list of profile names, referencing the CT log given as input or
     *     empty if the CT log is not in use
     */
    List<String> getCertificateProfileNamesByCtLog(CTLogInfo ctLog);
  }

  /**   *
   * @param ctLogs Logs
   * @param asystemConfigurationHelper Helper
   */
  public SystemConfigurationCtLogManager(
      final List<CTLogInfo> ctLogs,
      final SystemConfigurationHelper asystemConfigurationHelper) {
    super(ctLogs);
    this.systemConfigurationHelper = asystemConfigurationHelper;
    this.ctLogEditor = new CtLogEditor();
  }

  private byte[] getCtLogPublicKey(final UploadedFile upload) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Received uploaded public key file: " + upload.getName());
    }
    try {
      byte[] uploadedFileBytes = upload.getBytes();
      return KeyTools.getBytesFromPublicKeyFile(uploadedFileBytes);
    } catch (final IOException e) {
      LOG.info("Could not parse the public key file.", e);
      systemConfigurationHelper.addErrorMessage(
          "CTLOGTAB_BADKEYFILE", upload.getName(), e.getLocalizedMessage());
      return null;
    } catch (final Exception e) {
      LOG.info("Failed to add CT Log.", e);
      systemConfigurationHelper.addErrorMessage(
          "CTLOGTAB_GENERICADDERROR", e.getLocalizedMessage());
      return null;
    }
  }

  /** Adds a CT log with the information stored in the CT log editor. */
  public void addCtLog() {
    if (ctLogEditor.getCtLogUrl() == null
        || !ctLogEditor.getCtLogUrl().contains("://")) {
      systemConfigurationHelper.addErrorMessage("CTLOGTAB_MISSINGPROTOCOL");
      return;
    }
    if (ctLogEditor.getPublicKeyFile() == null) {
      systemConfigurationHelper.addErrorMessage("CTLOGTAB_UPLOADFAILED");
      return;
    }
    if (ctLogEditor.getCtLogTimeout() <= 0) {
      systemConfigurationHelper.addErrorMessage("CTLOGTAB_TIMEOUTNEGATIVE");
      return;
    }

    final byte[] newCtLogPublicKey =
        getCtLogPublicKey(ctLogEditor.getPublicKeyFile());
    if (newCtLogPublicKey == null) {
      // Error already reported
      return;
    }

    final CTLogInfo newCtLog =
        new CTLogInfo(
            ctLogEditor.getCtLogUrl(),
            newCtLogPublicKey,
            ctLogEditor.getCtLogLabel(),
            ctLogEditor.getCtLogTimeout());

    if (!super.canAdd(newCtLog)) {
      systemConfigurationHelper.addErrorMessage(
          "CTLOGTAB_ALREADYEXISTS", newCtLog.toString());
      return;
    }

    super.addCtLog(newCtLog);
    systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
    ctLogEditor.clear();
  }

  @Override
  public void removeCtLog(final CTLogInfo ctLog) {
    final List<String> usedByProfiles =
        systemConfigurationHelper.getCertificateProfileNamesByCtLog(ctLog);
    if (!usedByProfiles.isEmpty()) {
      systemConfigurationHelper.addErrorMessage(
          "CTLOGTAB_INUSEBYPROFILES", StringUtils.join(usedByProfiles, ", "));
      return;
    }
    super.removeCtLog(ctLog);
    systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
  }

  @Override
  public void moveUp(final CTLogInfo ctLog) {
    super.moveUp(ctLog);
    systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
  }

  @Override
  public void moveDown(final CTLogInfo ctLog) {
    super.moveDown(ctLog);
    systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
  }

  /**
   * Prepares for a CT log to be edited. This method will load the specified CT
   * log into the CT log editor and set the editor in edit mode.
   *
   * @param ctLog the CT log to be edited
   * @return the constant string EDIT_CT_LOG
   */
  public String editCtLog(final CTLogInfo ctLog) {
    ctLogEditor.loadIntoEditor(ctLog);
    return EDIT_CT_LOG;
  }

  /**
   * Retrieves the CT log editor for this CT log manager.
   *
   * @return an editor which can be used to edit CT logs
   */
  public CtLogEditor getCtLogEditor() {
    return ctLogEditor;
  }

  /**
   * Save the CT log currently being edited.
   *
   * @return an empty string on failure or the constant string CT_LOG_SAVED on
   *     success
   * @throws IllegalStateException if there is no CT log to save
   */
  public String saveCtLogBeingEdited() {
    if (ctLogEditor.getCtLogBeingEdited() == null) {
      throw new IllegalStateException(
          "The CT log being edited has already been saved or was never"
              + " loaded.");
    }

    /* Validate data entry by the user */
    if (!ctLogEditor.hasValidUrl()) {
      systemConfigurationHelper.addErrorMessage("CTLOGTAB_MISSINGPROTOCOL");
      return StringUtils.EMPTY;
    }
    if (ctLogEditor.getCtLogTimeout() <= 0) {
      systemConfigurationHelper.addErrorMessage("CTLOGTAB_TIMEOUTNEGATIVE");
      return StringUtils.EMPTY;
    }
    if (ctLogEditor.getPublicKeyFile() != null) {
      final byte[] keyBytes = getCtLogPublicKey(ctLogEditor.getPublicKeyFile());
      if (keyBytes == null) {
        // Error already reported
        return StringUtils.EMPTY;
      }
    }
    if (ctLogEditor.getIsAcceptingByExpirationYear()
        && !StringUtils.isNumeric(ctLogEditor.getExpirationYearRequired())) {
      systemConfigurationHelper.addErrorMessage(
          "CTLOGCONFIGURATION_INVALID_YEAR");
      return StringUtils.EMPTY;
    }

    /* Ensure the new log configuration is not conflicting with another log */
    final CTLogInfo ctLogToUpdate = ctLogEditor.getCtLogBeingEdited();
    for (final CTLogInfo existing : super.getAllCtLogs()) {
      final boolean isSameLog = existing.getLogId() == ctLogToUpdate.getLogId();
      final boolean urlExistsInCtLogGroup =
          StringUtils.equals(existing.getUrl(), ctLogEditor.getCtLogUrl())
              && StringUtils.equals(
                  existing.getLabel(), ctLogEditor.getCtLogLabel());
      if (!isSameLog && urlExistsInCtLogGroup) {
        systemConfigurationHelper.addErrorMessage(
            "CTLOGTAB_ALREADYEXISTS", existing.getUrl());
        return StringUtils.EMPTY;
      }
    }

    /* Update the configuration */
    final String url = ctLogEditor.getCtLogUrl();
    final byte[] keyBytes =
        ctLogEditor.getPublicKeyFile() != null
            ? getCtLogPublicKey(ctLogEditor.getPublicKeyFile())
            : ctLogEditor.getCtLogBeingEdited().getPublicKeyBytes();
    final int timeout = ctLogEditor.getCtLogTimeout();
    final String label = ctLogEditor.getCtLogLabel();
    ctLogToUpdate.setLogPublicKey(keyBytes);
    ctLogToUpdate.setTimeout(timeout);
    ctLogToUpdate.setUrl(url);
    ctLogToUpdate.setLabel(label);
    ctLogToUpdate.setExpirationYearRequired(
        ctLogEditor.getIsAcceptingByExpirationYear()
            ? Integer.valueOf(ctLogEditor.getExpirationYearRequired())
            : null);
    systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
    ctLogEditor.stopEditing();
    return CT_LOG_SAVED;
  }

  @Override
  public void renameLabel(final String oldLabel, final String newLabel) {
    super.renameLabel(oldLabel, newLabel);
    systemConfigurationHelper.saveCtLogs(super.getAllCtLogs());
  }

  /**
   * @param ctLog Log
   * @return Labels
   */
  public List<String> getAvailableLabels(final CTLogInfo ctLog) {
    final List<String> labels = super.getLabels();
    // Remove labels already containing a CT log with the same URL
    for (int i = labels.size() - 1; i >= 0; i--) {
      final String label = labels.get(i);
      if (StringUtils.equals(label, ctLog.getLabel())) {
        // Always add the CT log label of the log itself
        continue;
      }
      final List<CTLogInfo> logGroupMembers = super.getCtLogsByLabel(label);
      if (logGroupHasAnotherCtLogWithSameUrl(logGroupMembers, ctLog)) {
        labels.remove(i);
      }
    }
    return labels;
  }

  private boolean logGroupHasAnotherCtLogWithSameUrl(
      final List<CTLogInfo> logGroupMembers, final CTLogInfo ctLog) {
    for (final CTLogInfo logGroupMember : logGroupMembers) {
      if (logGroupMember.getLogId() != ctLog.getLogId()
          && StringUtils.equals(logGroupMember.getUrl(), ctLog.getUrl())) {
        return true;
      }
    }
    return false;
  }
}
