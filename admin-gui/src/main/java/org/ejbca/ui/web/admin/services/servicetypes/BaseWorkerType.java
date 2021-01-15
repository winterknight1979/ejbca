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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import org.ejbca.core.model.services.IWorker;

/**
 * Base type for workers.
 *
 * @version $Id: BaseWorkerType.java 28844 2018-05-04 08:31:02Z samuellb $
 */
public abstract class BaseWorkerType extends WorkerType {

  private static final long serialVersionUID = 7026884019102752494L;

  /** Param. */
  public static final String DEFAULT_TIMEUNIT = IWorker.UNIT_DAYS;
  /** Param. */
  public static final String DEFAULT_TIMEVALUE = "7";

  /** Param. */
  private List<String> selectedCANamesToCheck = new ArrayList<>();
  /** Param. */
  private List<String> selectedCertificateProfilesToCheck = new ArrayList<>();
  /** Param. */
  private Collection<String> compatibleActionTypeNames = new ArrayList<>();
  /** Param. */
  private Collection<String> compatibleIntervalTypeNames = new ArrayList<>();
  /** Param. */
  private String classpath = null;

  /**
   * @param subViewPage Page
   * @param name Name
   * @param translatable bool
   * @param aclasspath cp
   */
  public BaseWorkerType(
      final String subViewPage,
      final String name,
      final boolean translatable,
      final String aclasspath) {
    super(subViewPage, name, translatable);
    this.classpath = aclasspath;
  }

  //
  // Helper methods for BaseWorkerType to be used by extending classes
  //
  /**
   * @param name Name
   */
  protected void addCompatibleActionTypeName(final String name) {
    compatibleActionTypeNames.add(name);
  }

  /** Delete.
   */
  protected void deleteAllCompatibleActionTypes() {
    compatibleActionTypeNames = new ArrayList<>();
  }

  /**
   * @param name Name
   */
  protected void addCompatibleIntervalTypeName(final String name) {
    compatibleIntervalTypeNames.add(name);
  }

  /**
   * Delete.
   */
  protected void deleteAllCompatibleIntervalTypes() {
    compatibleIntervalTypeNames = new ArrayList<>();
  }

  /**
   * @return names
   */
  public List<String> getSelectedCANamesToCheck() {
    return selectedCANamesToCheck;
  }

  /**
   * @param aselectedCANamesToCheck names
   */
  public void setSelectedCANamesToCheck(
      final List<String> aselectedCANamesToCheck) {
    this.selectedCANamesToCheck = aselectedCANamesToCheck;
  }

  @Override
  public boolean isCustom() {
    return false;
  }

  @Override
  public Collection<String> getCompatibleActionTypeNames() {
    return compatibleActionTypeNames;
  }

  @Override
  public Collection<String> getCompatibleIntervalTypeNames() {
    return compatibleIntervalTypeNames;
  }

  @Override
  public String getClassPath() {
    return classpath;
  }

  @Override
  public Properties getProperties(final ArrayList<String> errorMessages)
      throws IOException {
    Properties retval = new Properties();
    String caIdString = null;
    for (String cAid : getSelectedCANamesToCheck()) {
      if (!cAid.trim().equals("")) {
        if (caIdString == null) {
          caIdString = cAid;
        } else {
          caIdString += ";" + cAid;
        }
      }
    }
    if (caIdString != null) {
      retval.setProperty(IWorker.PROP_CAIDSTOCHECK, caIdString);
    }
    String certificateProfileIdString = null;
    for (String certificateProfileId
        : getSelectedCertificateProfilesToCheck()) {
      if (!certificateProfileId.trim().equals("")) {
        if (certificateProfileIdString == null) {
          certificateProfileIdString = certificateProfileId;
        } else {
          certificateProfileIdString += ";" + certificateProfileId;
        }
      }
    }
    if (certificateProfileIdString != null) {
      retval.setProperty(
          IWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK,
          certificateProfileIdString);
    }
    return retval;
  }

  @Override
  public void setProperties(final Properties properties) throws IOException {
    ArrayList<String> aselectedCANamesToCheck = new ArrayList<>();
    aselectedCANamesToCheck.addAll(
        Arrays.asList(
            properties.getProperty(IWorker.PROP_CAIDSTOCHECK, "").split(";")));
    setSelectedCANamesToCheck(aselectedCANamesToCheck);
    ArrayList<String> selectedCertificateProfileNamesToCheck =
        new ArrayList<>();
    selectedCertificateProfileNamesToCheck.addAll(
        Arrays.asList(
            properties
                .getProperty(IWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK, "")
                .split(";")));
    setSelectedCertificateProfilesToCheck(
        selectedCertificateProfileNamesToCheck);
  }

  /** @return the selectedCertificateProfilesToCheck */
  public List<String> getSelectedCertificateProfilesToCheck() {
    return selectedCertificateProfilesToCheck;
  }

  /**
   * @param aselectedCertificateProfilesToCheck the
   *     selectedCertificateProfilesToCheck to set
   */
  public void setSelectedCertificateProfilesToCheck(
      final List<String> aselectedCertificateProfilesToCheck) {
    this.selectedCertificateProfilesToCheck =
        aselectedCertificateProfilesToCheck;
  }
}
