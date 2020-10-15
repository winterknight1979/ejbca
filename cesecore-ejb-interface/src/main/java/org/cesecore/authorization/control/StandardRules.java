/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.control;

/** @version $Id: StandardRules.java 26312 2017-08-15 07:15:23Z anatom $ */
public enum StandardRules {
      /** System. */
  ROLE_ROOT("/"),
  /** System. */
  CAACCESSBASE("/ca"),
  /** System. */
  CAACCESS("/ca/"),
  /** System. */
  CAACCESSANYCA("/ca/-1"),
  /** System. */
  CAFUNCTIONALITY("/ca_functionality"),
  /** Delete. */
  CAREMOVE(CAFUNCTIONALITY.resource() + "/remove_ca"),
  /** Create. */
  CAADD(CAFUNCTIONALITY.resource() + "/add_ca"),
  /** Edit. */
  CAEDIT(CAFUNCTIONALITY.resource() + "/edit_ca"),
  /** Create. */
  CARENEW(CAFUNCTIONALITY.resource() + "/renew_ca"),
  /** View. */
  CAVIEW(CAFUNCTIONALITY.resource() + "/view_ca"),
  /** Create. */
  CREATECERT(CAFUNCTIONALITY.resource() + "/create_certificate"),
  /** Edit. */
  CERTIFICATEPROFILEEDIT(
      CAFUNCTIONALITY.resource() + "/edit_certificate_profiles"),
  /** View. */
  CERTIFICATEPROFILEVIEW(
      CAFUNCTIONALITY.resource() + "/view_certificate_profiles"),
  /** Create. */
  CREATECRL(CAFUNCTIONALITY.resource() + "/create_crl"),
  /** Validator. */
  VALIDATORACCESSBASE("/validator"),
  /** Validator. */
  VALIDATORACCESS("/validator/"),
  /** Edit. */
  BLACKLISTEDIT(CAFUNCTIONALITY.resource() + "/edit_blacklist"),
  /** View. */
  VALIDATORVIEW(CAFUNCTIONALITY.resource() + "/view_validator"),
  /** Edit. */
  VALIDATOREDIT(CAFUNCTIONALITY.resource() + "/edit_validator"),
  /** System. */
  SYSTEMFUNCTIONALITY("/system_functionality"),
  /** Edit. */
  EDITROLES(SYSTEMFUNCTIONALITY.resource() + "/edit_administrator_privileges"),
  /** View. */
  VIEWROLES(SYSTEMFUNCTIONALITY.resource() + "/view_administrator_privileges"),
  /** Recover. */
  RECOVERY("/recovery"),
  /** Backup. */
  BACKUP(RECOVERY.resource() + "/backup"),
  /** Restore. */
  RESTORE(RECOVERY.resource() + "/restore"),
  /** Edit. */
  SYSTEMCONFIGURATION_EDIT(
      SYSTEMFUNCTIONALITY.resource() + "/edit_systemconfiguration"),
  /** View. */
  SYSTEMCONFIGURATION_VIEW(
      SYSTEMFUNCTIONALITY.resource() + "/view_systemconfiguration"),
  /** Edit. */
  EKUCONFIGURATION_EDIT(
      SYSTEMFUNCTIONALITY.resource() + "/edit_available_extended_key_usages"),
  /** View. */
  EKUCONFIGURATION_VIEW(
      SYSTEMFUNCTIONALITY.resource() + "/view_available_extended_key_usages"),
  /** Edit. */
  CUSTOMCERTEXTENSIONCONFIGURATION_EDIT(
      SYSTEMFUNCTIONALITY.resource()
          + "/edit_available_custom_certificate_extensions"),
  /** View. */
  CUSTOMCERTEXTENSIONCONFIGURATION_VIEW(
      SYSTEMFUNCTIONALITY.resource()
          + "/view_available_custom_certificate_extensions"),
  /** Edit. */
  APPROVALPROFILEEDIT(CAFUNCTIONALITY.resource() + "/edit_approval_profiles"),
  /** View. */
  APPROVALPROFILEVIEW(CAFUNCTIONALITY.resource() + "/view_approval_profiles");

    /** Resource. */
  private final String resource;

  StandardRules(final String aResource) {
    this.resource = aResource;
  }

  /**
   * @return resource
   */
  public String resource() {
    return this.resource;
  }

  @Override
  public String toString() {
    return this.resource;
  }
}
