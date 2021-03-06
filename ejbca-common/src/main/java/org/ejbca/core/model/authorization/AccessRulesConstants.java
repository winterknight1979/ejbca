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

package org.ejbca.core.model.authorization;

import org.cesecore.authorization.control.StandardRules;

/**
 * @version $Id: AccessRulesConstants.java 29240 2018-06-15 14:51:31Z henriks $
 */
public abstract class AccessRulesConstants {

  // Available end entity authorization rules.
      /** Config. */
  public static final String VIEW_END_ENTITY = "/view_end_entity";
  /** Config. */
  public static final String EDIT_END_ENTITY = "/edit_end_entity";
  /** Config. */
  public static final String CREATE_END_ENTITY = "/create_end_entity";
  /** Config. */
  public static final String DELETE_END_ENTITY = "/delete_end_entity";
  /** Config. */
  public static final String REVOKE_END_ENTITY = "/revoke_end_entity";
  /** Config. */
  public static final String VIEW_END_ENTITY_HISTORY =
      "/view_end_entity_history";
  /** Config. */
  public static final String APPROVE_END_ENTITY = "/approve_end_entity";
  /** Config. */

  public static final String HARDTOKEN_RIGHTS = "/view_hardtoken";
  /** Config. */
  public static final String HARDTOKEN_PUKDATA_RIGHTS =
      "/view_hardtoken/puk_data";

  /** Config. */
  public static final String KEYRECOVERY_RIGHTS = "/keyrecovery";

  /** Endings used in profile authorization. */
  public static final String[] ENDENTITYPROFILE_ENDINGS = {
    VIEW_END_ENTITY,
    EDIT_END_ENTITY,
    CREATE_END_ENTITY,
    DELETE_END_ENTITY,
    REVOKE_END_ENTITY,
    VIEW_END_ENTITY_HISTORY,
    APPROVE_END_ENTITY
  };

  /** Name of end entity profile prefix directory in authorization module. */
  public static final String ENDENTITYPROFILEBASE = "/endentityprofilesrules";
  /** Config. */
  public static final String ENDENTITYPROFILEPREFIX =
      "/endentityprofilesrules/";

  /** Name of end entity profile prefix directory in authorization module. */
  public static final String USERDATASOURCEBASE = "/userdatasourcesrules";
  /** Config. */
  public static final String USERDATASOURCEPREFIX = "/userdatasourcesrules/";

  /** Config. */
  public static final String UDS_FETCH_RIGHTS = "/fetch_userdata";
  /** Config. */
  public static final String UDS_REMOVE_RIGHTS = "/remove_userdata";

  /** Endings used in profile authorization. */
  public static final String[] USERDATASOURCE_ENDINGS = {
    UDS_FETCH_RIGHTS, UDS_REMOVE_RIGHTS
  };

  // CA access rules are managed in CESecore, see StandardRules

  /** Config. */
  public static final String ROLE_ADMINISTRATOR = "/administrator";
  /** Config. */
  public static final String REGULAR_ACTIVATECA =
      StandardRules.CAFUNCTIONALITY.resource() + "/activate_ca";
  /** Config. */
  public static final String REGULAR_VIEWCERTIFICATE =
      StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate";
  /** Config. */
  public static final String REGULAR_APPROVECAACTION =
      StandardRules.CAFUNCTIONALITY.resource() + "/approve_caaction";
  /** Config. */
  public static final String REGULAR_CREATECRL =
      StandardRules.CREATECRL.resource();
  /** Config. */
  public static final String REGULAR_CREATECERTIFICATE =
      StandardRules.CREATECERT.resource();
  /** Config. */
  public static final String REGULAR_EDITPUBLISHER =
      StandardRules.CAFUNCTIONALITY.resource() + "/edit_publisher";
  /** Config. */
  public static final String REGULAR_VIEWPUBLISHER =
      StandardRules.CAFUNCTIONALITY.resource() + "/view_publisher";
  /** Config. */
  public static final String REGULAR_EDITVALIDATOR =
      StandardRules.VALIDATOREDIT.resource();
  /** Config. */
  public static final String REGULAR_VIEWVALIDATOR =
      StandardRules.VALIDATORVIEW.resource();
  /** Config. */
  public static final String REGULAR_EDITBLACKLIST =
      StandardRules.BLACKLISTEDIT.resource();
  /** Config. */
  public static final String REGULAR_RAFUNCTIONALITY = "/ra_functionality";
  /** Config. */
  public static final String REGULAR_EDITENDENTITYPROFILES =
      REGULAR_RAFUNCTIONALITY + "/edit_end_entity_profiles";
  /** Config. */
  public static final String REGULAR_VIEWENDENTITYPROFILES =
      REGULAR_RAFUNCTIONALITY + "/view_end_entity_profiles";
  /** Config. */
  public static final String REGULAR_EDITUSERDATASOURCES =
      REGULAR_RAFUNCTIONALITY + "/edit_user_data_sources";
  /** Config. */
  public static final String REGULAR_APPROVEENDENTITY =
      REGULAR_RAFUNCTIONALITY + APPROVE_END_ENTITY;
  // REGULAR_REVOKEENDENTITY is used when revoking the certificate of a user
  /** Config. */
  public static final String REGULAR_REVOKEENDENTITY =
      REGULAR_RAFUNCTIONALITY + REVOKE_END_ENTITY;
  // The rules below seem to be for rights to certificates, and ae mostly used
  // from WS for token certificates and CMP for token certificates
  // You can question if these are valid and right?
  /** Config. */
  public static final String REGULAR_VIEWENDENTITY =
      REGULAR_RAFUNCTIONALITY + VIEW_END_ENTITY;
  /** Config. */
  public static final String REGULAR_CREATEENDENTITY =
      REGULAR_RAFUNCTIONALITY + CREATE_END_ENTITY;
  /** Config. */
  public static final String REGULAR_EDITENDENTITY =
      REGULAR_RAFUNCTIONALITY + EDIT_END_ENTITY;
  /** Config. */
  public static final String REGULAR_DELETEENDENTITY =
      REGULAR_RAFUNCTIONALITY
          + DELETE_END_ENTITY; // Unused, but exists as "raw" string
  /** Config. */
  public static final String REGULAR_VIEWENDENTITYHISTORY =
      REGULAR_RAFUNCTIONALITY
          + VIEW_END_ENTITY_HISTORY; // Unused, but exists as "raw" string

  /** Config. */
  public static final String REGULAR_VIEWHARDTOKENS =
      REGULAR_RAFUNCTIONALITY + HARDTOKEN_RIGHTS;
  /** Config. */
  public static final String REGULAR_VIEWPUKS =
      REGULAR_RAFUNCTIONALITY + HARDTOKEN_PUKDATA_RIGHTS;
  /** Config. */
  public static final String REGULAR_KEYRECOVERY =
      REGULAR_RAFUNCTIONALITY + KEYRECOVERY_RIGHTS;
  /** Config. */
  public static final String REGULAR_VIEWAPPROVALS =
      REGULAR_RAFUNCTIONALITY + "/view_approvals";

  /** EE version only, reference by String value. */
  public static final String REGULAR_PEERCONNECTOR_VIEW =
      "/peer/view"; // org.ejbca.peerconnector.PeerAccessRules.VIEW

  /** Config. */
  public static final String REGULAR_PEERCONNECTOR_MODIFY =
      "/peer/modify"; // org.ejbca.peerconnector.PeerAccessRules.MODIFY
  /** Config. */
  public static final String REGULAR_PEERCONNECTOR_MANAGE =
      "/peer/manage"; // org.ejbca.peerconnector.PeerAccessRules.MANAGE
  /** Config. */
  public static final String REGULAR_PEERCONNECTOR_INVOKEAPI =
      "/ra_master/invoke_api";
  // org.ejbca.peerconnector.PeerRaAccessRules.RA_MASTER_INVOKE_API

  /**
   * EE version only. Intended for checks required when Peers module might not
   * be available. When possible, reference PeerProtocolAccessRules instead.
   */
  public static final String REGULAR_PEERPROTOCOL_ACME =
      "/protocol/acme"; // org.ejbca.peerconnector.PeerProtocolAccessRules.ACME

  /** Config. */
  public static final String REGULAR_PEERPROTOCOL_CMP =
      "/protocol/cmp"; // org.ejbca.peerconnector.PeerProtocolAccessRules.CMP
  /** Config. */
  public static final String REGULAR_PEERPROTOCOL_EST =
      "/protocol/est"; // org.ejbca.peerconnector.PeerProtocolAccessRules.EST
  /** Config. */
  public static final String REGULAR_PEERPROTOCOL_REST =
      "/protocol/rest"; // org.ejbca.peerconnector.PeerProtocolAccessRules.REST
  /** Config. */
  public static final String REGULAR_PEERPROTOCOL_SCEP =
      "/protocol/scep"; // org.ejbca.peerconnector.PeerProtocolAccessRules.SCEP
  /** Config. */
  public static final String REGULAR_PEERPROTOCOL_WS =
      "/protocol/web_services";
  // org.ejbca.peerconnector.PeerProtocolAccessRules.WS

  /** Config. */
  public static final String HARDTOKEN_HARDTOKENFUNCTIONALITY =
      "/hardtoken_functionality";
  /** Config. */
  public static final String HARDTOKEN_EDITHARDTOKENISSUERS =
      HARDTOKEN_HARDTOKENFUNCTIONALITY + "/edit_hardtoken_issuers";
  /** Config. */
  public static final String HARDTOKEN_EDITHARDTOKENPROFILES =
      HARDTOKEN_HARDTOKENFUNCTIONALITY + "/edit_hardtoken_profiles";
  /** Config. */
  public static final String HARDTOKEN_ISSUEHARDTOKENS =
      HARDTOKEN_HARDTOKENFUNCTIONALITY + "/issue_hardtokens";
  /** Config. */
  public static final String HARDTOKEN_ISSUEHARDTOKENADMINISTRATORS =
      HARDTOKEN_HARDTOKENFUNCTIONALITY + "/issue_hardtoken_administrators";

  // Rules for editing/viewing Service workers
  /** Config. */
  public static final String SERVICES_BASE = "/services";
  /** Config. */
  public static final String SERVICES_EDIT = SERVICES_BASE + "/edit";
  /** Config. */
  public static final String SERVICES_VIEW = SERVICES_BASE + "/view";

  /** Standard Regular Access Rules. */
  public static final String[] STANDARDREGULARACCESSRULES = {
    StandardRules.CAFUNCTIONALITY.resource(),
    REGULAR_ACTIVATECA,
    StandardRules.CAEDIT.resource(),
    StandardRules.CARENEW.resource(),
    StandardRules.CAVIEW.resource(),
    REGULAR_VIEWCERTIFICATE,
    REGULAR_CREATECRL,
    StandardRules.CERTIFICATEPROFILEEDIT.resource(),
    StandardRules.CERTIFICATEPROFILEVIEW.resource(),
    StandardRules.APPROVALPROFILEEDIT.resource(),
    StandardRules.APPROVALPROFILEVIEW.resource(),
    REGULAR_CREATECERTIFICATE,
    REGULAR_EDITPUBLISHER,
    REGULAR_VIEWPUBLISHER,
    REGULAR_EDITVALIDATOR,
    REGULAR_VIEWVALIDATOR,
    REGULAR_EDITBLACKLIST,
    REGULAR_APPROVECAACTION,
    REGULAR_RAFUNCTIONALITY,
    REGULAR_EDITENDENTITYPROFILES,
    REGULAR_VIEWENDENTITYPROFILES,
    REGULAR_EDITUSERDATASOURCES,
    REGULAR_VIEWENDENTITY,
    REGULAR_CREATEENDENTITY,
    REGULAR_EDITENDENTITY,
    REGULAR_DELETEENDENTITY,
    REGULAR_REVOKEENDENTITY,
    REGULAR_VIEWENDENTITYHISTORY,
    REGULAR_APPROVEENDENTITY,
    REGULAR_VIEWAPPROVALS,
    StandardRules.SYSTEMFUNCTIONALITY.resource(),
    SERVICES_EDIT,
    SERVICES_VIEW,
    StandardRules.EDITROLES.resource(),
    StandardRules.VIEWROLES.resource(),
    StandardRules.SYSTEMCONFIGURATION_EDIT.resource(),
    StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
    StandardRules.EKUCONFIGURATION_EDIT.resource(),
    StandardRules.EKUCONFIGURATION_VIEW.resource(),
    StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(),
    StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource()
  };

  /** Role Access Rules. */
  public static final String[] ROLEACCESSRULES = {
    ROLE_ADMINISTRATOR, StandardRules.ROLE_ROOT.resource()
  };

  /** Hard Token specific accessrules used in authorization module. */
  public static final String[] HARDTOKENACCESSRULES = {
    HARDTOKEN_HARDTOKENFUNCTIONALITY,
    HARDTOKEN_EDITHARDTOKENISSUERS,
    HARDTOKEN_EDITHARDTOKENPROFILES,
    HARDTOKEN_ISSUEHARDTOKENS,
    HARDTOKEN_ISSUEHARDTOKENADMINISTRATORS
  };
}
